#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <sys/time.h>
#include <boost/optional.hpp>
#include <boost/foreach.hpp>
#include <boost/format.hpp>

#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libff/common/utils.hpp"
#include "libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp"

#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libff/algebra/fields/field_utils.hpp>


#include <boost/optional/optional_io.hpp> // for cout proof --Agzs
#include <libff/common/utils.hpp>

#include "uint256.h"
#include "util.h"


using namespace libsnark;
using namespace libff;
using namespace std;

/**
 * The code below provides an example of all stages of running a R1CS GG-ppzkSNARK.
 *
 * Of course, in a real-life scenario, we would have three distinct entities,
 * mangled into one in the demonstration below. The three entities are as follows.
 * (1) The "generator", which runs the ppzkSNARK generator on input a given
 *     constraint system CS to create a proving and a verification key for CS.
 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
 *     a primary input for CS, and an auxiliary input for CS.
 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
 *     a primary input for CS, and a proof.
 */

#define DEBUG 0

//=============================================================
// copy from util.tcc
//====================
// 进行bit转换
template<typename FieldT>
pb_variable_array<FieldT> from_bits(std::vector<bool> bits, pb_variable<FieldT>& ZERO) {
    pb_variable_array<FieldT> acc;

    BOOST_FOREACH(bool bit, bits) {
        acc.emplace_back(bit ? ONE : ZERO); // ONE是常数项，ZERO对应FiledT::zero()为零元
    }

    return acc;
}

// 从256位中截取后252位
std::vector<bool> trailing252(std::vector<bool> input) {
    if (input.size() != 256) {
        throw std::length_error("trailing252 input invalid length");
    }

    return std::vector<bool>(input.begin() + 4, input.end());
}

// 类型转换，将u256转换为bit数组
std::vector<bool> uint256_to_bool_vector(uint256 input) {
    std::vector<unsigned char> input_v(input.begin(), input.end());
    std::vector<bool> output_bv(256, 0);
    convertBytesVectorToVector(
        input_v,
        output_bv
    );

    return output_bv;
}

// 类型转换，将u64转换为bit数组
std::vector<bool> uint64_to_bool_vector(uint64_t input) {
    auto num_bv = convertIntToVectorLE(input);
    std::vector<bool> num_v(64, 0);
    convertBytesVectorToVector(num_bv, num_v);

    return num_v;
}

// 向into数组后追加from
void insert_uint256(std::vector<bool>& into, uint256 from) {
    std::vector<bool> blob = uint256_to_bool_vector(from);
    into.insert(into.end(), blob.begin(), blob.end());
}

// 向into数组后追加from
void insert_uint64(std::vector<bool>& into, uint64_t from) {
    std::vector<bool> num = uint64_to_bool_vector(from);
    into.insert(into.end(), num.begin(), num.end());
}

// 以32为对称线，每8位进行逆序转换
template<typename T>
T swap_endianness_u64(T v) {
    if (v.size() != 64) {
        throw std::length_error("invalid bit length for 64-bit unsigned integer");
    }

    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 8; j++) {
            std::swap(v[i*8 + j], v[((7-i)*8)+j]);
        }
    }

    return v;
}

// bit形式转换为十进制形式，但是仍然是线性组合的形式
template<typename FieldT>
linear_combination<FieldT> packed_addition(pb_variable_array<FieldT> input) {
    auto input_swapped = swap_endianness_u64(input);

    return pb_packing_sum<FieldT>(pb_variable_array<FieldT>( 
        input_swapped.rbegin(), input_swapped.rend() // 逆序的reverse_iterator
    ));
}

// bit形式转换为十进制形式，域的形式
template<typename FieldT>
FieldT packed_addition_fieldT(pb_variable_array<FieldT> input) {
    auto input_swapped = swap_endianness_u64(input);

    return pb_packing_filedT_sum<FieldT>(pb_variable_array<FieldT>( 
        input_swapped.rbegin(), input_swapped.rend() // 逆序的reverse_iterator
    ));
}
//=============================================================
template<typename FieldT>
class note_gadget_with_packing : public gadget<FieldT> { // 基类和比较类组合，基本的note_gadget和comparison_gadget (value_s)
public:
    pb_variable_array<FieldT> value; // 64位的value
    pb_variable<FieldT> value_packed;
    std::shared_ptr<packing_gadget<FieldT> > pack_value;
    
    pb_variable_array<FieldT> value_old; // 64位的value
    pb_variable<FieldT> value_old_packed;
    std::shared_ptr<packing_gadget<FieldT> > pack_value_old;

    // std::shared_ptr<digest_variable<FieldT>> r; // 256位的随机数r

    pb_variable_array<FieldT> value_s; // 64位的value
    pb_variable<FieldT> value_s_packed;
    std::shared_ptr<packing_gadget<FieldT> > pack_value_s;

    note_gadget_with_packing(protoboard<FieldT> &pb) : gadget<FieldT>(pb) {
        value.allocate(pb, 64);
        value_packed.allocate(pb);
        pack_value.reset(new packing_gadget<FieldT>(pb, value, value_packed,
                                                    FMT(this->annotation_prefix, " pack_value")));
        
        value_old.allocate(pb, 64);
        value_old_packed.allocate(pb);
        pack_value_old.reset(new packing_gadget<FieldT>(pb, value_old, value_old_packed,
                                                    FMT(this->annotation_prefix, " pack_value_old")));
        //r.reset(new digest_variable<FieldT>(pb, 256, "random number"));

        value_s.allocate(pb, 64);
        value_s_packed.allocate(pb, "value_s_packed");
        pack_value_s.reset(new packing_gadget<FieldT>(pb, value_s, value_s_packed,
                                                    FMT(this->annotation_prefix, " pack_value_s")));
    }

    void generate_r1cs_constraints() { // const Note& note

        // r->generate_r1cs_constraints(); // 随机数的约束

        pack_value_old->generate_r1cs_constraints(true);

        pack_value_s->generate_r1cs_constraints(true);

        pack_value->generate_r1cs_constraints(true);
    }

    void generate_r1cs_witness(uint64_t v, uint64_t v_old, uint64_t v_s) { // 为变量生成约束

        // r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(r));
        value.fill_with_bits(this->pb, uint64_to_bool_vector(v));
        pack_value->generate_r1cs_witness_from_bits();
        
        value_old.fill_with_bits(this->pb, uint64_to_bool_vector(v_old));
        pack_value_old->generate_r1cs_witness_from_bits();

        value_s.fill_with_bits(this->pb, uint64_to_bool_vector(v_s));
        pack_value_s->generate_r1cs_witness_from_bits();
    }
};



template<typename FieldT>
class less_comparison_gadget : public gadget<FieldT> {
private:
    pb_variable_array<FieldT> alpha;
    pb_variable<FieldT> alpha_packed;
    std::shared_ptr<packing_gadget<FieldT> > pack_alpha;

    std::shared_ptr<disjunction_gadget<FieldT> > all_zeros_test;
    pb_variable<FieldT> not_all_zeros;
public:
    const size_t n = 64;
    const pb_linear_combination<FieldT> A;
    const pb_linear_combination<FieldT> B;

    less_comparison_gadget(protoboard<FieldT>& pb,
                      const pb_linear_combination<FieldT> &A,
                      const pb_linear_combination<FieldT> &B,
                      const std::string &annotation_prefix="") :
        gadget<FieldT>(pb, annotation_prefix), A(A), B(B)
    {
        alpha.allocate(pb, n, FMT(this->annotation_prefix, " alpha"));
        alpha.emplace_back(0); // alpha[n] is less_or_eq, set alpha[n] = 0, just proof A <= B

        // this->pb.val(alpha) = this->pb.val(1);

        alpha_packed.allocate(pb, FMT(this->annotation_prefix, " alpha_packed"));
        not_all_zeros.allocate(pb, FMT(this->annotation_prefix, " not_all_zeros"));

        pack_alpha.reset(new packing_gadget<FieldT>(pb, alpha, alpha_packed,
                                                    FMT(this->annotation_prefix, " pack_alpha")));

        all_zeros_test.reset(new disjunction_gadget<FieldT>(pb,
                                                            pb_variable_array<FieldT>(alpha.begin(), alpha.begin() + n),
                                                            not_all_zeros,
                                                            FMT(this->annotation_prefix, " all_zeros_test")));
    };

    void generate_r1cs_constraints()
    {
        /*
        packed(alpha) = 2^n + B - A

        not_all_zeros = \bigvee_{i=0}^{n-1} alpha_i 或取

        if B - A > 0, then 2^n + B - A > 2^n,
            so alpha_n = 1 and not_all_zeros = 1
        if B - A = 0, then 2^n + B - A = 2^n,
            so alpha_n = 1 and not_all_zeros = 0
        if B - A < 0, then 2^n + B - A \in {0, 1, \ldots, 2^n-1},
            so alpha_n = 0

        therefore alpha_n = less_or_eq and alpha_n * not_all_zeros = 1
        */

        /* not_all_zeros to be Boolean, alpha_i are Boolean by packing gadget */
        generate_boolean_r1cs_constraint<FieldT>(this->pb, not_all_zeros,
                                        FMT(this->annotation_prefix, " not_all_zeros"));

        /* constraints for packed(alpha) = 2^n + B - A */
        pack_alpha->generate_r1cs_constraints(true);

        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, (FieldT(2)^n) + B - A, alpha_packed), FMT(this->annotation_prefix, " main_constraint"));

        /* compute result */
        all_zeros_test->generate_r1cs_constraints();
        
        /*********************************************************************************
         * 初始化时，我们预设 less_or_eq = 0, 即 alpha_n = 0,
         * less_or_eq * not_all_zeros = less
         * 0 * not_all_zeros = 0 => less => A < B
         * 0 * not_all_zeros = 1 => eq => A = B   
         * 1 * not_all_zeros = 1 => less_or_eq => A <= B
         * 1 * not_all_zeros = 0 => nothing
         * 1 * not_all_zeros = not_all_zeros => less_or_eq => A <= B
         * 0 * not_all_zeros = not_all_zeros => eq => A = B  
         * this->pb.val(0)== this->pb.val(1), 所以 not_all_zeros=1 时成立
         * ********************************************************************************/
        // this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(this->pb.val(0), not_all_zeros, this->pb.val(0)),
        //                             FMT(this->annotation_prefix, " less"));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(FieldT::one(), not_all_zeros, FieldT::one()),
                                    FMT(this->annotation_prefix, " less"));

    }
    void generate_r1cs_witness(){
        A.evaluate(this->pb);
        B.evaluate(this->pb);

        /* unpack 2^n + B - A into alpha_packed */
        this->pb.val(alpha_packed) = (FieldT(2)^n) + this->pb.lc_val(B) - this->pb.lc_val(A);
        pack_alpha->generate_r1cs_witness_from_packed();

        /* compute result */
        all_zeros_test->generate_r1cs_witness();

        printf("****************\n FieldT(2)^n) = %zu\n ****************\n", FieldT(2)^n);
        printf("****************\n A = %zu\n ****************\n", A);
        printf("****************\n B = %zu\n ****************\n", B);
        printf("****************\n not_all_zeros = %zu\n ****************\n", not_all_zeros);
        printf("****************\n alpha = %zu\n ****************\n", alpha);
        printf("****************\n (FieldT(2)^n) + B - A = %zu\n ****************\n", (FieldT(2)^n) + B - A);
        printf("****************\n alpha_packed = %zu\n ****************\n", alpha_packed);
        
        printf("****************\n this->pb.val(0) = %zu\n ****************\n", this->pb.val(0));
        printf("****************\n this->pb.val(1) = %zu\n ****************\n", this->pb.val(1));
    }
};


template<typename FieldT>
class note_gadget_with_comparison_and_subtraction_for_value_old : public note_gadget_with_packing<FieldT> { // 基类和比较类组合，基本的note_gadget和comparison_gadget (value_s)
public:
    //std::shared_ptr<note_gadget_with_packing<FieldT>> packThree;

    std::shared_ptr<less_comparison_gadget<FieldT> > less_cmp;

    note_gadget_with_comparison_and_subtraction_for_value_old(protoboard<FieldT> &pb) : note_gadget_with_packing<FieldT>(pb) {
        //packThree.reset(new note_gadget_with_packing<FieldT>(pb));

        less_cmp.reset(new less_comparison_gadget<FieldT>(pb, this->value_s_packed, this->value_old_packed,
                                                    FMT(this->annotation_prefix, " less_cmp")));
    }

    void generate_r1cs_constraints() { // const Note& note
        note_gadget_with_packing<FieldT>::generate_r1cs_constraints();

        // 1 * (value_old - value_s) = this->value 
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, (this->value_old_packed - this->value_s_packed), this->value_packed),
                                 FMT(this->annotation_prefix, " equal"));

        less_cmp->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(uint64_t v, uint64_t v_old, uint64_t v_s) { // 为变量生成约束
        note_gadget_with_packing<FieldT>::generate_r1cs_witness(v, v_old, v_s);

        less_cmp->generate_r1cs_witness();
    }
};


// 生成proof
template<typename ppzksnark_ppT>
boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> generate_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                    uint64_t value, 
                                                                    uint64_t value_old, 
                                                                    uint64_t value_s
                                                                   )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;  // 定义原始模型，该模型包含constraint_system成员变量
    note_gadget_with_comparison_and_subtraction_for_value_old<FieldT> g(pb); // 构造新模型
    g.generate_r1cs_constraints(); // 生成约束
    g.generate_r1cs_witness(value, value_old, value_s); // 为新模型的参数生成证明

    cout << "pb.is_satisfied() is " << pb.is_satisfied() << endl;

    if (!pb.is_satisfied()) { // 三元组R1CS是否满足  < A , X > * < B , X > = < C , X >
        return boost::none;
    }

    // 调用libsnark库中生成proof的函数
    return r1cs_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

// 验证proof
template<typename ppzksnark_ppT>
bool verify_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                  r1cs_ppzksnark_proof<ppzksnark_ppT> proof
                  )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    // const r1cs_primary_input<FieldT> input = note_gadget_with_add_input_map<FieldT>(uint64_to_bool_vector(value)); // 获取输入，并转换为有限域上的值
    
    const r1cs_primary_input<FieldT> input; 

    // std::cout << "*******************************************\n value = [ ";
    // //std::cout << "value: " << uint64_to_bool_vector(value) << endl;
    // BOOST_FOREACH(bool bit, uint64_to_bool_vector(value)) {
    //     printf("%d, ", bit);
    // }
    // std::cout << "]\n*******************************************\n";

    // 调用libsnark库中验证proof的函数
    return r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}

template<typename ppzksnark_ppT>
void PrintProof(r1cs_ppzksnark_proof<ppzksnark_ppT> proof)
{
    printf("================== Print proof ==================================\n");
    //printf("proof is %x\n", *proof);
    std::cout << "comparison proof:\n";

    std::cout << "\n knowledge_commitment<G1<ppT>, G1<ppT> > g_A: ";
    std::cout << "\n   knowledge_commitment.g: \n     " << proof.g_A.g;
    std::cout << "\n   knowledge_commitment.h: \n     " << proof.g_A.h << endl;

    std::cout << "\n knowledge_commitment<G2<ppT>, G1<ppT> > g_B: ";
    std::cout << "\n   knowledge_commitment.g: \n     " << proof.g_B.g;
    std::cout << "\n   knowledge_commitment.h: \n     " << proof.g_B.h << endl;

    std::cout << "\n knowledge_commitment<G1<ppT>, G1<ppT> > g_C: ";
    std::cout << "\n   knowledge_commitment.g: \n     " << proof.g_C.g;
    std::cout << "\n   knowledge_commitment.h: \n     " << proof.g_C.h << endl;


    std::cout << "\n G1<ppT> g_H: " << proof.g_H << endl;
    std::cout << "\n G1<ppT> g_K: " << proof.g_K << endl;
    printf("=================================================================\n");
}

// test_comparison_gadget_with_instance
template<typename ppzksnark_ppT> //--Agzs
bool test_note_gadget_with_comparison_for_value_old_with_instance(
                        uint64_t value, 
                        uint64_t value_old, 
                        uint64_t value_s
                        )
{
    typedef libff::Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;

    note_gadget_with_comparison_and_subtraction_for_value_old<FieldT> ncmp(pb);
    ncmp.generate_r1cs_constraints();// 生成约束

    // check conatraints
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    // key pair generation
    r1cs_ppzksnark_keypair<ppzksnark_ppT> keypair =  r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);

    // 生成proof
    cout << "Trying to generate proof..." << endl;
    auto proof = generate_proof<default_r1cs_ppzksnark_pp>(keypair.pk, 
                                                            value,
                                                            value_old,
                                                            value_s
                                                            );

    // verify proof
    if (!proof) {
        return false;
    } else {
        // const r1cs_primary_input<FieldT> input();
        // std::cout<<"NULL input: "<<input<<endl;
        
        // PrintProof(*proof);

        assert(verify_proof(keypair.vk, *proof));
    }

    printf("comparison tests successful\n");

    return true;
}

int main () {
    default_r1cs_ppzksnark_pp::init_public_params();
    //test_r1cs_gg_ppzksnark<default_r1cs_gg_ppzksnark_pp>(1000, 100);

    libff::print_header("#             test comparison gadget with assert()");

    uint64_t value = uint64_t(250); 
    uint64_t value_old = uint64_t(264); 
    uint64_t value_s = uint64_t(14);

    test_note_gadget_with_comparison_for_value_old_with_instance<default_r1cs_ppzksnark_pp>(value, value_old, value_s);

    // assert(test_comparison_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(6, 45, 40)); 
    // Note. cmake can not compile the assert()  --Agzs
    
    return 0;
}
