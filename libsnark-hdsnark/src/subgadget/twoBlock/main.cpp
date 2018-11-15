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

#include "deps/sha256.h"
#include "util.h"
#include "uint256.h"
#include "deps/sodium.h"


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

/********************************************************
 * copy from Note.hpp and Note.cpp
 * ******************************************************/

uint256 random_uint256()
{
    uint256 ret;
    randombytes_buf(ret.begin(), 32);

    return ret;
}

class Note {
public:
    uint64_t value;
    uint256 sn;
    uint256 r;

    Note(uint64_t value, uint256 sn, uint256 r)
        : value(value), sn(sn), r(r) {}

    Note() {
        //a_pk = random_uint256();
        sn = random_uint256();
        r = random_uint256();
        value = 0;
    }

    uint256 cm() const{
        //unsigned char discriminant = 0xb0;

        CSHA256 hasher;
        //hasher.Write(&discriminant, 1);
        //hasher.Write(a_pk.begin(), 32);

        auto value_vec = convertIntToVectorLE(value);

        hasher.Write(&value_vec[0], value_vec.size());
        hasher.Write(sn.begin(), 32);
        hasher.Write(r.begin(), 32);

        uint256 result;
        hasher.Finalize(result.begin());

        return result;
    }
    //uint256 nullifier(const SpendingKey& a_sk) const;
};

/********************************************************
 * copy from util.tcc
 * ******************************************************/
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

/***************************************************************
 * sha256(data+padding), 512bits < data.size() < 1024-64-1bits
 * *************************************************************
 * publicData: cmt_A_old, sn_A_old,  
 * privateData: value_old, r_A_old
 * *************************************************************
 * publicData: cmt_A_new, (value_s, balance)  
 * privateData: value_new, sn_A_new, r_A_new
 * *************************************************************
 * auxiliary: value_new == value_old + value_s
 *            value_s < balance
 * *************************************************************/
template<typename FieldT>
class sha256_two_block_gadget : gadget<FieldT> {
public:
    // Verifier inputs 验证者输入
    pb_variable_array<FieldT> zk_packed_inputs; // 合并为十进制
    pb_variable_array<FieldT> zk_unpacked_inputs; // 拆分为二进制
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker; // 二进制转十进制转换器

    // new commitment with sha256_two_block_gadget
    std::shared_ptr<digest_variable<FieldT>> cmtA; // cm

    pb_variable_array<FieldT> value;      // 64bits value for Mint
    std::shared_ptr<digest_variable<FieldT>> sn; // 256位的随机数r
    std::shared_ptr<digest_variable<FieldT>> r; // 256位的随机数r

    std::shared_ptr<block_variable<FieldT>> block1;
    std::shared_ptr<block_variable<FieldT>> block2;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher1;
    std::shared_ptr<digest_variable<FieldT>> intermediate_hash; // 中间hash值
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher2;

    pb_variable<FieldT> ZERO;

    sha256_two_block_gadget(              // cmt_A = sha256(value, sn, r, padding) for Mint
        protoboard<FieldT> &pb
    ) : gadget<FieldT>(pb, "sha256_two_block_gadget") {

        // Verification
        // Allocate space for the verifier input (result).
        {
            zk_packed_inputs.allocate(pb, verifying_field_element_size()); 
            this->pb.set_input_sizes(verifying_field_element_size());
        }

        ZERO.allocate(this->pb, FMT(this->annotation_prefix, "zero"));

        // final padding = base_padding + length
        pb_variable_array<FieldT> length_padding =
            from_bits({
                1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, // 12*4*8 = 384bits
                // length of message (576 bits)
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,1,0, 0,1,0,0,0,0,0,0 // 8*8 = 64bits
            }, ZERO); // 56*8=448bits


        //cmtA.reset(new digest_variable<FieldT>(pb, 256, "cmtA"));
        alloc_uint256(zk_unpacked_inputs, cmtA);
        //zk_unpacked_inputs.insert(zk_unpacked_inputs.end(), cmtA->bits.begin(), cmtA->bits.end());

        // sn.reset(new digest_variable<FieldT>(pb, 256, "serial number"));
        alloc_uint256(zk_unpacked_inputs, sn);
        // zk_unpacked_inputs.insert(zk_unpacked_inputs.end(), sn->bits.begin(), sn->bits.end());

        printf("zk_unpacked_inputs.size() = %d\n", zk_unpacked_inputs.size());
        printf("verifying_input_bit_size() = %d\n", verifying_input_bit_size());
        assert(zk_unpacked_inputs.size() == verifying_input_bit_size()); // 判定输入长度

        // This gadget will ensure that all of the inputs we provide are
        // boolean constrained. 布尔约束 <=> 比特位, 打包
        unpacker.reset(new multipacking_gadget<FieldT>(
            pb,
            zk_unpacked_inputs,
            zk_packed_inputs,
            FieldT::capacity(),
            "unpacker"
        ));

        value.allocate(pb, 64);
        //sn.reset(new digest_variable<FieldT>(pb, 256, "serial number"));
        r.reset(new digest_variable<FieldT>(pb, 256, "random number"));

        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        pb_variable_array<FieldT> first_of_r(r->bits.begin(), r->bits.begin()+192);
        pb_variable_array<FieldT> last_of_r(r->bits.begin()+192, r->bits.end());

        intermediate_hash.reset(new digest_variable<FieldT>(pb, 256, "intermediate_hash"));

        block1.reset(new block_variable<FieldT>(pb, {
            value,           // 64bits
            sn->bits,      // 256bits
            first_of_r   // 192bits
        }, "sha256_two_block_gadget_block1"));

        block2.reset(new block_variable<FieldT>(pb, {
            last_of_r,      // (256-192)=64bits
            length_padding  // 448bits
        }, "sha256_two_block_gadget_block2"));

        hasher1.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block1->bits,
            *intermediate_hash,
        "sha256_two_block_hash1"));

        pb_linear_combination_array<FieldT> IV2(intermediate_hash->bits); // hash迭代

        hasher2.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV2,
            block2->bits,
            *cmtA,
        "sha256_two_block_hash2"));
    }

    void generate_r1cs_constraints() {
        // The true passed here ensures all the inputs
        // are boolean constrained.
        unpacker->generate_r1cs_constraints(true);

        sn->generate_r1cs_constraints(); // 随机数的约束
        r->generate_r1cs_constraints(); // 随机数的约束

        // Constrain `ZERO`
        generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), "ZERO");

        // TODO: These constraints may not be necessary if SHA256
        // already boolean constrains its outputs.
        //cmtA->generate_r1cs_constraints();

        // TODO: This may not be necessary if SHA256 constrains
        // its output digests to be boolean anyway.
        intermediate_hash->generate_r1cs_constraints();

        hasher1->generate_r1cs_constraints();
        hasher2->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(
        const Note note
    ) {
        //(const Note& note_old, const Note& note, uint64_t v_s, uint64_t b)
        printf("============================================\n");
        printf("* note.value = %zu\n", note.value);
        printf("* note.sn = %zu\n", note.sn);
        printf("* note.r = %zu\n", note.r);
        printf("=============================================\n");

        value.fill_with_bits(this->pb, uint64_to_bool_vector(note.value));
        sn->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note.sn));
        r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note.r));

        printf(" value = [ ");
        BOOST_FOREACH(bool vs, uint64_to_bool_vector(note.value)) {
            printf("%d, ", vs);
        }

        printf("]\n sn = [ ");
        BOOST_FOREACH(bool vs, uint256_to_bool_vector(note.sn)) {
            printf("%d, ", vs);
        }

        printf("]\n r = [ ");
        BOOST_FOREACH(bool vs, uint256_to_bool_vector(note.r)) {
            printf("%d, ", vs);
        }
        printf("]\n");

        // Witness `zero`
        this->pb.val(ZERO) = FieldT::zero();

        hasher1->generate_r1cs_witness();
        hasher2->generate_r1cs_witness();

        // This happens last, because only by now are all the
        // verifier inputs resolved.
        unpacker->generate_r1cs_witness_from_bits();

        // [SANITY CHECK] Ensure the commitment is
        // valid.
        cmtA->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.cm())
        );

        printf("]\n cmtA = [ ");
        BOOST_FOREACH(bool vs, uint256_to_bool_vector(note.cm())) {
            printf("%d, ", vs);
        }
        printf("]\n");

        // // This happens last, because only by now are all the
        // // verifier inputs resolved.
        // unpacker->generate_r1cs_witness_from_bits();
    }

    // 将bit形式的私密输入 打包转换为 域上的元素
    static r1cs_primary_input<FieldT> witness_map(
        const uint256& sn,
        const uint256& cmtA
    ) {
        std::vector<bool> verify_inputs;

        insert_uint256(verify_inputs, cmtA);
        insert_uint256(verify_inputs, sn);

        assert(verify_inputs.size() == verifying_input_bit_size());
        auto verify_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(verify_inputs);
        assert(verify_field_elements.size() == verifying_field_element_size());
        return verify_field_elements;
    }

    // 计算输入元素的bit大小
    static size_t verifying_input_bit_size() {
        size_t acc = 0;

        acc += 256; // cmtA_old
        acc += 256; // sn_old

        return acc;
    }

    // 计算域上元素的组数
    static size_t verifying_field_element_size() {
        return div_ceil(verifying_input_bit_size(), FieldT::capacity());
    }

    // 分配空间，打包追加
    void alloc_uint256(
        pb_variable_array<FieldT>& packed_into,
        std::shared_ptr<digest_variable<FieldT>>& var
    ) {
        var.reset(new digest_variable<FieldT>(this->pb, 256, ""));
        packed_into.insert(packed_into.end(), var->bits.begin(), var->bits.end());
    }

    // 分配空间，打包追加
    void alloc_uint64(
        pb_variable_array<FieldT>& packed_into,
        pb_variable_array<FieldT>& integer
    ) {
        //integer.allocate(this->pb, 64, "");
        packed_into.insert(packed_into.end(), integer.begin(), integer.end());
    }
};

// 生成proof
template<typename ppzksnark_ppT>
boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> generate_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                    const Note note
                                                                   )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;  // 定义原始模型，该模型包含constraint_system成员变量
    sha256_two_block_gadget<FieldT> g(pb); // 构造新模型
    g.generate_r1cs_constraints(); // 生成约束

    g.generate_r1cs_witness(note); // 为新模型的参数生成证明

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
                    r1cs_ppzksnark_proof<ppzksnark_ppT> proof,
                    const uint256 cmtA,
                    const uint256 sn
                  )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    // const r1cs_primary_input<FieldT> input = note_gadget_with_add_input_map<FieldT>(uint64_to_bool_vector(value)); // 获取输入，并转换为有限域上的值
    
    //const r1cs_primary_input<FieldT> input;
    const r1cs_primary_input<FieldT> input = sha256_two_block_gadget<FieldT>::witness_map(
        sn,
        cmtA
    ); 

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

/****************************************
 * 全局变量，用于测试
 * **************************************/
// Note note_old_test, note_test;

// test_comparison_gadget_with_instance, v = v_old + v_s && v_s < b
template<typename ppzksnark_ppT> //--Agzs
bool test_sha256_two_block_gadget_with_instance(
                            // uint64_t v_old, 
                            // uint64_t v,
                            // uint64_t v_s, 
                            // uint64_t b
                            
                            //uint64_t value_old,
                            //uint256 sn_old,
                            //uint256 r_old,
                            uint64_t value
                            //uint256 sn,
                            //uint256 r,
                            //uint64_t value_s,
                            //uint64_t balance
                        )
{
    // Note note_old = Note(value_old, sn_old, r_old);
    // Note note = Note(value, sn, r);

    // uint256 sn_test = random_uint256();
    // uint256 r_test = random_uint256();
    std::string str = "1";

    uint256 sn_test = uint256S(str);//random_uint256();
    uint256 r_test = uint256S(str);//random_uint256();
    
    printf("* note.sn = %zu\n", sn_test);
    printf("* note.r = %zu\n", r_test);

    Note note_test = Note(value, sn_test, r_test);

    // note_test.value = value;
    // note_test.sn = random_uint256();
    // note_test.r = random_uint256();

    // Note note_old = Note(note_old_test.value, note_old_test.sn, note_old_test.r);
    Note note = Note(value, sn_test, r_test);

    printf("============================================\n");
    printf("* note.value = %zu\n", note.value);
    printf("* note.sn = %zu\n", note.sn);
    printf("* note.r = %zu\n", note.r);
    printf("=============================================\n");


    typedef libff::Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;

    sha256_two_block_gadget<FieldT> cmt(pb);
    cmt.generate_r1cs_constraints();// 生成约束

    // check conatraints
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    // key pair generation
    r1cs_ppzksnark_keypair<ppzksnark_ppT> keypair = r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);

    // 生成proof
    cout << "Trying to generate proof..." << endl;

    auto proof = generate_proof<default_r1cs_ppzksnark_pp>(keypair.pk, 
                                                            note
                                                            );

    // verify proof
    if (!proof) {
        printf("generate sha256 two blocks proof fail!!!\n");
        return false;
    } else {
        PrintProof(*proof);

        //assert(verify_proof(keypair.vk, *proof));
        uint256 wrong_sn = uint256S("11");//random_uint256();

        bool result = verify_proof(keypair.vk, 
                                   *proof, 
                                   note_test.cm(),
                                   wrong_sn // 正确验证的话。此处请使用sn_test
                                   );

        printf("verify result = %d\n", result);
         
        if (!result){
            cout << "Verifying sha256 two blocks proof unsuccessfully with uint256_to_bit_vector!!!" << endl;
        } else {
            cout << "Verifying sha256 two blocks proof successfully with uint256_to_bit_vector!!!" << endl;
        }
        
        return result;
    }
}

int main () {
    default_r1cs_ppzksnark_pp::init_public_params();
    //test_r1cs_gg_ppzksnark<default_r1cs_gg_ppzksnark_pp>(1000, 100);

    libff::print_header("#             testing mint gadget");

    uint64_t value = uint64_t(3); 
    // uint64_t value_old = uint64_t(2); 
    // uint64_t value_s = uint64_t(1);
    // uint64_t balance = uint64_t(300); // 由于balance是对外公开的，所以blance>0;此处balance设为负数也能验证通过

    test_sha256_two_block_gadget_with_instance<default_r1cs_ppzksnark_pp>(value);//_old, value, value_s, balance);

    // assert(test_comparison_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(6, 45, 40)); 
    // Note. cmake can not compile the assert()  --Agzs
    
    return 0;
}

