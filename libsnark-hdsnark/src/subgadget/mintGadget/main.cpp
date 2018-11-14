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
/*****************************************************
 * note_gadget_with_packing for packing value, value_old and value_s
 * ***************************************************/
template<typename FieldT>
class note_gadget_with_packing : public gadget<FieldT> { // 基类和比较类组合，基本的note_gadget和comparison_gadget (value_s)
public:
    pb_variable_array<FieldT> value; // 64位的value, 操作后的账户余额，也是当前最新的账户余额
    pb_variable<FieldT> value_packed;
    std::shared_ptr<packing_gadget<FieldT> > pack_value;
    
    pb_variable_array<FieldT> value_old; // 64位的value，操作前的账户余额
    pb_variable<FieldT> value_old_packed;
    std::shared_ptr<packing_gadget<FieldT> > pack_value_old;

    pb_variable_array<FieldT> value_s; // 64位的value，待操作的账户余额
    pb_variable<FieldT> value_s_packed;
    std::shared_ptr<packing_gadget<FieldT> > pack_value_s;

    std::shared_ptr<digest_variable<FieldT>> r; // 256位的随机数r
    std::shared_ptr<digest_variable<FieldT>> r_old; // 256位的随机数r

    std::shared_ptr<digest_variable<FieldT>> sn; // 256位的随机数serial number
    std::shared_ptr<digest_variable<FieldT>> sn_old; // 256位的随机数serial number

    note_gadget_with_packing(protoboard<FieldT> &pb) : gadget<FieldT>(pb) {
        value.allocate(pb, 64);
        value_packed.allocate(pb);
        pack_value.reset(new packing_gadget<FieldT>(pb, value, value_packed,
                                                    FMT(this->annotation_prefix, " pack_value")));
        
        value_old.allocate(pb, 64);
        value_old_packed.allocate(pb);
        pack_value_old.reset(new packing_gadget<FieldT>(pb, value_old, value_old_packed,
                                                    FMT(this->annotation_prefix, " pack_value_old")));

        value_s.allocate(pb, 64);
        value_s_packed.allocate(pb, "value_s_packed");
        pack_value_s.reset(new packing_gadget<FieldT>(pb, value_s, value_s_packed,
                                                    FMT(this->annotation_prefix, " pack_value_s")));
        
        r.reset(new digest_variable<FieldT>(pb, 256, "random number"));
        r_old.reset(new digest_variable<FieldT>(pb, 256, "old random number"));
        sn.reset(new digest_variable<FieldT>(pb, 256, "serial number"));
        sn_old.reset(new digest_variable<FieldT>(pb, 256, "old serial number"));
    }

    void generate_r1cs_constraints() { // const Note& note

        pack_value_old->generate_r1cs_constraints(true);

        pack_value_s->generate_r1cs_constraints(true);

        pack_value->generate_r1cs_constraints(true);

        r->generate_r1cs_constraints(); // 随机数的约束
        r_old->generate_r1cs_constraints(); // 随机数的约束
        sn->generate_r1cs_constraints(); // 随机数的约束
        sn_old->generate_r1cs_constraints(); // 随机数的约束
    }

    void generate_r1cs_witness(const Note& note_old, const Note& note, uint64_t v_s) { // 为变量生成约束
        value.fill_with_bits(this->pb, uint64_to_bool_vector(note.value));
        pack_value->generate_r1cs_witness_from_bits();
        
        value_old.fill_with_bits(this->pb, uint64_to_bool_vector(note_old.value));
        pack_value_old->generate_r1cs_witness_from_bits();

        value_s.fill_with_bits(this->pb, uint64_to_bool_vector(v_s));
        pack_value_s->generate_r1cs_witness_from_bits();

        r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note.r));
        r_old->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note_old.r));
        sn->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note.sn));
        sn_old->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note_old.sn));
    }
};

/**********************************************
 * less_cmp_gadget for judging A < B
 * ********************************************/
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
    }
};

/**********************************************
 * comparison_gadget and addition_constraint
 * value_s < balance for Mint, 
 * value_old + value_s == value for Mint
 * publicData: balance, value_s, 
 * privateData: value_old, value, 
 * ********************************************/
template<typename FieldT>
class note_gadget_with_comparison_and_addition_for_balance : public note_gadget_with_packing<FieldT> { // 基类和比较类组合，基本的note_gadget和comparison_gadget (value_s)
public:   
    pb_variable_array<FieldT> balance; // 64位的value
    pb_variable<FieldT> balance_packed;
    std::shared_ptr<packing_gadget<FieldT> > pack_balance;

    std::shared_ptr<less_comparison_gadget<FieldT> > less_cmp;

    note_gadget_with_comparison_and_addition_for_balance(protoboard<FieldT> &pb) : note_gadget_with_packing<FieldT>(pb) {
        balance.allocate(pb, 64);
        balance_packed.allocate(pb, "balance_packed");
        pack_balance.reset(new packing_gadget<FieldT>(pb, balance, balance_packed,
                                                    FMT(this->annotation_prefix, " pack_balance")));

        less_cmp.reset(new less_comparison_gadget<FieldT>(pb, this->value_s_packed, balance_packed,
                                                    FMT(this->annotation_prefix, " less_cmp")));
    }

    void generate_r1cs_constraints() { // const Note& note
        note_gadget_with_packing<FieldT>::generate_r1cs_constraints();

        // 1 * (value_old + value_s) = this->value 
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, (this->value_old_packed + this->value_s_packed), this->value_packed),
                                 FMT(this->annotation_prefix, " equal"));

        pack_balance->generate_r1cs_constraints(true);

        less_cmp->generate_r1cs_constraints();
    }
    
    void generate_r1cs_witness(const Note& note_old, const Note& note, uint64_t v_s, uint64_t b) { // 为变量生成约束
        note_gadget_with_packing<FieldT>::generate_r1cs_witness(note_old, note, v_s);

        balance.fill_with_bits(this->pb, uint64_to_bool_vector(b));
        pack_balance->generate_r1cs_witness_from_bits();

        less_cmp->generate_r1cs_witness();
    }
};

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
private:
    std::shared_ptr<block_variable<FieldT>> block1;
    std::shared_ptr<block_variable<FieldT>> block2;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher1;
    std::shared_ptr<digest_variable<FieldT>> intermediate_hash; // 中间hash值
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher2;

public:
    sha256_two_block_gadget(              // cmt_A = sha256(value, sn, r, padding) for Mint
        protoboard<FieldT> &pb,
        pb_variable<FieldT>& ZERO,
        pb_variable_array<FieldT>& v,      // 64bits value for Mint
        pb_variable_array<FieldT>& sn_old, // 256bits serial number
        pb_variable_array<FieldT>& rho,      // 256bits random number
        std::shared_ptr<digest_variable<FieldT>> cmtA // 256bits hash
    ) : gadget<FieldT>(pb, "sha256_two_block_gadget") {

        pb_variable_array<FieldT> first_of_r(rho.begin(), rho.begin()+192);
        pb_variable_array<FieldT> last_of_r(rho.begin()+192, rho.end());

        intermediate_hash.reset(new digest_variable<FieldT>(pb, 256, ""));

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

        block1.reset(new block_variable<FieldT>(pb, {
            v,           // 64bits
            sn_old,      // 256bits
            first_of_r   // 192bits
        }, "sha256_two_block_gadget_block1"));

        block2.reset(new block_variable<FieldT>(pb, {
            last_of_r,      // (256-192)=64bits
            length_padding  // 448bits
        }, "sha256_two_block_gadget_block2"));

        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

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
        // TODO: This may not be necessary if SHA256 constrains
        // its output digests to be boolean anyway.
        intermediate_hash->generate_r1cs_constraints();

        hasher1->generate_r1cs_constraints();
        hasher2->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        hasher1->generate_r1cs_witness();
        hasher2->generate_r1cs_witness();
    }
};

/**********************************************************
 * sha256_two_block_gadget, Add_gadget, Comparison_gadget
 ***************************************************************
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
 **********************************************************/
template<typename FieldT>
class commitment_with_add_and_less_gadget : public note_gadget_with_comparison_and_addition_for_balance<FieldT> {
public:
    // old commitment with sha256_two_block_gadget
    std::shared_ptr<digest_variable<FieldT>> cmtA_old; // cm
    std::shared_ptr<sha256_two_block_gadget<FieldT>> commit_to_inputs_old; // note_commitment

    // new commitment with sha256_two_block_gadget
    std::shared_ptr<digest_variable<FieldT>> cmtA; // cm
    std::shared_ptr<sha256_two_block_gadget<FieldT>> commit_to_inputs; // note_commitment
    
    // comparison_gadget inherited from note_gadget_with_comparison_and_addition_for_balance

    pb_variable<FieldT> ZERO;

    commitment_with_add_and_less_gadget(
        protoboard<FieldT>& pb
    ) : note_gadget_with_comparison_and_addition_for_balance<FieldT>(pb) {

        ZERO.allocate(pb);

        cmtA_old.reset(new digest_variable<FieldT>(pb, 256, "cmtA_old"));

        commit_to_inputs_old.reset(new sha256_two_block_gadget<FieldT>( 
            pb,
            ZERO,
            this->value_old,      // 64bits value for Mint
            this->sn_old->bits,   // 256bits serial number
            this->r_old->bits,    // 256bits random number
            cmtA_old
        ));

        cmtA.reset(new digest_variable<FieldT>(pb, 256, "cmtA"));

        commit_to_inputs.reset(new sha256_two_block_gadget<FieldT>( 
            pb,
            ZERO,
            this->value,       // 64bits value for Mint
            this->sn->bits,    // 256bits serial number
            this->r->bits,     // 256bits random number
            cmtA
        ));
    }

    // 约束函数，为commitment_with_add_and_less_gadget的变量生成约束
    void generate_r1cs_constraints() { 
        note_gadget_with_comparison_and_addition_for_balance<FieldT>::generate_r1cs_constraints();

        // Constrain `ZERO`
        generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), "ZERO");

        // TODO: These constraints may not be necessary if SHA256
        // already boolean constrains its outputs.
        cmtA_old->generate_r1cs_constraints();

        commit_to_inputs_old->generate_r1cs_constraints();

        cmtA->generate_r1cs_constraints();

        commit_to_inputs->generate_r1cs_constraints();
    }

    // 证据函数，为commitment_with_add_and_less_gadget的变量生成证据
    void generate_r1cs_witness(
        const Note& note_old, 
        const Note& note, 
        uint64_t v_s, 
        uint64_t b
    ) {
        //(const Note& note_old, const Note& note, uint64_t v_s, uint64_t b)
        note_gadget_with_comparison_and_addition_for_balance<FieldT>::generate_r1cs_witness(note_old, note, v_s, b);

        // Witness `zero`
        this->pb.val(ZERO) = FieldT::zero();

        // Witness the commitment of the input note
        commit_to_inputs_old->generate_r1cs_witness();

        // [SANITY CHECK] Ensure the commitment is
        // valid.
        cmtA_old->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note_old.cm())
        );

        // Witness the commitment of the input note
        commit_to_inputs->generate_r1cs_witness();

        // [SANITY CHECK] Ensure the commitment is
        // valid.
        cmtA->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.cm())
        );
    }
};

/***********************************************************
 * 模块整合，主要包括验证proof时所需要的publicData的输入
 * *********************************************************/
template<typename FieldT>
class mint_gadget : public commitment_with_add_and_less_gadget<FieldT> {
private:
    // Verifier inputs 验证者输入
    pb_variable_array<FieldT> zk_packed_inputs; // 合并为十进制
    pb_variable_array<FieldT> zk_unpacked_inputs; // 拆分为二进制
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker; // 二进制转十进制转换器

    /************************************************************************
     * std::shared_ptr<digest_variable<FieldT>> cmtA_old;  // this->cmtA_old
     * std::shared_ptr<digest_variable<FieldT>> sn_old;    // this->sn_old
     * std::shared_ptr<digest_variable<FieldT>> cmtA;      // this->cmtA
     * pb_variable_array<FieldT> value_s;                  // this->value_s
     * pb_variable_array<FieldT> balance_A;                // this->balance
     * *********************************************************************/
    //std::shared_ptr<commitment_with_add_and_less_gadget<FieldT>> cmt_add_less;

public:
    mint_gadget(protoboard<FieldT> &pb) : commitment_with_add_and_less_gadget<FieldT>(pb) {// 构造函数
        // Verification
        {
            // The verification inputs are all bit-strings of various
            // lengths (256-bit digests and 64-bit integers) and so we
            // pack them into as few field elements as possible. (The
            // more verification inputs you have, the more expensive
            // verification is.)
            zk_packed_inputs.allocate(pb, verifying_field_element_size()); 
            this->pb.set_input_sizes(verifying_field_element_size());

            alloc_uint256(zk_unpacked_inputs, this->cmtA_old);
            alloc_uint256(zk_unpacked_inputs, this->sn_old);
            alloc_uint256(zk_unpacked_inputs, this->cmtA);

            alloc_uint64(zk_unpacked_inputs, this->value_s); 
            alloc_uint64(zk_unpacked_inputs, this->balance);

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
        }
    }

    void generate_r1cs_constraints() {
        // The true passed here ensures all the inputs
        // are boolean constrained.
        unpacker->generate_r1cs_constraints(true);
  
        commitment_with_add_and_less_gadget<FieldT>::generate_r1cs_constraints();
    }

    void generate_r1cs_witness(
        const Note& note_old, 
        const Note& note, 
        uint64_t v_s, 
        uint64_t b
    ) {
        commitment_with_add_and_less_gadget<FieldT>::generate_r1cs_witness(note_old, note, v_s, b);

        // This happens last, because only by now are all the
        // verifier inputs resolved.
        unpacker->generate_r1cs_witness_from_bits();
    }

    // 将bit形式的私密输入 打包转换为 域上的元素
    static r1cs_primary_input<FieldT> witness_map(
        const uint256& cmtA_old,
        const uint256& sn_old,
        const uint256& cmtA,
        uint64_t value_s,
        uint64_t balance
    ) {
        std::vector<bool> verify_inputs;

        insert_uint256(verify_inputs, cmtA_old);
        insert_uint256(verify_inputs, sn_old);
        insert_uint256(verify_inputs, cmtA);

        insert_uint64(verify_inputs, value_s);
        insert_uint64(verify_inputs, balance);

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
        acc += 256; // cmtA
        
        acc += 64; // value_s
        acc += 64; // balance

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
        integer.allocate(this->pb, 64, "");
        packed_into.insert(packed_into.end(), integer.begin(), integer.end());
    }
};

/****************************************
 * 全局变量，用于测试
 * **************************************/
Note note_old_test, note_test;

// 生成proof
template<typename ppzksnark_ppT>
boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> generate_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                    uint64_t value_old,
                                                                    //uint256 sn_old,
                                                                    //uint256 r_old,
                                                                    uint64_t value,
                                                                    //uint256 sn,
                                                                    //uint256 r,
                                                                    uint64_t value_s,
                                                                    uint64_t balance
                                                                   )
{
    typedef Fr<ppzksnark_ppT> FieldT;
   
    // Note note_old = Note(value_old, sn_old, r_old);
    // Note note = Note(value, sn, r);

    note_old_test.value = value_old;
    note_old_test.sn = random_uint256();
    note_old_test.r = random_uint256();

    note_test.value = value;
    note_test.sn = random_uint256();
    note_test.r = random_uint256();

    Note note_old = Note(note_old_test.value, note_old_test.sn, note_old_test.r);
    Note note = Note(note_test.value, note_test.sn, note_test.r);

    protoboard<FieldT> pb;  // 定义原始模型，该模型包含constraint_system成员变量
    mint_gadget<FieldT> g(pb); // 构造新模型
    g.generate_r1cs_constraints(); // 生成约束

    g.generate_r1cs_witness(note_old, note, value_s, balance); // 为新模型的参数生成证明

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
                    const uint256& cmtA_old,
                    const uint256& sn_old,
                    const uint256& cmtA,
                    uint64_t value_s,
                    uint64_t balance
                  )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    // const r1cs_primary_input<FieldT> input = note_gadget_with_add_input_map<FieldT>(uint64_to_bool_vector(value)); // 获取输入，并转换为有限域上的值
    
    const r1cs_primary_input<FieldT> input = mint_gadget<FieldT>::witness_map(
        cmtA_old,
        sn_old,
        cmtA,
        value_s,
        balance
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

// test_comparison_gadget_with_instance, v = v_old + v_s && v_s < b
template<typename ppzksnark_ppT> //--Agzs
bool test_mint_gadget_with_instance(
                            uint64_t v_old, 
                            uint64_t v,
                            uint64_t v_s, 
                            uint64_t b
                        )
{
    typedef libff::Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;

    mint_gadget<FieldT> mint(pb);
    mint.generate_r1cs_constraints();// 生成约束

    // check conatraints
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    // key pair generation
    r1cs_ppzksnark_keypair<ppzksnark_ppT> keypair = r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);

    // 生成proof
    cout << "Trying to generate proof..." << endl;

    auto proof = generate_proof<default_r1cs_ppzksnark_pp>(keypair.pk, 
                                                            v_old,
                                                            v,
                                                            v_s,
                                                            b
                                                            );

    // verify proof
    if (!proof) {
        return false;
    } else {
        // PrintProof(*proof);

        //assert(verify_proof(keypair.vk, *proof));
        
        bool result = verify_proof(keypair.vk, 
                                   *proof, 
                                   note_old_test.cm(),
                                   note_old_test.sn,
                                   note_test.cm(),
                                   v_s,
                                   b
                                   );

        printf("verify result = %d\n", result);
         
        if (!result){
            cout << "Verifying proof unsuccessfully!!!" << endl;
        } else {
            cout << "Verifying proof successfully!!!" << endl;
        }
        
        return result;
    }
}

int main () {
    default_r1cs_ppzksnark_pp::init_public_params();
    //test_r1cs_gg_ppzksnark<default_r1cs_gg_ppzksnark_pp>(1000, 100);

    libff::print_header("#             testing mint gadget");

    uint64_t value = uint64_t(3); 
    uint64_t value_old = uint64_t(2); 
    uint64_t value_s = uint64_t(1);
    uint64_t balance = uint64_t(300); // 由于balance是对外公开的，所以blance>0;此处balance设为负数也能验证通过

    test_mint_gadget_with_instance<default_r1cs_ppzksnark_pp>(value_old, value, value_s, balance);

    // assert(test_comparison_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(6, 45, 40)); 
    // Note. cmake can not compile the assert()  --Agzs
    
    return 0;
}

