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


/**********************************************
 * note_gadget and add_gadget
 * ********************************************/
template<typename FieldT>
class note_gadget_with_add : public gadget<FieldT> { // 基类，基本的note_gadget,仅含value和随机数r
public:
    pb_variable_array<FieldT> value_old; // 64位的value
    pb_variable_array<FieldT> value_s; // 64位的value
    pb_variable_array<FieldT> value; // 64位的value

    note_gadget_with_add(protoboard<FieldT> &pb) : gadget<FieldT>(pb) {
        value.allocate(pb, 64);        
        value_old.allocate(pb, 64);
        value_s.allocate(pb, 64);
    }

    void generate_r1cs_constraints() { // const Note& note

        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value_old[i],
                "boolean_value_old"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value_s[i],
                "boolean_value_s"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value[i],
                "boolean_value"
            );
        }

        // Addition constraint
        // 1 * (value_old + value_s) = this->value 
        // There may exist error !!!!

        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
            1,
            (packed_addition(this->value_old) + packed_addition(this->value_s)),
            packed_addition(this->value)
        ), "1 * (value_old + value_s) = this->value");

        // std::cout << "packed_addition(this->value_old) = " << packed_addition(this->value_old) << endl;
        // std::cout << "packed_addition(this->value_s) = " << packed_addition(this->value_s) << endl;
        // std::cout << "packed_addition(this->value) = " << packed_addition(this->value) << endl;

        // this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
        //     1,
        //     (packed_addition_fieldT(this->value_old) + packed_addition_fieldT(this->value_s)),
        //     packed_addition_fieldT(this->value)
        // ), "1 * (value_old + value_s) = this->value");

        
        // this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
        //     packed_addition(this->value),
        //     FieldT::one(),
        //     FieldT::one() * (note.value_old + note.value_s)
        // ), "");

    }

    void generate_r1cs_witness(uint64_t v, uint64_t v_old, uint64_t v_s) { // 为变量生成约束
        
        value_old.fill_with_bits(this->pb, uint64_to_bool_vector(v_old));

        value_s.fill_with_bits(this->pb, uint64_to_bool_vector(v_s));

        value.fill_with_bits(this->pb, uint64_to_bool_vector(v));

        std::cout << "*******************************************\n value_old = [ ";
        // for (size_t i = 0; i < 64; i++) {
        //     printf("%d, ", value_old[i]);
        // }
        BOOST_FOREACH(bool bit, value_old.get_bits(this->pb)) {
            printf("%d, ", bit);
        }
        std::cout << "]\n*******************************************\n";
        std::cout << "*******************************************\n value_s = [ ";
        // for (size_t i = 0; i < 64; i++) {
        //     printf("%d, ", value_s[i]);
        // }
        BOOST_FOREACH(bool bit, value_s.get_bits(this->pb)) {
            printf("%d, ", bit);
        }
        std::cout << "]\n*******************************************\n";
        std::cout << "*******************************************\n value = [ ";
        // for (size_t i = 0; i < 64; i++) {
        //     printf("%d, ", value[i]);
        // }
        BOOST_FOREACH(bool bit, value.get_bits(this->pb)) {
            printf("%d, ", bit);
        }
        std::cout << "]\n*******************************************\n";
    }
};


