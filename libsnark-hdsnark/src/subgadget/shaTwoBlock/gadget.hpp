#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libff/algebra/fields/field_utils.hpp>

#include <iostream> //--Agzs

const size_t sha256_digest_len = 256;
//const size_t tuple_data_len = 256*3;

using namespace libff;

/*
// sha256算法流程：https://blog.csdn.net/code_segment/article/details/80273482
*/

// length of msg is 768 bits
bool sha256_padding[448] = {
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
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,1,0, 0,1,0,0,0,0,0,0}; // 8*8 = 64bits};


template<typename FieldT>
class sha_two_block_gadget : public gadget<FieldT> {
public:
    pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
    pb_variable_array<FieldT> input_as_bits; /* unpacked R1CS input */
    std::shared_ptr<multipacking_gadget<FieldT> > unpack_inputs; /* multipacking gadget 将 primary input 打包成 field 元素的 gadget*/

    // ======= Sha256 hash gadget for tuple data ======== 
    std::shared_ptr<digest_variable<FieldT>> hash_tuple_data_var; /* Hash(tuple_data) */

    //std::shared_ptr<digest_variable<FieldT>> tuple_data_var; /* tuple_data */
    pb_variable_array<FieldT> value;      // 64bits value for Mint
    std::shared_ptr<digest_variable<FieldT>> sn; // 256位的随机数r
    std::shared_ptr<digest_variable<FieldT>> r; // 256位的随机数r

     /* 1024 bit block that contains data(768 bits) + padding(256 bits) 分组处理，填充比特*/
    std::shared_ptr<block_variable<FieldT>> block1;
    std::shared_ptr<block_variable<FieldT>> block2;

     /* hashing gadget for tuple_data */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher1;
    std::shared_ptr<digest_variable<FieldT>> intermediate_hash; // 中间hash值
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher2;

    pb_variable<FieldT> zero;
    pb_variable_array<FieldT> padding_var; /* SHA256 length padding 填充*/

    //类sha_two_block_gadgett的构造函数
    sha_two_block_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb, "sha_two_block_gadget")
    {
        // Allocate space for the verifier input (result).
        const size_t input_size_in_bits = sha256_digest_len;
        {
            // We use a "multipacking" technique which allows us to constrain
            // the input bits in as few field elements as possible.
            
            // printf("\n======== test content =====\n");
            // printf("FieldT::capacity() = %zu", FieldT::capacity());
            // printf("\n============================\n");
            // FieldT::capacity() is 253.
            // input_size_in_field_elements = (256*3 + 253-1) / 253 = 4
            const size_t input_size_in_field_elements = div_ceil(input_size_in_bits, FieldT::capacity());
            input_as_field_elements.allocate(pb, input_size_in_field_elements, "input_as_field_elements");
            this->pb.set_input_sizes(input_size_in_field_elements);
        }

        zero.allocate(this->pb, FMT(this->annotation_prefix, "zero")); // zero 由0变为有限域上5 in finite field
        // printf("\n======== test content =====\n");
        // printf("zero = %zu\n", zero);
        // printf("\nONE = %zu", ONE);
        // printf("\n============================\n");

        // SHA256's length padding 位数填充至512bit, 转换为域上相应的值
        for (size_t i = 0; i < 448; i++) {
            if (sha256_padding[i])
                padding_var.emplace_back(ONE); // 类似于push_back()，但是比其速度更快, ONE是有限域上的0
            else
                padding_var.emplace_back(zero); // zero是有限域上的5
        }

        // Verifier (and prover) inputs:
        hash_tuple_data_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "hash_tuple_data"));// reset重置一个新的shared_ptr对象"hash_tuple_data"

        // 在指定位置input_as_bits.end()前“插入”区间 [ *_var->bits.begin(), *_var->bits.end() ) 的所有元素.
        input_as_bits.insert(input_as_bits.end(), hash_tuple_data_var->bits.begin(), hash_tuple_data_var->bits.end());
        
        // Multipacking 分块处理，块大小由FieldT::capacity()确定
        assert(input_as_bits.size() == input_size_in_bits); // 插入的h1, h2, x, 每个长度都为sha256_digest_len
        unpack_inputs.reset(new multipacking_gadget<FieldT>(this->pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " unpack_inputs")));


        // Prover inputs:
        // Convert multi-attribute into one tuple
        //tuple_data_var.reset(new digest_variable<FieldT>(pb, tuple_data_len, "tuple_data")); 
        value.allocate(pb, 64);
        sn.reset(new digest_variable<FieldT>(pb, 256, "serial number"));
        r.reset(new digest_variable<FieldT>(pb, 256, "random number"));

        // IV for SHA256 初始化SHA256缓存
        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        // pb_variable_array<FieldT> first_of_data(tuple_data_var->bits.begin(), tuple_data_var->bits.begin()+512);
        // pb_variable_array<FieldT> last_of_data(tuple_data_var->bits.begin()+512, tuple_data_var->bits.end());
        pb_variable_array<FieldT> first_of_r(r->bits.begin(), r->bits.begin()+192);
        pb_variable_array<FieldT> last_of_r(r->bits.begin()+192, r->bits.end());

        intermediate_hash.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "intermediate_hash"));

        block1.reset(new block_variable<FieldT>(pb, {
            value,           // 64bits
            sn->bits,      // 256bits
            first_of_r   // 192bits
        }, "sha256_two_block_gadget_block1"));

        block2.reset(new block_variable<FieldT>(pb, {
            last_of_r,      // (256-192)=64bits
            padding_var  // 448bits
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
            *hash_tuple_data_var,
        "sha256_two_block_hash2"));
    }

    void generate_r1cs_constraints() {

        // Multipacking constraints (for input validation)
        unpack_inputs->generate_r1cs_constraints(true);

        // Ensure bitness of the digests. Bitness of the inputs
        // is established by `unpack_inputs->generate_r1cs_constraints(true)`
        //tuple_data_var->generate_r1cs_constraints();
        sn->generate_r1cs_constraints(); // 随机数的约束
        r->generate_r1cs_constraints(); // 随机数的约束

        generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");

        // TODO: This may not be necessary if SHA256 constrains
        // its output digests to be boolean anyway.
        intermediate_hash->generate_r1cs_constraints();

        hasher1->generate_r1cs_constraints();
        hasher2->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(const bit_vector &h_data, 
                               const bit_vector &v_data,
                               const bit_vector &sn_data,
                               const bit_vector &r_data
                                ) {
        value.fill_with_bits(this->pb, v_data);
        sn->bits.fill_with_bits(this->pb, sn_data);
        r->bits.fill_with_bits(this->pb, r_data);
        //tuple_data_var->bits.fill_with_bits(this->pb, tuple_data);
        this->pb.val(zero) = FieldT::zero();

        hasher1->generate_r1cs_witness();
        hasher2->generate_r1cs_witness();

        unpack_inputs->generate_r1cs_witness_from_bits();

        hash_tuple_data_var->bits.fill_with_bits(this->pb, h_data);
    }
};

template<typename FieldT>
r1cs_primary_input<FieldT> l_input_map(const bit_vector &hash)
{
    // Construct the multipacked field points which encode
    // the verifier's knowledge. This is the "dual" of the
    // multipacking gadget logic in the constructor.
    assert(hash.size() == sha256_digest_len);

    bit_vector input_as_bits;
    input_as_bits.insert(input_as_bits.end(), hash.begin(), hash.end());
    std::vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);
    return input_as_field_elements;
}
