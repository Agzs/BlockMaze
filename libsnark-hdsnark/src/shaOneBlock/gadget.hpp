#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libff/algebra/fields/field_utils.hpp>

#include <iostream> //--Agzs
#include <string>
#include <stdlib.h>
#include <math.h>
#include "premium_computation_gadget.hpp"

const size_t sha256_digest_len = 256;

// const size_t heartbeat_len = 8;
// const size_t blood_pressure_len = 16;
// const size_t height_len = 8;
// const size_t weight_len = 8;
// const size_t lung_capacity_len = 16;
// const size_t ID_len = 16;
// const size_t time_len = 24;
// const size_t random_number_len = 160;

const size_t tuple_data_len = 256 * 2; // instead of padding

const size_t coeff_num = 60; // max is 64
const size_t coeff_len = 8 * coeff_num; // each coefficient is 8 bits.
const size_t single_attr_len = 8;

const size_t premium_len = 16;

//const size_t mutli_attribute_value_len = heartbeat_len + blood_pressure_len + height_len + weight_len + lung_capacity_len;


using namespace libff;
using namespace libsnark;

/*
tuple data = x_1, x_2, ..., x_n, ID, T, r
Heartbeat, BloodPressure, Height, Weight, LungCapacity, ID, Time, RandomNumer

Premium = C_0 + C_1 * HealthRating

HealthRating = (Hearbeat-)

http://www.lifeant.com/life-insurance-medical-exam-info/

人寿保险是由两部分构成的：分别是纯保险费和附加保费。
前者用于保险金的给付;后者用于保险公司业务经营费用的开支，二者的总和就是营业保险费，亦称毛保费。其计算公式为：毛保费=纯保费+附加保费。
保险费=保险金额*保险费率

*/


template<typename FieldT>
class hdsnark_gadget : public gadget<FieldT> {
public:
    pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
    pb_variable_array<FieldT> input_as_bits; /* unpacked R1CS input */
    std::shared_ptr<multipacking_gadget<FieldT> > unpack_inputs; /* multipacking gadget 将 primary input 打包成 field 元素的 gadget*/
  
    // ======= Sha256 hash gadget for tuple data ======== 
    std::shared_ptr<digest_variable<FieldT>> hash_tuple_data_var; /* Hash(tuple_data) */
    
    // Heartbeat, BloodPressure, Height, Weight, LungCapacity, ID, Time, RandomNumer

    // std::shared_ptr<digest_variable<FieldT>> HB_var; /* Heartbeat         8 bits */
    // std::shared_ptr<digest_variable<FieldT>> BP_var; /* Blood Pressure(diastolic and systolic)  8+8 bits */
    // std::shared_ptr<digest_variable<FieldT>> H_var;  /* Height            8 bits */
    // std::shared_ptr<digest_variable<FieldT>> W_var;  /* Weight            8 bits */
    // std::shared_ptr<digest_variable<FieldT>> LC_var; /* Lung Capacity     16 bits */
    // std::shared_ptr<digest_variable<FieldT>> ID_var; /* ID                16 bits */
    // std::shared_ptr<digest_variable<FieldT>> T_var;  /* Time(yyyy/mm/dd)  12+4+8 bits */
    // std::shared_ptr<digest_variable<FieldT>> R_var;  /* RandomNumer       20*8 bits */

    // std::vector<digest_variable<FieldT>> tuple_data(256); 
    
    std::shared_ptr<digest_variable<FieldT>> tuple_data_var; /* tuple_data */
    
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_gadget_tuple_data; /* hashing gadget for tuple_data */

    // ======= sha256 hash gadget for premium computation coefficient ========
    // std::shared_ptr<digest_variable<FieldT>> hash_coeff_var; /* Hash(coeff_var) */

    // std::shared_ptr<digest_variable<FieldT>> coeff_var; /* coefficient_var */

    // std::shared_ptr<block_variable<FieldT>> h_coeff_block; /* 512 bit block that contains coeff_var + padding 分组处理，填充比特*/
    
    // std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_gadget_coeff; /* hashing gadget for coeff_var */
    
    // ======= Premium computation hash gadget ======== 
    std::shared_ptr<digest_variable<FieldT>> result_var; // premium
    
    std::shared_ptr<digest_variable<FieldT>> coeff_var; /* coefficient_var */
    pb_variable_array<FieldT> A_var; // multi-attribute value 
    pb_variable_array<FieldT> B_var; // related coefficient

    //// pb_variable<FieldT> result;
    
    //=> TODO. 这里应该添加一个premium_computation_gadget，暂时命名为premium_gadget，用于验证保费确实是由hash原象计算而来。--Agzs
    std::shared_ptr<premium_computation_gadget<FieldT>> premium_gadget; /* premium gadget for multi-attribute value */

    //类hdsnark_gadget的构造函数
    hdsnark_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb, "hdsnark_gadget")
    {
        // Allocate space for the verifier input (Hash_data, coeff, Premium).
        const size_t input_size_in_bits = sha256_digest_len + coeff_len + premium_len;
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


        // Verifier (and prover) inputs (Hash, Premium):
        hash_tuple_data_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "hash_tuple_data"));// reset重置一个新的shared_ptr对象"hash_tuple_data"
        // hash_coeff_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "hash_coeff"));// reset重置一个新的shared_ptr对象"hash_coeff"
        result_var.reset(new digest_variable<FieldT>(pb, premium_len, "result_var"));
        coeff_var.reset(new digest_variable<FieldT>(pb, coeff_len, "coeff_var")); 

        A_var.allocate(pb, coeff_num, "A_var");
        B_var.allocate(pb, coeff_num, "B_var");
    
        //// result.allocate(pb, "result");

        // 在指定位置input_as_bits.end()前“插入”区间 [ *_var->bits.begin(), *_var->bits.end() ) 的所有元素.
        input_as_bits.insert(input_as_bits.end(), hash_tuple_data_var->bits.begin(), hash_tuple_data_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), coeff_var->bits.begin(), coeff_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), result_var->bits.begin(), result_var->bits.end());
        
        // Multipacking 分块处理，块大小由FieldT::capacity()确定
        assert(input_as_bits.size() == input_size_in_bits); // 插入的Hash, Premium, 长度分别为sha256_digest_len，premium_len
        unpack_inputs.reset(new multipacking_gadget<FieldT>(this->pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " unpack_inputs")));


        // // Prover inputs one tuple:
        // tuple_data_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "tuple_data"));

        // Prover inputs multi-attribute:
        // HB_var.reset(new digest_variable<FieldT>(pb, heartbeat_len, "HB"));
        // BP_var.reset(new digest_variable<FieldT>(pb, blood_pressure_len, "BP"));
        // H_var.reset(new digest_variable<FieldT>(pb, height_len, "H"));
        // W_var.reset(new digest_variable<FieldT>(pb, weight_len, "W"));
        // LC_var.reset(new digest_variable<FieldT>(pb, lung_capacity_len, "LC"));
        // ID_var.reset(new digest_variable<FieldT>(pb, ID_len, "ID"));
        // T_var.reset(new digest_variable<FieldT>(pb, time_len, "T"));
        // R_var.reset(new digest_variable<FieldT>(pb, random_number_len, "R"));
        
        // Convert multi-attribute into one tuple
        tuple_data_var.reset(new digest_variable<FieldT>(pb, tuple_data_len, "tuple_data")); 
        

        // IV for SHA256 初始化SHA256缓存
        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        // Initialize the hash gadget for tuple_data's hash
        h_gadget_tuple_data.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                  IV,
                                                                  tuple_data_var->bits,
                                                                  *hash_tuple_data_var,
                                                                  "h_gadget_tuple_data"));


        //=> TODO. 这里应该初始化premium_computation_gadget，可参考basic_gadget。--Agzs
        //=> How to change result_var->bits to result
        //=>   pb_variable_array<FieldT>  vector<pb_variable<FieldT> >  pb_variable          
        premium_gadget.reset(new premium_computation_gadget<FieldT>(pb,
                                                            A_var,
                                                            B_var,
                                                            result_var->bits, //// result,
                                                            "premium_gadget"));

    }

    //类hdsnark_gadget生成约束
    void generate_r1cs_constraints()
    {   
        // Multipacking constraints (for input validation)
        unpack_inputs->generate_r1cs_constraints(true);

        // Ensure bitness of the digests. Bitness of the inputs
        // is established by `unpack_inputs->generate_r1cs_constraints(true)`
        tuple_data_var->generate_r1cs_constraints();
        coeff_var->generate_r1cs_constraints();

        for (size_t i = 0; i < A_var.size(); ++i)
        {
            //coeff_B_filed is the filed of B's binary format 
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(this->pb.val(B_var[i]), FieldT(1),
                  FieldT::zero()+
                  ((this->pb.val(coeff_var->bits[i*8]) == FieldT(1)) ? pow(2, 7) : 0)+
                  ((this->pb.val(coeff_var->bits[i*8+1]) == FieldT(1)) ? pow(2, 6) : 0)+
                  ((this->pb.val(coeff_var->bits[i*8+2]) == FieldT(1)) ? pow(2, 5) : 0)+
                  ((this->pb.val(coeff_var->bits[i*8+3]) == FieldT(1)) ? pow(2, 4) : 0)+
                  ((this->pb.val(coeff_var->bits[i*8+4]) == FieldT(1)) ? pow(2, 3) : 0)+
                  ((this->pb.val(coeff_var->bits[i*8+5]) == FieldT(1)) ? pow(2, 2) : 0)+
                  ((this->pb.val(coeff_var->bits[i*8+6]) == FieldT(1)) ? pow(2, 1) : 0)+
                  ((this->pb.val(coeff_var->bits[i*8+7]) == FieldT(1)) ? pow(2, 0) : 0)),
                FMT(this->annotation_prefix, " S_%zu", i));
        }


        // These are the constraints to ensure the hashes validate.
        h_gadget_tuple_data->generate_r1cs_constraints();
        // h_gadget_coeff->generate_r1cs_constraints();
        //=> TODO. 这里应该为premium_computation_gadget生成约束，可参考basic_gadget。--Agzs
        premium_gadget->generate_r1cs_constraints();
    }

    //类hdsnark_gadget生成witness
    void generate_r1cs_witness(const bit_vector &h_data, 
                                const bit_vector &tuple_data,
                                const bit_vector &data_coeff,
                                const bit_vector &premium
                                )
    {
        // Prase multi-attribute from one tuple, transfer into size_t
        std::vector<size_t> a;
        std::vector<size_t> b;

        size_t attr_to_size_t = 0;
        size_t coeff_to_size_t = 0;
        size_t coeff_cnt = 1;

        unsigned int j = 0;
        while (j < coeff_len && coeff_cnt <= coeff_num) {
            
            attr_to_size_t += (tuple_data[j] ? 1 : 0) * pow(2, coeff_cnt*single_attr_len-1-j);
            coeff_to_size_t += (data_coeff[j] ? 1 : 0) * pow(2, coeff_cnt*single_attr_len-1-j);
            j ++;
            
            if (j % single_attr_len == 0) {
                a.push_back(attr_to_size_t);
                b.push_back(coeff_to_size_t);
                attr_to_size_t = 0;
                coeff_to_size_t = 0;
                coeff_cnt ++;
            }
        }

        tuple_data_var->bits.fill_with_bits(this->pb, tuple_data);

        coeff_var->bits.fill_with_bits(this->pb, data_coeff);

        /////////////////////

        // Generate witnesses as necessary in our other gadgets
        h_gadget_tuple_data->generate_r1cs_witness();
        // h_gadget_coeff->generate_r1cs_witness();
        
        //=> TODO. 这里应该为premium_computation_gadget生成witness，可参考basic_gadget。--Agzs
        assert(a.size() == b.size());
        size_t correct = 0;
        for (unsigned int i = 0; i < a.size(); ++i) {
            this->pb.val(A_var[i]) = FieldT::zero();
            this->pb.val(B_var[i]) = FieldT::zero();
            for (unsigned int k = 0; k < a[i]; ++k) {
                this->pb.val(A_var[i]) += FieldT::one();
            }
            for (unsigned int k = 0; k < b[i]; ++k) {
                this->pb.val(B_var[i]) += FieldT::one();
            }
            correct += a[i] * b[i];
            // printf("positive test for (%zu, %zu), and correct = %zu\n", a[i], b[i], correct);
        }
        // printf("********* positive test for premium correct = %zu *********\n", correct);

        result_var->bits.fill_with_bits(this->pb, premium); // must place it before generate_r1cs_witness();
        
        premium_gadget->generate_r1cs_witness();

        //// assert(this->pb.val(result) == FieldT(correct));
        
        unpack_inputs->generate_r1cs_witness_from_bits();

        hash_tuple_data_var->bits.fill_with_bits(this->pb, h_data);
        // hash_coeff_var->bits.fill_with_bits(this->pb, hash_coeff);

        //// result_var->bits.fill_with_bits(this->pb, premium);
        
        size_t premium_to_size_t = 0;
        for (unsigned int j = 0; j < premium_len; j++){
            premium_to_size_t += (premium[j] ? 1 : 0) * pow(2, premium_len-j-1);
        }
        //// cout << "********* bit_to_size_t = " << bit_to_size_t << " ******" << endl;

        //// assert(this->pb.val(result) == FieldT(bit_to_size_t));
        assert(FieldT(correct) == FieldT(premium_to_size_t));
    }
};

template<typename FieldT>
r1cs_primary_input<FieldT> hdsnark_input_map(const bit_vector &h_data,
                                             const bit_vector &data_coeff,
                                             const bit_vector &premium
                                             )
{
    // Construct the multipacked field points which encode
    // the verifier's knowledge. This is the "dual" of the
    // multipacking gadget logic in the constructor.
    assert(h_data.size() == sha256_digest_len);
    assert(data_coeff.size() == coeff_len);
    assert(premium.size() == premium_len);
   
    bit_vector input_as_bits;
    input_as_bits.insert(input_as_bits.end(), h_data.begin(), h_data.end());
    input_as_bits.insert(input_as_bits.end(), data_coeff.begin(), data_coeff.end());
    input_as_bits.insert(input_as_bits.end(), premium.begin(), premium.end());
    std::vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);
    return input_as_field_elements;
}
