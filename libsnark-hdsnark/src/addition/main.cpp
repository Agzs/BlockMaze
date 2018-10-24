#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp"
#include "gadget.hpp"

using namespace libff;
using namespace libsnark;
using namespace std;


template<typename ppzksnark_ppT>
r1cs_ppzksnark_keypair<ppzksnark_ppT> generate_keypair()
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;  // 定义原始模型，该模型包含constraint_system成员变量
    note_gadget_with_add<FieldT> g(pb); // 构造新模型
    g.generate_r1cs_constraints(); // 生成约束
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system(); // 获取约束系统

    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;

    // 调用libsnark库中生成密钥对的函数    
    return r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);
}


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
    note_gadget_with_add<FieldT> g(pb); // 构造新模型
    g.generate_r1cs_constraints(); // 生成约束
    g.generate_r1cs_witness(value, value_old, value_s); // 为新模型的参数生成证明

    cout << "pb.is_satisfied() is " << pb.is_satisfied() << endl;

    if (!pb.is_satisfied()) { // 三元组R1CS是否满足  < A , X > * < B , X > = < C , X >
        return boost::none;
    }

    // 调用libsnark库中生成proof的函数
    return r1cs_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

template<typename FieldT>
r1cs_primary_input<FieldT> note_gadget_with_add_input_map(const bit_vector &value)
{
    // Construct the multipacked field points which encode
    // the verifier's knowledge. This is the "dual" of the
    // multipacking gadget logic in the constructor.
    assert(value.size() == 64);
    // assert(premium.size() == premium_len);
   
    bit_vector input_as_bits;
    input_as_bits.insert(input_as_bits.end(), value.begin(), value.end());
    std::vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);
    return input_as_field_elements;
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

    // std::cout << "\n knowledge_commitment<G2<ppT>, G1<ppT> > g_B: \n " << proof.g_B << endl;
    // std::cout << "\n knowledge_commitment<G2<ppT>, G1<ppT> > g_B: \n " << proof.g_B << endl;
    // std::cout << "\n knowledge_commitment<G1<ppT>, G1<ppT> > g_C: \n " << proof.g_C << endl;

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

// test_add_gadget_with_instance
template<typename ppzksnark_ppT> //--Agzs
bool test_add_gadget_with_instance(uint64_t value, 
                        uint64_t value_old, 
                        uint64_t value_s
                        )
{
    default_r1cs_ppzksnark_pp::init_public_params();
    // Generate the verifying/proving keys. (This is trusted setup!)
    auto keypair = generate_keypair<default_r1cs_ppzksnark_pp>();

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
        PrintProof(*proof);

        return verify_proof(keypair.vk, *proof);
        // return verify_proof(keypair.vk, *proof, value);
    }
   
    return true;
}

int main () {
    default_r1cs_ppzksnark_pp::init_public_params();
    //test_r1cs_gg_ppzksnark<default_r1cs_gg_ppzksnark_pp>(1000, 100);

    libff::print_header("#             test addition gadget with assert()");
    
    // uint256 r = uint256S("0x000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317");
    uint64_t value = uint64_t(251); 
    uint64_t value_old = uint64_t(252); 
    uint64_t value_s = uint64_t(-1);

    test_add_gadget_with_instance<default_r1cs_ppzksnark_pp>(value, value_old, value_s);

    return 0;
}