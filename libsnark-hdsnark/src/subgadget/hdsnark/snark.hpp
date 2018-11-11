#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libff/common/utils.hpp"
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp"
#include <boost/optional.hpp>
#include "gadget.hpp"

using namespace libff;
using namespace libsnark;
using namespace std;

/***********************************
 * R1CS = "Rank-1 Constraint Systems"
 * ppzkSNARK = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
 ******************************************** 
*/

// 生成密钥对
template<typename ppzksnark_ppT>
r1cs_ppzksnark_keypair<ppzksnark_ppT> generate_keypair()
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;  // 定义原始模型，该模型包含constraint_system成员变量
    hdsnark_gadget<FieldT> g(pb); // 构造新模型
    g.generate_r1cs_constraints(); // 生成约束
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system(); // 获取约束系统

    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;

    // 调用libsnark库中生成密钥对的函数    
    return r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);
}

// 生成proof
template<typename ppzksnark_ppT>
boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> generate_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                    const bit_vector &h_data, 
                                                                    const bit_vector &tuple_data,
                                                                    //const bit_vector &hash_coeff,
                                                                    const bit_vector &data_coeff,
                                                                    const bit_vector &premium
                                                                   )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;  // 定义原始模型，该模型包含constraint_system成员变量
    hdsnark_gadget<FieldT> g(pb); // 构造新模型
    g.generate_r1cs_constraints(); // 生成约束
    g.generate_r1cs_witness(h_data, 
                            tuple_data,
                            //hash_coeff,
                            data_coeff,                                                            
                            premium
                            ); // 为新模型的参数生成证明


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
                  const bit_vector &h_data,
                  const bit_vector &data_coeff,
                  const bit_vector &premium
                  )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    const r1cs_primary_input<FieldT> input = hdsnark_input_map<FieldT>(h_data, data_coeff, premium); // 获取输入，并转换为有限域上的值

    // 调用libsnark库中验证proof的函数
    return r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}


template<typename ppzksnark_ppT>
void PrintProof(r1cs_ppzksnark_proof<ppzksnark_ppT> proof)
{
    printf("================== Print proof ==================================\n");
    // std::cout << proof << endl;
    // printf("proof is %x\n", *proof);
    std::cout << "hdsnark proof with r1cs_ppzksnark:\n";

    /*
      为把平常点和无穷远点的坐标统一起来，把点的坐标用（X，Y，Z）表示，X，Y，Z不能同时为0，
      且对平常点（x，y）来说，有Z≠0，x=X/Z，y=Y/Z，这样对于无穷远点则有Z=0，也成立。
    */

    std::cout << "\n knowledge_commitment<G1<ppT>, G1<ppT> > g_A: " << endl;
    proof.g_A.print();
    std::cout << endl;

    std::cout << "\n knowledge_commitment<G2<ppT>, G1<ppT> > g_B: " << endl;
    proof.g_B.print();
    std::cout << endl;

    std::cout << "\n knowledge_commitment<G1<ppT>, G1<ppT> > g_C: " << endl;
    proof.g_C.print();
    std::cout << endl;

    std::cout << "\n G1<ppT> g_H: " << endl;
    proof.g_H.print();
    std::cout << endl;

    std::cout << "\n G1<ppT> g_K: " << endl;
    proof.g_K.print();

    printf("=================================================================\n");
}
