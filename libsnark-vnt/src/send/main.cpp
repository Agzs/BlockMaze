#include <stdio.h>
#include <iostream>

#include <boost/optional.hpp>
#include <boost/foreach.hpp>
#include <boost/format.hpp>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

#include "Note.h"

using namespace libsnark;
using namespace libff;
using namespace std;

#include "circuit/gadget.tcc"

#define DEBUG 0

// 生成proof
template<typename ppzksnark_ppT>
boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> generate_send_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                    const Note& note_old,
                                                                    const NoteS& notes,
                                                                    const Note& note,
                                                                    uint256 cmtA_old,
                                                                    uint256 cmtS,
                                                                    uint256 cmtA
                                                                   )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;  // 定义原始模型，该模型包含constraint_system成员变量
    send_gadget<FieldT> send(pb); // 构造新模型
    send.generate_r1cs_constraints(); // 生成约束

    send.generate_r1cs_witness(note_old, notes, note, cmtA_old, cmtS, cmtA); // 为新模型的参数生成证明

    cout << "pb.is_satisfied() is " << pb.is_satisfied() << endl;

    if (!pb.is_satisfied()) { // 三元组R1CS是否满足  < A , X > * < B , X > = < C , X >
        return boost::none;
    }

    // 调用libsnark库中生成proof的函数
    return r1cs_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

// 验证proof
template<typename ppzksnark_ppT>
bool verify_send_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                    r1cs_ppzksnark_proof<ppzksnark_ppT> proof,
                    const uint256& cmtA_old,
                    const uint256& sn_old,
                    const uint256& cmtS,
                    const uint256& cmtA     
                  )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    const r1cs_primary_input<FieldT> input = send_gadget<FieldT>::witness_map(
        cmtA_old,
        sn_old,
        cmtS,
        cmtA
    ); 

    // 调用libsnark库中验证proof的函数
    return r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}

template<typename ppzksnark_ppT>
void PrintProof(r1cs_ppzksnark_proof<ppzksnark_ppT> proof)
{
    printf("================== Print proof ==================================\n");
    //printf("proof is %x\n", *proof);
    std::cout << "send proof:\n";

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

template<typename ppzksnark_ppT> //--Agzs
bool test_send_gadget_with_instance(
                            uint64_t value_old,
                            //uint256 sn_old,
                            //uint256 r_old,
                            //uint256 sn,
                            //uint256 r,
                            //uint256 cmtA_old,
                            //uint256 cmtA,
                            uint64_t value_s,
                            uint64_t value
                        )
{
    // Note note_old = Note(value_old, sn_old, r_old);
    // Note note = Note(value, sn, r);

    // uint256 sn_test = random_uint256();
    // uint256 r_test = random_uint256();
   
    uint256 sn_old = uint256S("123456");//random_uint256();
    uint256 r_old = uint256S("123456");//random_uint256();
    Note note_old = Note(value_old, sn_old, r_old);
    uint256 cmtA_old = note_old.cm();

    uint160 pk = uint160S("123");
    uint256 sn_s = uint256S("123");//random_uint256();
    uint256 r_s = uint256S("123");//random_uint256();
    NoteS notes = NoteS(value_s, pk, sn_s, r_s, sn_old);
    uint256 cmtS = notes.cm();

    //printf("value_old+value_s = %zu\n", value_old+value_s);
    uint256 sn = uint256S("12");//random_uint256();
    uint256 r = uint256S("12");//random_uint256();
    Note note = Note(value, sn, r);
    uint256 cmtA = note.cm();

    // wrong test data
    uint256 wrong_sn_old = uint256S("666");
    uint256 wrong_cmtS = note_old.cm();
    uint256 wrong_cmtA_old = note.cm();
    uint256 wrong_cmtA = note_old.cm();
    
    typedef libff::Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;

    send_gadget<FieldT> send(pb);
    send.generate_r1cs_constraints();// 生成约束

    // check conatraints
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    
    // key pair generation
    r1cs_ppzksnark_keypair<ppzksnark_ppT> keypair = r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);

    // 生成proof
    cout << "Trying to generate proof..." << endl;

    auto proof = generate_send_proof<default_r1cs_ppzksnark_pp>(keypair.pk, 
                                                            note_old,
                                                            notes,
                                                            note,
                                                            cmtA_old, // wrong_cmtA_old
                                                            cmtS, // wrong_cmtS
                                                            cmtA // wrong_cmtA
                                                            );

    // verify proof
    if (!proof) {
        printf("generate send proof fail!!!\n");
        return false;
    } else {
        PrintProof(*proof);

        //assert(verify_send_proof(keypair.vk, *proof));
        
        bool result = verify_send_proof(keypair.vk, 
                                   *proof, 
                                   cmtA_old,
                                   sn_old,
                                   cmtS,
                                   cmtA
                                   );

        //printf("verify result = %d\n", result);
         
        if (!result){
            cout << "Verifying send proof unsuccessfully!!!" << endl;
        } else {
            cout << "Verifying send proof successfully!!!" << endl;
        }
        
        return result;
    }
}

int main () {
    default_r1cs_ppzksnark_pp::init_public_params();

    libff::print_header("#             testing send gadget");

    uint64_t value = uint64_t(14); 
    uint64_t value_old = uint64_t(22); 
    uint64_t value_s = uint64_t(8);

    test_send_gadget_with_instance<default_r1cs_ppzksnark_pp>(value_old, value_s, value);

    // Note. cmake can not compile the assert()  --Agzs
    
    return 0;
}

