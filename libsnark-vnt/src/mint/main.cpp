#include <stdio.h>
#include <iostream>

#include <boost/optional.hpp>
#include <boost/foreach.hpp>
#include <boost/format.hpp>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

#include<sys/time.h>

#include "Note.h"

using namespace libsnark;
using namespace libff;
using namespace std;

#include "circuit/gadget.tcc"

#define DEBUG 0

// 生成proof
template<typename ppzksnark_ppT>
boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> generate_mint_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                    const Note& note_old,
                                                                    const Note& note,
                                                                    uint256 cmtA_old,
                                                                    uint256 cmtA,
                                                                    uint64_t value_s
                                                                   )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;  // 定义原始模型，该模型包含constraint_system成员变量
    mint_gadget<FieldT> g(pb); // 构造新模型
    g.generate_r1cs_constraints(); // 生成约束

    g.generate_r1cs_witness(note_old, note, cmtA_old, cmtA, value_s); // 为新模型的参数生成证明

    cout << "pb.is_satisfied() is " << pb.is_satisfied() << endl;

    if (!pb.is_satisfied()) { // 三元组R1CS是否满足  < A , X > * < B , X > = < C , X >
        return boost::none;
    }

    // 调用libsnark库中生成proof的函数
    return r1cs_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

// 验证proof
template<typename ppzksnark_ppT>
bool verify_mint_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                    r1cs_ppzksnark_proof<ppzksnark_ppT> proof,
                    const uint256& cmtA_old,
                    const uint256& sn_old,
                    const uint256& cmtA,
                    uint64_t value_s
                  )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    const r1cs_primary_input<FieldT> input = mint_gadget<FieldT>::witness_map(
        cmtA_old,
        sn_old,
        cmtA,
        value_s
    ); 

    // 调用libsnark库中验证proof的函数
    return r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}

template<typename ppzksnark_ppT>
void PrintProof(r1cs_ppzksnark_proof<ppzksnark_ppT> proof)
{
    printf("================== Print proof ==================================\n");
    //printf("proof is %x\n", *proof);
    std::cout << "mint proof:\n";

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
bool test_mint_gadget_with_instance(
                            uint64_t value,
                            uint64_t value_old,
                            //uint256 sn_old,
                            //uint256 r_old,
                            //uint256 sn,
                            //uint256 r,
                            //uint256 cmtA_old,
                            //uint256 cmtA,
                            uint64_t value_s,
                            r1cs_ppzksnark_keypair<ppzksnark_ppT> keypair
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

    uint256 sn = uint256S("123");//random_uint256();
    uint256 r = uint256S("123");//random_uint256();
    Note note = Note(value, sn, r);
    uint256 cmtA = note.cm();

    //printf("value_old+value_s = %zu\n", value_old+value_s);
    
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

    struct timeval gen_start, gen_end;
    double mintTimeUse;
    gettimeofday(&gen_start,NULL);

    auto proof = generate_mint_proof<default_r1cs_ppzksnark_pp>(keypair.pk, 
                                                            note_old,
                                                            note,
                                                            cmtA_old,
                                                            cmtA,
                                                            value_s
                                                            );

    gettimeofday(&gen_end, NULL);
    mintTimeUse = gen_end.tv_sec - gen_start.tv_sec + (gen_end.tv_usec - gen_start.tv_usec)/1000000.0;
    printf("\n\nGen Mint Proof Use Time:%fs\n\n", mintTimeUse);

    // verify proof
    if (!proof) {
        printf("generate mint proof fail!!!\n");
        return false;
    } else {
        //PrintProof(*proof);

        //assert(verify_mint_proof(keypair.vk, *proof));
        // wrong test data
        uint256 wrong_sn_old = uint256S("666");//random_uint256();
        uint64_t wrong_value_s = uint64_t(100);
        uint256 wrong_cmtA_old = note.cm();
        uint256 wrong_cmtA = note_old.cm();        

        struct timeval ver_start, ver_end;
        double mintVerTimeUse;
        gettimeofday(&ver_start, NULL);

        bool result = verify_mint_proof(keypair.vk, 
                                   *proof, 
                                   cmtA_old,
                                   sn_old,
                                   cmtA,
                                   value_s
                                   );

        gettimeofday(&ver_end, NULL);
        mintVerTimeUse = ver_end.tv_sec - ver_start.tv_sec + (ver_end.tv_usec - ver_start.tv_usec)/1000000.0;
        printf("\n\nVer Mint Proof Use Time:%fs\n\n", mintVerTimeUse);
        //printf("verify result = %d\n", result);
         
        if (!result){
            cout << "Verifying mint proof unsuccessfully!!!" << endl;
        } else {
            cout << "Verifying mint proof successfully!!!" << endl;
        }
        
        return result;
    }
}

template<typename ppzksnark_ppT>
r1cs_ppzksnark_keypair<ppzksnark_ppT> Setup() {
    default_r1cs_ppzksnark_pp::init_public_params();
    
    typedef libff::Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;

    mint_gadget<FieldT> mint(pb);
    mint.generate_r1cs_constraints();// 生成约束

    // check conatraints
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    
    // key pair generation
    r1cs_ppzksnark_keypair<ppzksnark_ppT> keypair = r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);

    return keypair;
}

int main () {
    struct timeval t1, t2;
    double timeuse;
    gettimeofday(&t1,NULL);

    //default_r1cs_ppzksnark_pp::init_public_params();
    r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = Setup<default_r1cs_ppzksnark_pp>();

    gettimeofday(&t2,NULL);
    timeuse = t2.tv_sec - t1.tv_sec + (t2.tv_usec - t1.tv_usec)/1000000.0;
    printf("\n\nMint Use Time:%fs\n\n",timeuse);
    //test_r1cs_gg_ppzksnark<dsefault_r1cs_gg_ppzksnark_pp>(1000, 100);
   
    //r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = Setup<default_r1cs_ppzksnark_pp>();

    libff::print_header("#             testing mint gadget");

    uint64_t value = uint64_t(13); 
    uint64_t value_old = uint64_t(6); 
    uint64_t value_s = uint64_t(7);

    test_mint_gadget_with_instance<default_r1cs_ppzksnark_pp>(value, value_old, value_s, keypair);

    // Note. cmake can not compile the assert()  --Agzs
    
    return 0;
}

