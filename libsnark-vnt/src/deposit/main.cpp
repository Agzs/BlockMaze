#include <stdio.h>
#include <iostream>

#include <boost/optional.hpp>
#include <boost/foreach.hpp>
#include <boost/format.hpp>
#include <boost/array.hpp>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp"

#include "Note.h"
#include "IncrementalMerkleTree.hpp"

using namespace libsnark;
using namespace libff;
using namespace std;
using namespace libvnt;

#include "circuit/gadget.tcc"

#define DEBUG 0

// 生成proof
template<typename ppzksnark_ppT>
boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> generate_deposit_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                    const NoteS& note_s,
                                                                    const Note& note_old,
                                                                    const Note& note,
                                                                    uint256 cmtS,
                                                                    uint256 cmtB_old,
                                                                    uint256 cmtB,
                                                                    const uint256& rt,
                                                                     const MerklePath& path
                                                                   )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;  // 定义原始模型，该模型包含constraint_system成员变量
    deposit_gadget<FieldT> deposit(pb); // 构造新模型
    deposit.generate_r1cs_constraints(); // 生成约束

    deposit.generate_r1cs_witness(note_s, note_old, note, cmtS, cmtB_old, cmtB, rt, path); // 为新模型的参数生成证明

    cout << "pb.is_satisfied() is " << pb.is_satisfied() << endl;

    if (!pb.is_satisfied()) { // 三元组R1CS是否满足  < A , X > * < B , X > = < C , X >
        return boost::none;
    }

    // 调用libsnark库中生成proof的函数
    return r1cs_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

// 验证proof
template<typename ppzksnark_ppT>
bool verify_deposit_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                    r1cs_ppzksnark_proof<ppzksnark_ppT> proof,
                    const uint256& rt,
                    const uint160& pk_recv,
                    const uint256& cmtB_old,
                    const uint256& sn_old,
                    const uint256& cmtB                  )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    const r1cs_primary_input<FieldT> input = deposit_gadget<FieldT>::witness_map(
        rt,
        pk_recv,
        cmtB_old,
        sn_old,
        cmtB
    ); 

    // 调用libsnark库中验证proof的函数
    return r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}

template<typename ppzksnark_ppT>
void PrintProof(r1cs_ppzksnark_proof<ppzksnark_ppT> proof)
{
    printf("================== Print proof ==================================\n");
    //printf("proof is %x\n", *proof);
    std::cout << "deposit proof:\n";

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
bool test_deposit_gadget_with_instance(
                            uint64_t value,
                            uint64_t value_old,
                            //uint256 sn_old,
                            //uint256 r_old,
                            //uint256 sn,
                            //uint256 r,
                            //uint256 cmtB_old,
                            //uint256 cmtB,
                            uint64_t value_s
                        )
{
    // Note note_old = Note(value_old, sn_old, r_old);
    // Note note = Note(value, sn, r);

    // uint256 sn_test = random_uint256();
    // uint256 r_test = random_uint256();
   
    uint256 sn_old = uint256S("123456");//random_uint256();
    uint256 r_old = uint256S("123456");//random_uint256();
    Note note_old = Note(value_old, sn_old, r_old);
    uint256 cmtB_old = note_old.cm();

    uint160 pk_recv = uint160S("123");
    uint256 sn_s = uint256S("123");//random_uint256();
    uint256 r_s = uint256S("123");//random_uint256();
    uint256 sn_A_old = uint256S("123");
    NoteS note_s = NoteS(value_s, pk_recv, sn_s, r_s, sn_A_old);
    uint256 cmtS = note_s.cm();

    uint256 sn = uint256S("12");//random_uint256();
    uint256 r = uint256S("12");//random_uint256();
    Note note = Note(value, sn, r);
    uint256 cmtB = note.cm();

    boost::array<uint256, 16> commitments; //16个cmts
    //std::vector<boost::optional<uint256>>& commitments;
    
    const char *str[] = {"1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                    "11", "12", "13", "14", "15", "16"};
    commitments[9] = cmtS;
    cout << "cmtS = 0x" << cmtS.ToString() << endl;
    for (size_t i = 0; i < 16; i++) {
        if(i == 9) {
            //cout << "commitments[" << i << "] = 0x" << commitments[i].ToString() << endl;
            continue;
        }
        //const char *ch = str[i];
        commitments[i] = uint256S(str[i]);
        //cout << "commitments[" << i << "] = 0x" << commitments[i].ToString() << endl;
    }

    ZCIncrementalMerkleTree tree;
    assert(tree.root() == ZCIncrementalMerkleTree::empty_root());
    
    ZCIncrementalWitness wit = tree.witness(); //初始化witness
    bool find_cmtS = false;
    for (size_t i = 0; i < 16; i++) {
        if (find_cmtS) {
            wit.append(commitments[i]);
        } else {
            /********************************************
             * 如果删除else分支，
             * 将tree.append(commitments[i])放到for循环体中，
             * 最终得到的rt == wit.root() == tree.root()
             *********************************************/
            tree.append(commitments[i]);
        }

        if (commitments[i] == cmtS) {
            //在要证明的叶子节点添加到tree后，才算真正初始化wit，下面的root和path才会正确。
            wit = tree.witness(); 
            find_cmtS = true;
        } 
    }

    auto path = wit.path();
    uint256 rt = wit.root();

    cout << "tree.root = 0x" << tree.root().ToString() << endl;
    cout << "wit.root = 0x" << wit.root().ToString() << endl;

    // 错误测试数据
    ZCIncrementalMerkleTree wrong_tree;
    assert(wrong_tree.root() == ZCIncrementalMerkleTree::empty_root());
    wrong_tree.append(uint256S("17"));
    ZCIncrementalWitness wrong_wit = wrong_tree.witness(); //初始化witness
    wrong_wit.append(uint256S("18"));
    wrong_wit.append(uint256S("19"));
    wrong_wit.append(uint256S("20"));
    
    uint256 wrong_rt = wrong_wit.root();
    auto wrong_path = wrong_wit.path();
    uint256 wrong_cmtS = note_old.cm();
    uint256 wrong_cmtB_old = note.cm();
    uint256 wrong_cmtB = note_old.cm();
    uint160 wrong_pk_recv = uint160S("333");
    uint256 wrong_sn_old = uint256S("666");

    cout << "wit.wrong_root = 0x" << wrong_rt.ToString() << endl;
   
    typedef libff::Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;

    deposit_gadget<FieldT> deposit(pb);
    deposit.generate_r1cs_constraints();// 生成约束

    // check conatraints
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    
    // key pair generation
    r1cs_ppzksnark_keypair<ppzksnark_ppT> keypair = r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);

    // 生成proof
    cout << "Trying to generate proof..." << endl;

    auto proof = generate_deposit_proof<default_r1cs_ppzksnark_pp>(keypair.pk, 
                                                            note_s,
                                                            note_old,
                                                            note,
                                                            cmtS,
                                                            cmtB_old,
                                                            cmtB,
                                                            rt, //wrong_rt
                                                            path //wrong_path
                                                            );

    // verify proof
    if (!proof) {
        printf("generate deposit proof fail!!!\n");
        return false;
    } else {
        PrintProof(*proof);

        //assert(verify_deposit_proof(keypair.vk, *proof));
        
        bool result = verify_deposit_proof(keypair.vk, 
                                    *proof, 
                                    rt, //wrong_rt
                                    pk_recv,
                                    cmtB_old,
                                    sn_old,
                                    cmtB
                                   );

        //printf("verify result = %d\n", result);
         
        if (!result){
            cout << "Verifying deposit proof unsuccessfully!!!" << endl;
        } else {
            cout << "Verifying deposit proof successfully!!!" << endl;
        }
        
        return result;
    }
}

int main () {
    default_r1cs_ppzksnark_pp::init_public_params();

    libff::print_header("#             testing deposit gadget");

    uint64_t value = uint64_t(264); 
    uint64_t value_old = uint64_t(255); 
    uint64_t value_s = uint64_t(9);

    test_deposit_gadget_with_instance<default_r1cs_ppzksnark_pp>(value, value_old, value_s);

    // Note. cmake can not compile the assert()  --Agzs
    
    return 0;
}

