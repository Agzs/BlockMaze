#include <stdio.h>
#include <iostream>

#include<sys/time.h>

#include <boost/optional.hpp>
#include <boost/foreach.hpp>
#include <boost/format.hpp>
#include <boost/array.hpp>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp"
#include "libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp"

#include "Note.h"
#include "uint256.h"
#include "depositcgo.hpp"
#include "IncrementalMerkleTree.hpp"

using namespace libsnark;
using namespace libff;
using namespace std;
using namespace libvnt;

#include "circuit/gadget.tcc"

int convertFromAscii(uint8_t ch)
{
    if (ch >= '0' && ch <= '9')
    {
        return ch - '0';
    }
    else if (ch >= 'a' && ch <= 'f')
    {
        return ch - 'a' + 10;
    }
}

libff::bigint<libff::alt_bn128_r_limbs> libsnarkBigintFromBytes(const uint8_t *_x)
{
    libff::bigint<libff::alt_bn128_r_limbs> x;

    for (unsigned i = 0; i < 4; i++)
    {
        for (unsigned j = 0; j < 8; j++)
        {
            x.data[3 - i] |= uint64_t(_x[i * 8 + j]) << (8 * (7 - j));
        }
    }
    return x;
}

template <typename T>
void writeToFile(std::string path, T &obj)
{
    std::stringstream ss;
    ss << obj;
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template <typename T>
T loadFromFile(std::string path)
{
    std::stringstream ss;
    std::ifstream fh(path, std::ios::binary);

    assert(fh.is_open());

    ss << fh.rdbuf();
    fh.close();

    ss.rdbuf()->pubseekpos(0, std::ios_base::in);

    T obj;
    ss >> obj;

    return obj;
}

void serializeProvingKeyToFile(r1cs_ppzksnark_proving_key<alt_bn128_pp> pk, const char *pk_path)
{
    writeToFile(pk_path, pk);
}

void vkToFile(r1cs_ppzksnark_verification_key<alt_bn128_pp> vk, const char *vk_path)
{
    writeToFile(vk_path, vk);
}

void proofToFile(r1cs_ppzksnark_proof<alt_bn128_pp> pro, const char *pro_path)
{
    writeToFile(pro_path, pro);
}

r1cs_ppzksnark_proving_key<alt_bn128_pp> deserializeProvingKeyFromFile(const char *pk_path)
{
    return loadFromFile<r1cs_ppzksnark_proving_key<alt_bn128_pp>>(pk_path);
}

r1cs_ppzksnark_verification_key<alt_bn128_pp> deserializevkFromFile(const char *vk_path)
{
    return loadFromFile<r1cs_ppzksnark_verification_key<alt_bn128_pp>>(vk_path);
}

r1cs_ppzksnark_proof<alt_bn128_pp> deserializeproofFromFile(const char *pro_path)
{
    return loadFromFile<r1cs_ppzksnark_proof<alt_bn128_pp>>(pro_path);
}

std::string HexStringFromLibsnarkBigint(libff::bigint<libff::alt_bn128_r_limbs> _x)
{
    uint8_t x[32];
    for (unsigned i = 0; i < 4; i++)
        for (unsigned j = 0; j < 8; j++)
            x[i * 8 + j] = uint8_t(uint64_t(_x.data[3 - i]) >> (8 * (7 - j)));

    std::stringstream ss;
    ss << std::setfill('0');
    for (unsigned i = 0; i < 32; i++)
    {
        ss << std::hex << std::setw(2) << (int)x[i];
    }

    std::string str = ss.str();
    return str.erase(0, min(str.find_first_not_of('0'), str.size() - 1));
}

std::string outputPointG1AffineAsHex(libff::alt_bn128_G1 _p)
{
    libff::alt_bn128_G1 aff = _p;
    aff.to_affine_coordinates();

    std::string s_x = HexStringFromLibsnarkBigint(aff.X.as_bigint());
    while (s_x.size() < 64)
    {
        s_x = "0" + s_x;
    }

    std::string s_y = HexStringFromLibsnarkBigint(aff.Y.as_bigint());
    while (s_y.size() < 64)
    {
        s_y = "0" + s_y;
    }
    return s_x + s_y;
}

std::string outputPointG2AffineAsHex(libff::alt_bn128_G2 _p)
{
    libff::alt_bn128_G2 aff = _p;
    aff.to_affine_coordinates();

    std::string x_1 = HexStringFromLibsnarkBigint(aff.X.c1.as_bigint());
    while (x_1.size() < 64)
    {
        x_1 = "0" + x_1;
    }
    std::string x_0 = HexStringFromLibsnarkBigint(aff.X.c0.as_bigint());
    while (x_0.size() < 64)
    {
        x_0 = "0" + x_0;
    }
    std::string y_1 = HexStringFromLibsnarkBigint(aff.Y.c1.as_bigint());
    while (y_1.size() < 64)
    {
        y_1 = "0" + y_1;
    }
    std::string y_0 = HexStringFromLibsnarkBigint(aff.Y.c0.as_bigint());
    while (y_0.size() < 64)
    {
        y_0 = "0" + y_0;
    }
    return x_1 + x_0 + y_1 + y_0;
}
std::string string_proof_as_hex(libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof)
{
    std::string A = outputPointG1AffineAsHex(proof.g_A.g);

    std::string A_P = outputPointG1AffineAsHex(proof.g_A.h);

    std::string B = outputPointG2AffineAsHex(proof.g_B.g);
    std::string B_P = outputPointG1AffineAsHex(proof.g_B.h);

    std::string C = outputPointG1AffineAsHex(proof.g_C.g);
    std::string C_P = outputPointG1AffineAsHex(proof.g_C.h);

    std::string H = outputPointG1AffineAsHex(proof.g_H);

    std::string K = outputPointG1AffineAsHex(proof.g_K);

    std::string proof_string = A + A_P + B + B_P + C + C_P + H + K;

    return proof_string;
}

template <typename ppzksnark_ppT>
r1cs_ppzksnark_proof<ppzksnark_ppT> generate_deposit_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                           const NoteS &note_s,
                                                           const Note &note_old,
                                                           const Note &note,
                                                           uint256 cmtS,
                                                           uint256 cmtB_old,
                                                           uint256 cmtB,
                                                           const uint256 &rt,
                                                           const MerklePath &path,
                                                           uint256 sn_s_data,
                                                           uint256 sk_data
                                                           )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;               // 定义原始模型，该模型包含constraint_system成员变量
    deposit_gadget<FieldT> deposit(pb);  // 构造新模型
    deposit.generate_r1cs_constraints(); // 生成约束

    deposit.generate_r1cs_witness(note_s, note_old, note, cmtS, cmtB_old, cmtB, rt, path, sn_s_data, sk_data); // 为新模型的参数生成证明

    if (!pb.is_satisfied())
    { // 三元组R1CS是否满足  < A , X > * < B , X > = < C , X >
        //throw std::invalid_argument("Constraint system not satisfied by inputs");
        cout << "can not generate deposit proof" << endl;
        return r1cs_ppzksnark_proof<ppzksnark_ppT>();
    }

    // 调用libsnark库中生成proof的函数
    return r1cs_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

// 验证proof
template <typename ppzksnark_ppT>
bool verify_deposit_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                          r1cs_ppzksnark_proof<ppzksnark_ppT> proof,
                          // const uint256& merkle_root,
                          const uint256 &rt,
                          const uint160 &pk_recv,
                          const uint256 &cmtB_old,
                          const uint256 &sn_old,
                          const uint256 &cmtB,
                          const uint256& sn_s
                          )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    const r1cs_primary_input<FieldT> input = deposit_gadget<FieldT>::witness_map(
        rt,
        pk_recv,
        cmtB_old,
        sn_old,
        cmtB,
        sn_s
    );

    // 调用libsnark库中验证proof的函数
    return r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}

//func GenCMT(value uint64, sn []byte, r []byte)
char *genCMT(uint64_t value, char *sn_string, char *r_string)
{
    uint256 sn = uint256S(sn_string);
    uint256 r = uint256S(r_string);
    Note note = Note(value, sn, r);
    uint256 cmtA = note.cm();
    std::string cmtA_c = cmtA.ToString();

    char *p = new char[67]; //必须使用new开辟空间 不然cgo调用该函数结束全为0
    cmtA_c.copy(p, 66, 0);
    *(p + 66) = '\0'; //手动加结束符

    return p;
}

char *genCMTS(uint64_t value_s, char *pk_string, char *r_s_string, char *sn_old_string)
{
    uint160 pk = uint160S(pk_string);
    uint256 r_s = uint256S(r_s_string);
    uint256 sn = uint256S(sn_old_string);
    NoteS notes = NoteS(value_s, pk, r_s, sn);
    uint256 cmtS = notes.cm();

    std::string cmtS_c = cmtS.ToString();

    char *p = new char[67]; //必须使用new开辟空间 不然cgo调用该函数结束全为0
    cmtS_c.copy(p, 66, 0);
    *(p + 66) = '\0'; //手动加结束符

    return p;
}

char* computePRF(char* sk_string, char* r_string)
{
    uint256 sk = uint256S(sk_string);
    uint256 r = uint256S(r_string);
    uint256 sn = Compute_PRF(sk, r);
    std::string sn_c = sn.ToString();

    char *p = new char[65]; //必须使用new开辟空间 不然cgo调用该函数结束全为0
    sn_c.copy(p, 64, 0);
    *(p + 64) = '\0'; //手动加结束符

    return p;
}

char *genRoot(char *cmtarray, int n)
{
    boost::array<uint256, 256> commitments; //256个cmts

    string s = cmtarray;

    ZCIncrementalMerkleTree tree;
    assert(tree.root() == ZCIncrementalMerkleTree::empty_root());

    for (int i = 0; i < n; i++)
    {
        commitments[i] = uint256S(s.substr(i * 66, 66)); //分割cmtarray  0x+64个十六进制数 一共64位
        tree.append(commitments[i]);
    }

    uint256 rt = tree.root();
    std::string rt_c = rt.ToString();

    char *p = new char[65]; //必须使用new开辟空间 不然cgo调用该函数结束全为0   65
    rt_c.copy(p, 64, 0);
    *(p + 64) = '\0'; //手动加结束符

    return p;
}

char *genDepositproof(uint64_t value,
                      uint64_t value_old,
                      char *sn_old_string,
                      char *r_old_string,
                      char *sn_string,
                      char *r_string,
                      char *sns_string,
                      char *rs_string,
                      char *cmtB_old_string,
                      char *cmtB_string,
                      uint64_t value_s,
                      char *pk_string,
                      char *sn_A_oldstring,
                      char *cmtS_string,
                      char *cmtarray,
                      int n,
                      char *RT,
                      char *sk_string)
{
    uint256 sn_old = uint256S(sn_old_string);
    uint256 r_old = uint256S(r_old_string);
    uint256 sn = uint256S(sn_string);
    uint256 r = uint256S(r_string);
    uint256 sn_s = uint256S(sns_string);
    uint256 r_s = uint256S(rs_string);
    uint256 cmtB_old = uint256S(cmtB_old_string);
    uint256 cmtB = uint256S(cmtB_string);
    uint160 pk_recv = uint160S(pk_string);
    uint256 sn_A_old = uint256S(sn_A_oldstring);
    uint256 cmtS = uint256S(cmtS_string);
    uint256 sk = uint256S(sk_string);

    Note note_old = Note(value_old, sn_old, r_old);

    NoteS note_s = NoteS(value_s, pk_recv, r_s, sn_A_old);

    Note note = Note(value, sn, r);

    boost::array<uint256, 256> commitments; //256个cmts
    string sss = cmtarray;

    for (int i = 0; i < n; i++)
    {
        commitments[i] = uint256S(sss.substr(i * 66, 66)); //分割cmtarray  0x+64个十六进制数 一共66位
    }

    ZCIncrementalMerkleTree tree;
    assert(tree.root() == ZCIncrementalMerkleTree::empty_root());

    ZCIncrementalWitness wit = tree.witness(); //初始化witness
    bool find_cmtS = false;
    for (size_t i = 0; i < n; i++)
    {
        if (find_cmtS)
        {
            wit.append(commitments[i]);
        }
        else
        {
            /********************************************
             * 如果删除else分支，
             * 将tree.append(commitments[i])放到for循环体中，
             * 最终得到的rt == wit.root() == tree.root()
             *********************************************/
            tree.append(commitments[i]);
        }

        if (commitments[i] == cmtS)
        {
            //在要证明的叶子节点添加到tree后，才算真正初始化wit，下面的root和path才会正确。
            wit = tree.witness();
            find_cmtS = true;
        }
    }

    auto path = wit.path();
    uint256 rt = wit.root();

    //初始化参数
    alt_bn128_pp::init_public_params();

    struct timeval t1, t2;
    double timeuse;
    gettimeofday(&t1,NULL);

    r1cs_ppzksnark_keypair<alt_bn128_pp> keypair;
    //cout << "Trying to read deposit proving key file..." << endl;
    //cout << "Please be patient as this may take about 64 seconds. " << endl;
    keypair.pk = deserializeProvingKeyFromFile("/usr/local/prfKey/depositpk.txt");

    gettimeofday(&t2,NULL);
    timeuse = t2.tv_sec - t1.tv_sec + (t2.tv_usec - t1.tv_usec)/1000000.0;
    // printf("\n\n reading deposit pk Use Time:%fs\n\n",timeuse);

    // 生成proof
    cout << "Trying to generate deposit proof..." << endl;

    libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof = generate_deposit_proof<alt_bn128_pp>(keypair.pk,
                                                                                                     note_s,
                                                                                                     note_old,
                                                                                                     note,
                                                                                                     cmtS,
                                                                                                     cmtB_old,
                                                                                                     cmtB,
                                                                                                     rt,
                                                                                                     path,
                                                                                                     sn_s,
                                                                                                     sk);

    //proof转字符串
    std::string proof_string = string_proof_as_hex(proof);

    char *p = new char[1153];
    proof_string.copy(p, 1152, 0);
    *(p + 1152) = '\0';

    return p;
}

bool verifyDepositproof(char *data, char *RT, char *pk, char *cmtb_old, char *snold, char *cmtb, char *sns)
{
    uint256 rt = uint256S(RT);
    uint160 pk_recv = uint160S(pk);
    uint256 cmtB_old = uint256S(cmtb_old);
    uint256 sn_old = uint256S(snold);
    uint256 cmtB = uint256S(cmtb);
    uint256 sn_s = uint256S(sns);

    alt_bn128_pp::init_public_params();

    struct timeval t1, t2;
    double timeuse;
    gettimeofday(&t1,NULL);

    r1cs_ppzksnark_keypair<alt_bn128_pp> keypair;
    keypair.vk = deserializevkFromFile("/usr/local/prfKey/depositvk.txt");

    gettimeofday(&t2,NULL);
    timeuse = t2.tv_sec - t1.tv_sec + (t2.tv_usec - t1.tv_usec)/1000000.0;
    // printf("\n\n reading deposit vk Use Time:%fs\n\n",timeuse);

    libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof;

    uint8_t A_g_x[64];
    uint8_t A_g_y[64];
    uint8_t A_h_x[64];
    uint8_t A_h_y[64];
    uint8_t B_g_x_1[64];
    uint8_t B_g_x_0[64];
    uint8_t B_g_y_1[64];
    uint8_t B_g_y_0[64];
    uint8_t B_h_x[64];
    uint8_t B_h_y[64];
    uint8_t C_g_x[64];
    uint8_t C_g_y[64];
    uint8_t C_h_x[64];
    uint8_t C_h_y[64];
    uint8_t H_x[64];
    uint8_t H_y[64];
    uint8_t K_x[64];
    uint8_t K_y[64];

    for (int i = 0; i < 64; i++)
    {
        A_g_x[i] = uint8_t(data[i + 0]);
        A_g_y[i] = uint8_t(data[i + 64]);
        A_h_x[i] = uint8_t(data[i + 128]);
        A_h_y[i] = uint8_t(data[i + 192]);
        B_g_x_1[i] = uint8_t(data[i + 256]);
        B_g_x_0[i] = uint8_t(data[i + 320]);
        B_g_y_1[i] = uint8_t(data[i + 384]);
        B_g_y_0[i] = uint8_t(data[i + 448]);
        B_h_x[i] = uint8_t(data[i + 512]);
        B_h_y[i] = uint8_t(data[i + 576]);
        C_g_x[i] = uint8_t(data[i + 640]);
        C_g_y[i] = uint8_t(data[i + 704]);
        C_h_x[i] = uint8_t(data[i + 768]);
        C_h_y[i] = uint8_t(data[i + 832]);
        H_x[i] = uint8_t(data[i + 896]);
        H_y[i] = uint8_t(data[i + 960]);
        K_x[i] = uint8_t(data[i + 1024]);
        K_y[i] = uint8_t(data[i + 1088]);
    }

    for (int i = 0, j = 0; i < 64; i += 2, j++)
    {
        A_g_x[j] = uint8_t(convertFromAscii(A_g_x[i]) * 16 + convertFromAscii(A_g_x[i + 1]));
        A_g_y[j] = uint8_t(convertFromAscii(A_g_y[i]) * 16 + convertFromAscii(A_g_y[i + 1]));
        A_h_x[j] = uint8_t(convertFromAscii(A_h_x[i]) * 16 + convertFromAscii(A_h_x[i + 1]));
        A_h_y[j] = uint8_t(convertFromAscii(A_h_y[i]) * 16 + convertFromAscii(A_h_y[i + 1]));
        B_g_x_1[j] = uint8_t(convertFromAscii(B_g_x_1[i]) * 16 + convertFromAscii(B_g_x_1[i + 1]));
        B_g_x_0[j] = uint8_t(convertFromAscii(B_g_x_0[i]) * 16 + convertFromAscii(B_g_x_0[i + 1]));
        B_g_y_1[j] = uint8_t(convertFromAscii(B_g_y_1[i]) * 16 + convertFromAscii(B_g_y_1[i + 1]));
        B_g_y_0[j] = uint8_t(convertFromAscii(B_g_y_0[i]) * 16 + convertFromAscii(B_g_y_0[i + 1]));
        B_h_x[j] = uint8_t(convertFromAscii(B_h_x[i]) * 16 + convertFromAscii(B_h_x[i + 1]));
        B_h_y[j] = uint8_t(convertFromAscii(B_h_y[i]) * 16 + convertFromAscii(B_h_y[i + 1]));
        C_g_x[j] = uint8_t(convertFromAscii(C_g_x[i]) * 16 + convertFromAscii(C_g_x[i + 1]));
        C_g_y[j] = uint8_t(convertFromAscii(C_g_y[i]) * 16 + convertFromAscii(C_g_y[i + 1]));
        C_h_x[j] = uint8_t(convertFromAscii(C_h_x[i]) * 16 + convertFromAscii(C_h_x[i + 1]));
        C_h_y[j] = uint8_t(convertFromAscii(C_h_y[i]) * 16 + convertFromAscii(C_h_y[i + 1]));
        H_x[j] = uint8_t(convertFromAscii(H_x[i]) * 16 + convertFromAscii(H_x[i + 1]));
        H_y[j] = uint8_t(convertFromAscii(H_y[i]) * 16 + convertFromAscii(H_y[i + 1]));
        K_x[j] = uint8_t(convertFromAscii(K_x[i]) * 16 + convertFromAscii(K_x[i + 1]));
        K_y[j] = uint8_t(convertFromAscii(K_y[i]) * 16 + convertFromAscii(K_y[i + 1]));
    }

    libff::bigint<libff::alt_bn128_r_limbs> a_g_x = libsnarkBigintFromBytes(A_g_x);
    libff::bigint<libff::alt_bn128_r_limbs> a_g_y = libsnarkBigintFromBytes(A_g_y);
    libff::bigint<libff::alt_bn128_r_limbs> a_h_x = libsnarkBigintFromBytes(A_h_x);
    libff::bigint<libff::alt_bn128_r_limbs> a_h_y = libsnarkBigintFromBytes(A_h_y);
    libff::bigint<libff::alt_bn128_r_limbs> b_g_x_1 = libsnarkBigintFromBytes(B_g_x_1);
    libff::bigint<libff::alt_bn128_r_limbs> b_g_x_0 = libsnarkBigintFromBytes(B_g_x_0);
    libff::bigint<libff::alt_bn128_r_limbs> b_g_y_1 = libsnarkBigintFromBytes(B_g_y_1);
    libff::bigint<libff::alt_bn128_r_limbs> b_g_y_0 = libsnarkBigintFromBytes(B_g_y_0);

    libff::bigint<libff::alt_bn128_r_limbs> b_h_x = libsnarkBigintFromBytes(B_h_x);
    libff::bigint<libff::alt_bn128_r_limbs> b_h_y = libsnarkBigintFromBytes(B_h_y);
    libff::bigint<libff::alt_bn128_r_limbs> c_g_x = libsnarkBigintFromBytes(C_g_x);
    libff::bigint<libff::alt_bn128_r_limbs> c_g_y = libsnarkBigintFromBytes(C_g_y);
    libff::bigint<libff::alt_bn128_r_limbs> c_h_x = libsnarkBigintFromBytes(C_h_x);
    libff::bigint<libff::alt_bn128_r_limbs> c_h_y = libsnarkBigintFromBytes(C_h_y);
    libff::bigint<libff::alt_bn128_r_limbs> h_x = libsnarkBigintFromBytes(H_x);
    libff::bigint<libff::alt_bn128_r_limbs> h_y = libsnarkBigintFromBytes(H_y);
    libff::bigint<libff::alt_bn128_r_limbs> k_x = libsnarkBigintFromBytes(K_x);
    libff::bigint<libff::alt_bn128_r_limbs> k_y = libsnarkBigintFromBytes(K_y);

    //ecc element
    proof.g_A.g.X = a_g_x;
    proof.g_A.g.Y = a_g_y;
    proof.g_A.h.X = a_h_x;
    proof.g_A.h.Y = a_h_y;
    proof.g_B.g.X.c1 = b_g_x_1;
    proof.g_B.g.X.c0 = b_g_x_0;
    proof.g_B.g.Y.c1 = b_g_y_1;
    proof.g_B.g.Y.c0 = b_g_y_0;
    proof.g_B.h.X = b_h_x;
    proof.g_B.h.Y = b_h_y;
    proof.g_C.g.X = c_g_x;
    proof.g_C.g.Y = c_g_y;
    proof.g_C.h.X = c_h_x;
    proof.g_C.h.Y = c_h_y;
    proof.g_H.X = h_x;
    proof.g_H.Y = h_y;
    proof.g_K.X = k_x;
    proof.g_K.Y = k_y;

    bool result = verify_deposit_proof(keypair.vk,
                                       proof,
                                       rt,
                                       pk_recv,
                                       cmtB_old,
                                       sn_old,
                                       cmtB,
                                       sn_s);

    if (!result)
    {
        cout << "Verifying deposit proof unsuccessfully!!!" << endl;
    }
    else
    {
        cout << "Verifying deposit proof successfully!!!" << endl;
    }

    return result;
}
