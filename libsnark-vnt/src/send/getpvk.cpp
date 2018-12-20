#include <stdio.h>
#include <iostream>

#include <boost/optional.hpp>
#include <boost/foreach.hpp>
#include <boost/format.hpp>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp"

#include "Note.h"
#include "uint256.h"
using namespace libsnark;
using namespace libff;
using namespace std;
#include "circuit/gadget.tcc"

template<typename T>
void writeToFile(std::string path, T& obj) {
    std::stringstream ss;
    ss << obj;
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

void serializeProvingKeyToFile(r1cs_ppzksnark_proving_key<alt_bn128_pp> pk, const char* pk_path){
  writeToFile(pk_path, pk);
}

void vkToFile(r1cs_ppzksnark_verification_key<alt_bn128_pp> vk, const char* vk_path){
  writeToFile(vk_path, vk);
}


int main(){
    alt_bn128_pp::init_public_params();
    typedef libff::Fr<alt_bn128_pp> FieldT;
    protoboard<FieldT> pb;
    send_gadget<FieldT> send(pb);
    send.generate_r1cs_constraints();// 生成约束
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    r1cs_ppzksnark_keypair<alt_bn128_pp> keypair = r1cs_ppzksnark_generator<alt_bn128_pp>(constraint_system);
    serializeProvingKeyToFile(keypair.pk,"sendpk.txt");
    vkToFile(keypair.vk,"sendvk.txt");
}