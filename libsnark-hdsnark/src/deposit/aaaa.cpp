#include <stdio.h>
#include <iostream>

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

int main(){
    uint64_t value = uint64_t(80); 
    uint64_t value_old = uint64_t(0); 
    uint64_t value_s = uint64_t(80);
    char* sn_old_string="0x0000000000000000000000000000000000000000000000000000000000000000";
    char* r_old_string="0x0000000000000000000000000000000000000000000000000000000000000000";
    char* sn_string="0xb9d6e8651462db2d4a8141a18ef5c721044017671bfdc423710ed265fffd2802";
    char* r_string="0x6dbbe8b866c694efa460c561832f785ed360131890b945db75e314235b2b5255";
    char* sns_string="0xd620b194a10116cf1b45651823e5c5d039e7be5062ae5be96de7e16e0107a11d";
    char* rs_string="0x1f3fc954f39b58c2f945b108036f45bed354e57c906ef0804ea9deaf7bd245bf";
    char* pk_string="0xa3a39202e6c0c120ee9e76c48e3e8fe54217f04b";
    char* sn_A_oldstring="0x633a33dab1d49d5aef5300d6f0875af952352f5fe76923661fb97cf23f777090";

    char* cmtbold=genCMT(value_old,sn_old_string,r_old_string);
    char* cmtb=genCMT(value,sn_string,r_string);
    char* cmts=genCMTS(value_s, pk_string, sns_string, rs_string, sn_A_oldstring);

    printf("cmtbold=%s\n",cmtbold);
    printf("cmtb=%s\n",cmtb);
    printf("cmts=%s\n",cmts);

    char* cmtstosting="0xdfa1a819fb07a69adb62871f77637cd69f1e8f41f5d91117c7fdf3c85a68b210";
    char* cmtarray="0xdfa1a819fb07a69adb62871f77637cd69f1e8f41f5d91117c7fdf3c85a68b210";
    char* rt="36c093dbae3c5c309cb69818ff6f4cc3328e50d932cb414a7f7e783efa8201ea";
    char* proof= genDepositproof(value,
                                value_old,
                                sn_old_string,
                                r_old_string,
                                sn_string,
                                r_string,
                                sns_string,
                                rs_string,
                                cmtbold,
                                cmtb,
                                value_s,
                                pk_string,
                                sn_A_oldstring,
                                cmtstosting,
                                cmtarray,
                                1,
                                rt
                        );
    
    verifyDepositproof(proof, rt,pk_string, cmtbold,sn_old_string,cmtb);
}