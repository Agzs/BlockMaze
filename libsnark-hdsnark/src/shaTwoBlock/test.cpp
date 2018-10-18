#include <stdlib.h>
#include <iostream>

#include "snark.hpp"

#include <boost/optional/optional_io.hpp> // for cout<<proof --Agzs
#include <libff/common/utils.hpp>

using namespace libff;
using namespace libsnark;
using namespace std;

int main()
{
    // Initialize the curve parameters.
    default_r1cs_ppzksnark_pp::init_public_params();
    // Generate the verifying/proving keys. (This is trusted setup!)
    auto keypair = generate_keypair<default_r1cs_ppzksnark_pp>();
    // Run test vectors.

    // Initialize bit_vectors for all of the variables involved.
    std::vector<bool> hash_bv(256); 
    std::vector<bool> tuple_data_bv(256*3); // unknown --Agzs

    {
        hash_bv = int_list_to_bits({117, 168, 218, 154, 81, 177, 31, 236, 177, 112, 34, 236, 238, 84, 38, 152, 27, 161, 236, 35, 127,156, 212, 161, 69, 210, 107, 160, 230, 81, 189, 250}, 8);
        tuple_data_bv = int_list_to_bits({80, 75, 115, 178, 85, 17, 148, 178, 17, 126, 39, 9, 34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18, 80, 75, 115, 178, 85, 17, 148, 178, 17, 126, 39, 9, 34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18, 80, 75, 115, 178, 85, 17, 148, 178, 17, 126, 39, 9, 34, 14, 66,65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18}, 8);    }

    // 生成proof
    cout << "Trying to generate proof..." << endl;
    auto proof = generate_proof<default_r1cs_ppzksnark_pp>(keypair.pk, hash_bv, tuple_data_bv);
    cout << "Proof generated!" << endl;
    cout << "\n======== Proof content =====" << endl;
    cout << proof << endl;
    cout << "============================\n" << endl;

    // 验证proof
    if (!proof) {
        return false;
    } else {
        // verification should not fail if the proof is generated!
        assert(verify_proof(keypair.vk, *proof, hash_bv));
        return true;
    }
}