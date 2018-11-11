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
    std::vector<bool> hash_test_bv(256); 

    {
        hash_bv = int_list_to_bits({190, 120, 255, 212, 127, 96, 31, 93, 67, 149, 152, 141, 198, 30, 121, 200, 160, 77, 216, 203, 85, 2, 143, 105, 60, 10, 119, 96, 113, 148, 58, 240}, 8);
        tuple_data_bv = int_list_to_bits({80, 75, 115, 178, 85, 17, 148, 178, 17, 126, 39, 9, 34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18, 80, 75, 115, 178, 85, 17, 148, 178, 17, 126, 39, 9, 34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18, 80, 75, 115, 178, 85, 17, 148, 178, 17, 126, 39, 9, 34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18, 80, 75, 115, 178, 85, 17, 148, 178, 17, 126, 39, 9, 34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18, 80, 75, 115, 178, 85, 17, 148, 178, 17, 126, 39, 9, 34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18}, 8);
        
        hash_test_bv = int_list_to_bits({191, 120, 255, 212, 127, 96, 31, 93, 67, 149, 152, 141, 198, 30, 121, 200, 160, 77, 216, 203, 85, 2, 143, 105, 60, 10, 119, 96, 113, 148, 58, 240}, 8);
    }

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
        
        assert(!verify_proof(keypair.vk, *proof, hash_test_bv)); // should return false

        cout << "Verifying proof successfully!!!" << endl;
        
        return true;
    }
}