#include <stdlib.h>
#include <iostream>
#include <boost/optional.hpp>
#include <boost/foreach.hpp>
#include <boost/format.hpp>

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
    //std::vector<bool> tuple_data_bv(256*3); // unknown --Agzs
    std::vector<bool> v_data_bv(64);
    std::vector<bool> sn_data_bv(256);
    std::vector<bool> r_data_bv(256);
    std::vector<bool> test_hash_bv(256); 

    {
        hash_bv = int_list_to_bits({190, 52, 115, 56, 213, 177, 167, 45, 56, 54, 234, 220, 215, 251, 27, 80, 21, 187, 215, 179, 191, 244, 97, 164, 206, 7, 154, 32, 206, 177, 86, 90}, 8);
        v_data_bv = int_list_to_bits({3, 0, 0, 0, 0, 0, 0, 0}, 8);
        sn_data_bv = int_list_to_bits({1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 8);
        r_data_bv = int_list_to_bits({1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 8);
    }

    {
        printf(" value = [ ");
        BOOST_FOREACH(bool vs, v_data_bv) {
            printf("%d, ", vs);
        }

        printf("]\n sn = [ ");
        BOOST_FOREACH(bool vs, sn_data_bv) {
            printf("%d, ", vs);
        }

        printf("]\n r = [ ");
        BOOST_FOREACH(bool vs, r_data_bv) {
            printf("%d, ", vs);
        }
        printf("]\n");

        printf("]\n cmtA = [ ");
        BOOST_FOREACH(bool vs, hash_bv) {
            printf("%d, ", vs);
        }
        printf("]\n");
    }

    // 生成proof
    cout << "Trying to generate proof..." << endl;
    auto proof = generate_proof<default_r1cs_ppzksnark_pp>(keypair.pk, hash_bv, v_data_bv, sn_data_bv, r_data_bv);
    cout << "Proof generated!" << endl;
    cout << "\n======== Proof content =====" << endl;
    cout << proof << endl;
    cout << "============================\n" << endl;

    // 验证proof
    if (!proof) {
        return false;
    } else {
        test_hash_bv = int_list_to_bits({190, 52, 115, 56, 213, 177, 167, 45, 56, 54, 234, 220, 215, 251, 27, 80, 21, 187, 215, 179, 191, 244, 97, 164, 206, 7, 154, 32, 206, 177, 86, 90}, 8);

        // verification should not fail if the proof is generated!
        bool result = verify_proof(keypair.vk, *proof, test_hash_bv);
        printf("verify result = %d\n", result);
        // assert(!verify_proof(keypair.vk, *proof, test_hash_bv));
        // verify_proof(keypair.vk, *proof, hash_bv);
        if (!result){
            cout << "Verifying proof unsuccessfully!!!" << endl;
        } else {
            cout << "Verifying proof successfully!!!" << endl;
        }
        
        return result;
    }
}