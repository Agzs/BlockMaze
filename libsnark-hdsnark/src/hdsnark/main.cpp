#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <sys/time.h>
#include "snark.hpp"


#include <boost/optional/optional_io.hpp> // for cout proof --Agzs
#include <libff/common/utils.hpp>

using namespace libff;
using namespace libsnark;
using namespace std;


const bool ProofTest = false;

bool run_test(r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp>& keypair) 
{
    // Initialize bit_vectors for all of the variables involved.

    /* tuple data */
    // const size_t coeff_num = 6; // defined in gadget.hpp

    std::vector<bool> h_data_bv(256); // h_data_bv = sha256(tuple_data), known
    std::vector<bool> tuple_data_bv(256);
    std::vector<bool> data_coeff_bv(coeff_num*8); // coeff_num input
    std::vector<bool> premium_bv(16);

    std::vector<unsigned long> tt_vector={111, 24, 20, 107, 245, 107, 158, 62, 87, 244, 16, 72, 107, 5, 77, 124, 45, 166, 80, 114, 139, 173, 102, 33, 136, 61, 210, 75, 110, 138, 41, 255};


    h_data_bv = int_list_to_bits(tt_vector, 8);
    //h_data_bv = int_list_to_bits({111, 24, 20, 107, 245, 107, 158, 62, 87, 244, 16, 72, 107, 5, 77, 124, 45, 166, 80, 114, 139, 173, 102, 33, 136, 61, 210, 75, 110, 138, 41, 255}, 8);
    tuple_data_bv = int_list_to_bits({80, 75, 115, 178, 85, 17, 148, 178, 17, 126, 
    39, 9, 34, 14, 66, 
    65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18}, 8);
    if ( coeff_num == 5) {
        data_coeff_bv = int_list_to_bits({8, 5, 10, 2, 2}, 8);
        premium_bv = int_list_to_bits({10,131}, 8);
    }
    if ( coeff_num == 10) {
        data_coeff_bv = int_list_to_bits({8, 5, 10, 2, 2, 1, 1, 1, 1, 1}, 8);
        premium_bv = int_list_to_bits({12,105}, 8);
    }
    if ( coeff_num == 15) {
        data_coeff_bv = int_list_to_bits({8, 5, 10, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 8);
        premium_bv = int_list_to_bits({13,11}, 8);
    }
    if ( coeff_num == 20) {
        data_coeff_bv = int_list_to_bits({8, 5, 10, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 8);
        premium_bv = int_list_to_bits({14,236}, 8);
    }
    // else is reset all zero

    
    cout << "Input number is: " << coeff_num <<endl;

    // 生成proof
    cout << "Trying to generate proof..." << endl;
    auto proof = generate_proof<default_r1cs_ppzksnark_pp>(keypair.pk, 
                                                            h_data_bv, 
                                                            tuple_data_bv,
                                                            data_coeff_bv,
                                                            premium_bv
                                                            );

    std::vector<bool> test_premium_bv(16);
    test_premium_bv = int_list_to_bits({10,148}, 8);

    std::vector<bool> test_h_data_bv(256);
    test_h_data_bv = int_list_to_bits({111, 24, 20, 107, 245, 107, 158, 62, 87, 244, 16, 72, 107, 5, 77, 124, 45, 166, 80, 114, 139, 173, 102, 33, 136, 61, 210, 75, 110, 138, 41, 255}, 8);

    std::vector<bool> test_data_coeff_data_bv(48);
    test_data_coeff_data_bv = int_list_to_bits({8, 5, 10, 2, 2, 1}, 8);

    // 验证proof
    if (!proof) { 
        return false;
    } else {
        // verification should not fail if the proof is generated!
        // assert(verify_proof(keypair.vk, *proof, h1_bv, h2_bv, x_bv));
        // const r1cs_primary_input<FieldT> input();
        // std::cout << "NULL input: " << input<<endl;
        PrintProof(*proof);
        libff::print_time("premium_computation_gadget tests successful");
        
        if (ProofTest){
            return verify_proof(keypair.vk, *proof, test_h_data_bv, test_data_coeff_data_bv, test_premium_bv); 
        }  
        return verify_proof(keypair.vk, *proof, h_data_bv, data_coeff_bv, premium_bv); 
    }
}

int main()
{
    struct timeval t_start,t_end;
    // long cost_time_2;
    // Initialize the curve parameters.
    gettimeofday(&t_start, NULL);
    printf("Start time: %ld s %ld us", t_start.tv_sec,t_start.tv_usec);
    default_r1cs_ppzksnark_pp::init_public_params();
    // Generate the verifying/proving keys. (This is trusted setup!)
    auto keypair = generate_keypair<default_r1cs_ppzksnark_pp>();
    gettimeofday(&t_end, NULL);
    printf("end time: %ld s %ld us", t_end.tv_sec,t_end.tv_usec);
    long cost_time_1=t_end.tv_sec - t_start.tv_sec;
    long cost_time_2 = t_end.tv_usec - t_start.tv_usec;
    cout<<"genkeypair_time"<<endl<<endl;
    printf("%ld s %ld us",cost_time_1,cost_time_2);
    // Run test vectors.
    run_test(keypair);   // 正确的例子，生成和验证proof时 tuple_data 与h_tuple_data间的对应关系

}