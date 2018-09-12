#include <stdlib.h>
#include <iostream>

#include <boost/optional/optional_io.hpp> // for cout proof --Agzs
#include <libff/common/utils.hpp>

using namespace libff;

using namespace std;


int main()
{
     /* tuple data */
    std::vector<bool> tuple_data_bv(256); // h_data_bv = sha256(tuple_data), known
    tuple_data_bv = int_list_to_bits({80, 75, 115, 178, 85, 17, 148, 178, 17, 126, 39, 9, 34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18}, 8);
    
    printf("tuple_data = [");

    for (int i = 0; i < 256; i++) {
        if (i == 255){
            printf(" %d]\n", tuple_data_bv[i]?1:0);
        } else {
            printf(" %d", tuple_data_bv[i]?1:0);
        }        
    }


    std::vector<bool> h_data_bv(256); // h_data_bv = sha256(tuple_data), known
    
    std::vector<bool> hb_bv(8);
    std::vector<bool> bp_bv(16);
    std::vector<bool> h_bv(8);
    std::vector<bool> w_bv(8);
    std::vector<bool> lc_bv(16);
    std::vector<bool> ID_bv(16);
    std::vector<bool> t_bv(24);
    std::vector<bool> r_bv(160);

    h_data_bv = int_list_to_bits({111, 24, 20, 107, 245, 107, 158, 62, 87, 244, 16, 72, 107, 5, 77, 124, 45, 166, 80, 114, 139, 173, 102, 33, 136, 61, 210, 75, 110, 138, 41, 255}, 8);
    
    printf("hash_tuple_data = [");
    for (int i = 0; i < 256; i++) {
        if (i == 255){
            printf(" %d]\n", h_data_bv[i]?1:0);
        } else {
            printf(" %d", h_data_bv[i]?1:0);
        }        
    }

    // for (int i = 0; i < 256; i++) {
    //     printf("	h%d == %d\n", 255-i, h_data_bv[i]?1:0);
         
    // }
    
    
    // hb_bv = int_list_to_bits({80}, 8);
    // bp_bv = int_list_to_bits({75, 115}, 8);
    // h_bv = int_list_to_bits({178}, 8);
    // w_bv = int_list_to_bits({85}, 8);
    // lc_bv = int_list_to_bits({17, 148}, 8);
    // ID_bv = int_list_to_bits({178, 17}, 8);
    // t_bv = int_list_to_bits({126, 39, 9}, 8);
    // r_bv = int_list_to_bits({34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18}, 8);

    // a.push_back(80); // Heartbeat
    // a.push_back(75); // Blood Pressure (diastolic)
    // a.push_back(115); // Blood Pressure (systolic)
    // a.push_back(178); // Height
    // a.push_back(85); // Weight
    // a.push_back(4500); // Lung Capacity  1 1100 0001 0111
    
    //premium = (hb as u64) * 8 + (bp_d as u64) * 5 + (bp_s as u64) * 10 + (height as u64) * 2 + (weight as u64) * 2 + (lc as u64) * 1;
    // b.push_back(8);  // Heartbeat
    // b.push_back(5);  // Blood Pressure (diastolic)
    // b.push_back(10); // Blood Pressure (systolic)
    // b.push_back(2);  // Height
    // b.push_back(2);  // Weight   
    // b.push_back(1);  // Lung Capacity

    /* premium coefficient*/
    std::vector<bool> hash_coeff_bv(256); 

    std::vector<bool> data_coeff_bv(256); 
    
    std::vector<bool> hb_coeff_bv(8);
    std::vector<bool> bp_diastolic_coeff_bv(8);
    std::vector<bool> bp_systolic_coeff_bv(8);
    std::vector<bool> h_coeff_bv(8);
    std::vector<bool> w_coeff_bv(8);
    std::vector<bool> lc_coeff_bv(8);
    std::vector<bool> r_coeff_bv(208);

    data_coeff_bv = int_list_to_bits({8, 5, 10, 2, 2, 1, 148, 178, 17, 126, 39, 9, 34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18}, 8);
    
    printf("data_coeff = [");
    for (int i = 0; i < 256; i++) {
        if (i == 255){
            printf(" %d]\n", data_coeff_bv[i]?1:0);
        } else {
            printf(" %d", data_coeff_bv[i]?1:0);
        }        
    }
    
    hash_coeff_bv = int_list_to_bits({192, 129, 109, 8, 16, 43, 16, 163, 195, 45, 111, 244, 16, 126, 103, 88, 203, 207, 206, 176, 254, 146, 102, 167, 11, 145, 126, 12, 92, 174, 53, 15}, 8);

    printf("hash_coeff = [");
    for (int i = 0; i < 256; i++) {
        if (i == 255){
            printf(" %d]\n", hash_coeff_bv[i]?1:0);
        } else {
            printf(" %d", hash_coeff_bv[i]?1:0);
        }        
    }

    // for (int i = 0; i < 256; i++) {
    //     printf("	h%d == %d\n", 255-i, hash_coeff_bv[i]?1:0);
         
    // }

    
    // hb_coeff_bv = int_list_to_bits({8}, 8);
    // bp_diastolic_coeff_bv = int_list_to_bits({5}, 8);
    // bp_systolic_coeff_bv = int_list_to_bits({10}, 8);
    // h_coeff_bv = int_list_to_bits({2}, 8);
    // w_coeff_bv = int_list_to_bits({2}, 8);
    // lc_coeff_bv = int_list_to_bits({1}, 8);
    // r_coeff_bv = int_list_to_bits({148, 178, 17, 126, 39, 9, 34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18}, 8);

    std::vector<bool> premium_bv(16);
    premium_bv = int_list_to_bits({28,23}, 8);

    printf("result = 7191\n");
    
    return 0;
}

