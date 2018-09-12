#include "test.h"

int convertFromAscii(uint8_t ch) {
        if (ch >= '0' && ch <='9') {
                return ch-'0';
        } else if (ch >= 'a' && ch <= 'f') {
                return ch-'a'+10;
        }
}
//test
int main() 
{
        struct timeval t_start,t_end;
        // long cost_time_2;
        // Initialize the curve parameters.	    // Initialize the curve parameters.
        gettimeofday(&t_start, NULL);
        printf("Start time: %ld s %ld us", t_start.tv_sec,t_start.tv_usec);
        
        // Initialize the curve parameters. Generate the verifying/proving keys. (This is trusted setup!)
        r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair = setup_keypair();
        //pk  vk
        exportVerificationKey(keypair);

        gettimeofday(&t_end, NULL);
        printf("end time: %ld s %ld us", t_end.tv_sec,t_end.tv_usec);
        long cost_time_1=t_end.tv_sec - t_start.tv_sec;
        long cost_time_2 = t_end.tv_usec - t_start.tv_usec;
        cout<<"genkeypair_time"<<endl<<endl;
        printf("%ld s %ld us",cost_time_1,cost_time_2);


        //socket
        io_service iosev;   
        ip::tcp::acceptor acceptorInstance(iosev, ip::tcp::endpoint(ip::tcp::v4(), 8032));
        for( ; ; ){
                ip::tcp::socket socket(iosev);
                acceptorInstance.accept(socket);
                std::cout << socket.remote_endpoint().address() << std::endl;
                boost::system::error_code ec;
                //original  data from go
                unsigned char data[1400];
                //change data to int
                unsigned long input[1400];
                
                std::cout << "wait ....." << std::endl;
                //get inputs
                socket.read_some(buffer(data), ec);

                cout<<endl<<endl<<endl<<endl;
                for (int i = 0; i < 1400; i++) {
                        // Now the hex code for the specific character.
                        input[i] = 0;
                }
                ///===============================================
                for (int i = 0; i < 1400; i++) {
                        // Now the hex code for the specific character.
                        input[i] = int(data[i]);
                        std::cout<<input[i]<<" ";
                }
                std::cout << endl;
                
                ///================================================

                if(input[0]==0&&input[1]==0){
                        libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof;
                        std::vector<bool> h_data_bv(256); // h_data_bv = sha256(tuple_data), known
                        std::vector<bool> tuple_data_bv(512);  //1056*8 or?
                        //std::vector<bool> hash_coeff_bv(256);
                        std::vector<bool> data_coeff_bv(coeff_len);
                        unsigned long result=0;
                        std::vector<bool> premium_bv(16);
                        

                        // dataCoeff = [1, 1, 1, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                        std::vector<unsigned long> v_h_data;
                        std::vector<unsigned long> v_tuple_data;
                        std::vector<unsigned long> v_data_coeff;
                        //v_h_data
                        for(int i=0;i<32;i++){                      //always 32
                               v_h_data.push_back(input[i+2]); 
                        }
                        //h_data_bv
                        h_data_bv=int_list_to_bits(v_h_data,8);  
                        //v_tuple_data
                        for(int i=0;i<64;i++){                    //need to change 32
                               v_tuple_data.push_back(input[i+34]);   
                        }
                        //tuple_data_bv
                        tuple_data_bv=int_list_to_bits(v_tuple_data,8);
                        
                        std::cout << endl<<"input[98] = " << input[98] << std::endl;  //need to change 66
                        //v_data_coeff
                        for(int i=0;i<input[98];i++){                                   //need to change 66
                                v_data_coeff.push_back(input[i+99]);                    //need to change 67   +1
                        }
                        //data_coeff_bv
                        data_coeff_bv = int_list_to_bits(v_data_coeff,8);                
                        //result        
                        for(int i=0;i<input[98];i++){                                    //need to change 66
                                result+=input[34+i]*input[99+i];                        // not change 34  change 67
                        }

                        cout<<endl<<"result"<<result<<endl;
                              
                        //premium_bv
                        premium_bv = int_list_to_bits({result/256,result%256}, 8);
 
                        cout<<result<<endl;
                        std::string result_string=std::to_string (result);
                        cout<<"result_string.size"<<endl;
                        cout<<result_string.size()<<endl;
                        cout<<"len(result_string)"<<endl;
                        cout<<result_string.length()<<endl;

                        proof = *generate_proof<libff::alt_bn128_pp>(keypair.pk, 
                                                                        h_data_bv, 
                                                                        tuple_data_bv,
                                                                        data_coeff_bv,                                                            
                                                                        premium_bv
                                                                        );
                        //to string_proof
                        std::string proof_string=string_proof_as_hex(proof); 
                        cout<<"string_proof"<<proof_string<<endl;            
                        cout<<proof_string<<endl;
                        std::string result_and_proof=result_string+proof_string;
                        cout<<"result_and_proof.size()"<<endl;
                        cout<<result_and_proof.size()<<endl;
                        cout<<"len(result_and_proof)"<<endl;
                        cout<<result_and_proof.length()<<endl;

                        socket.write_some(buffer(result_and_proof),ec);
                }
                else if(input[0]==0 && input[1]==1){
                        libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof;
                        std::vector<bool> test_premium_bv(16);
                        std::vector<bool> test_h_data_bv(256);
                        std::vector<bool> test_coeff_data_bv(coeff_len);

                        //change go proof to c++ proof
                        cout<<"go_proof"<<endl;
                        for (int i = 0; i < 1400; i++) {
                        // Now the hex code for the specific character.
                                cout<<input[i]<<" ";
                        }
                        cout<<endl;
                        
                        std::vector<unsigned long> v_test_h_data;
                        std::vector<unsigned long> v_test_coeff_data;
                        //v-h-data
                        for(int i=0;i<32;i++){                            //alawys 32
                               v_test_h_data.push_back(input[i+1154]);    //always  1154
                        }
                        //test_h_data_bv
                        test_h_data_bv=int_list_to_bits(v_test_h_data,8);

                        cout<<endl<<"input[1218]"<<endl<<input[1218]<<endl;

                        //test_premium_bv
                        test_premium_bv=int_list_to_bits({input[1216],input[1217]}, 8);
                        //v_test_coeff_data
                        for(int i=0;i<input[1218];i++){                         //always  1218
                                v_test_coeff_data.push_back(input[i+1219]);     //always   1219
                        }
                        //test_coeff_data_bv
                        test_coeff_data_bv=int_list_to_bits(v_test_coeff_data,8);

                        //change go_proof
                        uint8_t A_g_x[64];  uint8_t A_g_y[64];  uint8_t A_h_x[64];  uint8_t A_h_y[64];  
                        uint8_t B_g_x_1[64];uint8_t B_g_x_0[64];uint8_t B_g_y_1[64];uint8_t B_g_y_0[64];
                        uint8_t B_h_x[64];  uint8_t B_h_y[64];  uint8_t C_g_x[64];  uint8_t C_g_y[64];
                        uint8_t C_h_x[64];  uint8_t C_h_y[64];  uint8_t H_x[64];    uint8_t H_y[64];
                        uint8_t K_x[64];    uint8_t K_y[64];
                        
                        for(int i=0;i<64;i++){
                                A_g_x[i]=uint8_t(data[i+2]);    A_g_y[i]=uint8_t(data[i+66]);
                                A_h_x[i]=uint8_t(data[i+130]);  A_h_y[i]=uint8_t(data[i+194]);
                                B_g_x_1[i]=uint8_t(data[i+258]);B_g_x_0[i]=uint8_t(data[i+322]);
                                B_g_y_1[i]=uint8_t(data[i+386]);B_g_y_0[i]=uint8_t(data[i+450]);
                                B_h_x[i]=uint8_t(data[i+514]);  B_h_y[i]=uint8_t(data[i+578]);
                                C_g_x[i]=uint8_t(data[i+642]);  C_g_y[i]=uint8_t(data[i+706]);
                                C_h_x[i]=uint8_t(data[i+770]);  C_h_y[i]=uint8_t(data[i+834]);
                                H_x[i]=uint8_t(data[i+898]);    H_y[i]=uint8_t(data[i+962]);
                                K_x[i]=uint8_t(data[i+1026]);   K_y[i]=uint8_t(data[i+1090]);
                        }

                         for(int i=0,j=0;i<64;i+=2,j++){
                                A_g_x[j] = uint8_t(convertFromAscii(A_g_x[i])*16   + convertFromAscii(A_g_x[i+1]));
                                A_g_y[j] = uint8_t(convertFromAscii(A_g_y[i])*16   + convertFromAscii(A_g_y[i+1]));
                                A_h_x[j] = uint8_t(convertFromAscii(A_h_x[i])*16   + convertFromAscii(A_h_x[i+1]));
                                A_h_y[j] = uint8_t(convertFromAscii(A_h_y[i])*16   + convertFromAscii(A_h_y[i+1]));
                                B_g_x_1[j]=uint8_t(convertFromAscii(B_g_x_1[i])*16 + convertFromAscii(B_g_x_1[i+1]));
                                B_g_x_0[j]=uint8_t(convertFromAscii(B_g_x_0[i])*16 + convertFromAscii(B_g_x_0[i+1]));
                                B_g_y_1[j]=uint8_t(convertFromAscii(B_g_y_1[i])*16 + convertFromAscii(B_g_y_1[i+1]));
                                B_g_y_0[j]=uint8_t(convertFromAscii(B_g_y_0[i])*16 + convertFromAscii(B_g_y_0[i+1]));
                                B_h_x[j]=uint8_t(convertFromAscii(B_h_x[i])*16     + convertFromAscii(B_h_x[i+1]));
                                B_h_y[j]=uint8_t(convertFromAscii(B_h_y[i])*16     + convertFromAscii(B_h_y[i+1]));
                                C_g_x[j]=uint8_t(convertFromAscii(C_g_x[i])*16     + convertFromAscii(C_g_x[i+1]));
                                C_g_y[j]=uint8_t(convertFromAscii(C_g_y[i])*16     + convertFromAscii(C_g_y[i+1]));
                                C_h_x[j]=uint8_t(convertFromAscii(C_h_x[i])*16     + convertFromAscii(C_h_x[i+1]));
                                C_h_y[j]=uint8_t(convertFromAscii(C_h_y[i])*16     + convertFromAscii(C_h_y[i+1]));
                                H_x[j]=uint8_t(convertFromAscii(H_x[i])*16         + convertFromAscii(H_x[i+1]));
                                H_y[j]=uint8_t(convertFromAscii(H_y[i])*16         + convertFromAscii(H_y[i+1]));
                                K_x[j]=uint8_t(convertFromAscii(K_x[i])*16         + convertFromAscii(K_x[i+1]));
                                K_y[j]=uint8_t(convertFromAscii(K_y[i])*16         + convertFromAscii(K_y[i+1]));
                        }


                        libff::bigint<libff::alt_bn128_r_limbs> a_g_x   = libsnarkBigintFromBytes(A_g_x);
                        libff::bigint<libff::alt_bn128_r_limbs> a_g_y   = libsnarkBigintFromBytes(A_g_y);
                        libff::bigint<libff::alt_bn128_r_limbs> a_h_x   = libsnarkBigintFromBytes(A_h_x);
                        libff::bigint<libff::alt_bn128_r_limbs> a_h_y   = libsnarkBigintFromBytes(A_h_y);
                        libff::bigint<libff::alt_bn128_r_limbs> b_g_x_1 = libsnarkBigintFromBytes(B_g_x_1);
                        libff::bigint<libff::alt_bn128_r_limbs> b_g_x_0 = libsnarkBigintFromBytes(B_g_x_0);
                        libff::bigint<libff::alt_bn128_r_limbs> b_g_y_1 = libsnarkBigintFromBytes(B_g_y_1);
                        libff::bigint<libff::alt_bn128_r_limbs> b_g_y_0 = libsnarkBigintFromBytes(B_g_y_0);

                        libff::bigint<libff::alt_bn128_r_limbs> b_h_x   = libsnarkBigintFromBytes(B_h_x);
                        libff::bigint<libff::alt_bn128_r_limbs> b_h_y   = libsnarkBigintFromBytes(B_h_y);
                        libff::bigint<libff::alt_bn128_r_limbs> c_g_x   = libsnarkBigintFromBytes(C_g_x);
                        libff::bigint<libff::alt_bn128_r_limbs> c_g_y   = libsnarkBigintFromBytes(C_g_y);
                        libff::bigint<libff::alt_bn128_r_limbs> c_h_x   = libsnarkBigintFromBytes(C_h_x);
                        libff::bigint<libff::alt_bn128_r_limbs> c_h_y   = libsnarkBigintFromBytes(C_h_y);
                        libff::bigint<libff::alt_bn128_r_limbs> h_x     = libsnarkBigintFromBytes(H_x);
                        libff::bigint<libff::alt_bn128_r_limbs> h_y     = libsnarkBigintFromBytes(H_y);
                        libff::bigint<libff::alt_bn128_r_limbs> k_x     = libsnarkBigintFromBytes(K_x);
                        libff::bigint<libff::alt_bn128_r_limbs> k_y     = libsnarkBigintFromBytes(K_y); 
  
                        cout<<"A-g-x"<<endl;
                        for(int i=0;i<32;i++){
                                //cout<<A_g_x[i];
                                printf("%d ", A_g_x[i]);
                        }
                        cout<<"A-g-x"<<endl;
                        // for(int i=0;i<64;i++){
                        //         cout<<A_g_y[i];
                        // }

                        cout<<endl<<"a_g-x"<<endl<<a_g_x<<endl<<"a_g-x"<<endl;
                        cout<<a_g_y<<endl;
                        cout<<a_h_x<<a_h_y<<endl<<b_g_x_1<<b_g_x_0<<b_g_y_1<<b_g_y_0<<endl;
                        cout<<b_h_x<<b_h_y<<endl<<c_g_x<<c_g_y<<endl<<c_h_x<<c_h_y<<endl<<h_x<<h_y<<endl<<k_x<<k_y<<endl;
                        //ecc element
                        proof.g_A.g.X=a_g_x;     proof.g_A.g.Y=a_g_y;     proof.g_A.h.X=a_h_x;     proof.g_A.h.Y=a_h_y;
                        proof.g_B.g.X.c1=b_g_x_1;proof.g_B.g.X.c0=b_g_x_0;proof.g_B.g.Y.c1=b_g_y_1;proof.g_B.g.Y.c0=b_g_y_0;
                        proof.g_B.h.X=b_h_x;     proof.g_B.h.Y=b_h_y;
                        proof.g_C.g.X=c_g_x;     proof.g_C.g.Y=c_g_y;     proof.g_C.h.X=c_h_x;     proof.g_C.h.Y=c_h_y;
                        proof.g_H.X=h_x;         proof.g_H.Y=h_y;         proof.g_K.X=k_x;         proof.g_K.Y=k_y;
                        // bool right_or_false=verify(keypair, proof);
                        bool right_or_false = verify_proof(keypair.vk, proof, test_h_data_bv, test_coeff_data_bv, test_premium_bv);
                        
                        if(right_or_false)
                        socket.write_some(buffer("1"),ec);
                        else
                        socket.write_some(buffer("2"),ec);
                }
        }
}



r1cs_ppzksnark_keypair<libff::alt_bn128_pp> setup_keypair()
{
    libff::alt_bn128_pp::init_public_params();
    r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair = generate_keypair<libff::alt_bn128_pp>();
    return keypair;
}


//convert conversion byte[32] -> libsnark bigint
libff::bigint<libff::alt_bn128_r_limbs> libsnarkBigintFromBytes(const uint8_t* _x)
{
  libff::bigint<libff::alt_bn128_r_limbs> x;

  for (unsigned i = 0; i < 4; i++) {
    for (unsigned j = 0; j < 8; j++) {
      x.data[3 - i] |= uint64_t(_x[i * 8 + j]) << (8 * (7-j));
    }
  }
  return x;
}

//libsnark bigint->conversion byte[32]
std::string HexStringFromLibsnarkBigint(libff::bigint<libff::alt_bn128_r_limbs> _x){
    uint8_t x[32];
    for (unsigned i = 0; i < 4; i++)
        for (unsigned j = 0; j < 8; j++)
                x[i * 8 + j] = uint8_t(uint64_t(_x.data[3 - i]) >> (8 * (7 - j)));

        std::stringstream ss;
        ss << std::setfill('0');
        for (unsigned i = 0; i<32; i++) {
                ss << std::hex << std::setw(2) << (int)x[i];
        }

        std::string str = ss.str(); 
        return str.erase(0, min(str.find_first_not_of('0'), str.size()-1));
}


//g1 as hex
std::string outputPointG1AffineAsHex(libff::alt_bn128_G1 _p)
{
        libff::alt_bn128_G1 aff = _p;
        aff.to_affine_coordinates();
        cout<<aff.X.as_bigint()<<endl;
        std::string s_x=HexStringFromLibsnarkBigint(aff.X.as_bigint());
        while(s_x.size()<64){
            s_x="0"+s_x;
        }
        cout<<s_x<<endl;
        std::string s_y=HexStringFromLibsnarkBigint(aff.Y.as_bigint());
        while(s_y.size()<64){
            s_y="0"+s_y;
        }
        return s_x+s_y;
}

std::string outputPointG2AffineAsHex(libff::alt_bn128_G2 _p)
{
        libff::alt_bn128_G2 aff = _p;
        aff.to_affine_coordinates();
        cout<<aff.X.c1.as_bigint()<<aff.X.c0.as_bigint()<<aff.Y.c1.as_bigint()<<aff.Y.c0.as_bigint()<<endl;

        std::string x_1=HexStringFromLibsnarkBigint(aff.X.c1.as_bigint());
        while(x_1.size()<64){
            x_1="0"+x_1;
        }
        std::string x_0=HexStringFromLibsnarkBigint(aff.X.c0.as_bigint());
        while(x_0.size()<64){
            x_0="0"+x_0;
        }
        std::string y_1=HexStringFromLibsnarkBigint(aff.Y.c1.as_bigint());
        while(y_1.size()<64){
            y_1="0"+y_1;
        }
        std::string y_0=HexStringFromLibsnarkBigint(aff.Y.c0.as_bigint());
        while(y_0.size()<64){
            y_0="0"+y_0;
        }
        return x_1+x_0+y_1+y_0;
}

//string_proof as hex
std::string string_proof_as_hex(libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof)
{
    std::string A=outputPointG1AffineAsHex(proof.g_A.g);
    cout<<endl<<"proof.g_A.g"<<endl<<A<<endl;  //
    std::string A_P=outputPointG1AffineAsHex(proof.g_A.h);
    cout<<A.size()<<" "<<A_P.size()<<endl;
    std::string B=outputPointG2AffineAsHex(proof.g_B.g);
    std::string B_P=outputPointG1AffineAsHex(proof.g_B.h);
    cout<<B.size()<<" "<<B_P.size()<<endl;
    std::string C=outputPointG1AffineAsHex(proof.g_C.g);
    std::string C_P=outputPointG1AffineAsHex(proof.g_C.h);
    cout<<C.size()<<" "<<C_P.size()<<endl;
    std::string H=outputPointG1AffineAsHex(proof.g_H);
    cout<<H.size()<<endl;
    std::string K=outputPointG1AffineAsHex(proof.g_K);
    cout<<K.size()<<endl;
    std::string proof_string=A+A_P+B+B_P+C+C_P+H+K;
    return proof_string;
}

void exportVerificationKey(r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair){
        unsigned icLength = keypair.vk.encoded_IC_query.rest.indices.size() + 1;

        cout << "\tVerification key in Solidity compliant format:{" << endl;
        cout << "\t\tvk.A = Pairing.G2Point(" << outputPointG2AffineAsHex(keypair.vk.alphaA_g2) << ");" << endl;
        cout << "\t\tvk.B = Pairing.G1Point(" << outputPointG1AffineAsHex(keypair.vk.alphaB_g1) << ");" << endl;
        cout << "\t\tvk.C = Pairing.G2Point(" << outputPointG2AffineAsHex(keypair.vk.alphaC_g2) << ");" << endl;
        cout << "\t\tvk.gamma = Pairing.G2Point(" << outputPointG2AffineAsHex(keypair.vk.gamma_g2) << ");" << endl;
        cout << "\t\tvk.gammaBeta1 = Pairing.G1Point(" << outputPointG1AffineAsHex(keypair.vk.gamma_beta_g1) << ");" << endl;
        cout << "\t\tvk.gammaBeta2 = Pairing.G2Point(" << outputPointG2AffineAsHex(keypair.vk.gamma_beta_g2) << ");" << endl;
        cout << "\t\tvk.Z = Pairing.G2Point(" << outputPointG2AffineAsHex(keypair.vk.rC_Z_g2) << ");" << endl;
        cout << "\t\tvk.IC = new Pairing.G1Point[](" << icLength << ");" << endl;
        cout << "\t\tvk.IC[0] = Pairing.G1Point(" << outputPointG1AffineAsHex(keypair.vk.encoded_IC_query.first) << ");" << endl;
        for (size_t i = 1; i < icLength; ++i)
        {
                auto vkICi = outputPointG1AffineAsHex(keypair.vk.encoded_IC_query.rest.values[i - 1]);
                cout << "\t\tvk.IC[" << i << "] = Pairing.G1Point(" << vkICi << ");" << endl;
        }
        cout << "\t\t}" << endl;

}




