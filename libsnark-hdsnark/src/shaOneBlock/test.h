#include <stdlib.h>
#include <iostream>
#include <cassert>
#include <iomanip>
#include <vector>
#include <boost/asio.hpp>
#include <sys/time.h>
#include "snark.hpp"

#include <boost/optional/optional_io.hpp> // for cout proof --Agzs
#include <libff/common/utils.hpp>
// contains definition of alt_bn128 ec public parameters
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp"

// contains required interfaces and types (keypair, proof, generator, prover, verifier)
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

using namespace libff;
using namespace libsnark;
using namespace std;
using namespace boost::asio;


typedef long integer_coeff_t;
typedef unsigned char uint8_t;

//init + keypair
r1cs_ppzksnark_keypair<libff::alt_bn128_pp> setup_keypair();
//verify
// bool verify(r1cs_ppzksnark_keypair<libff::alt_bn128_pp>& keypair,r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof);
//convert conversion byte[32] -> libsnark bigint
libff::bigint<libff::alt_bn128_r_limbs> libsnarkBigintFromBytes(const uint8_t* _x);
//libsnark bigint->conversion byte[32]
std::string HexStringFromLibsnarkBigint(libff::bigint<libff::alt_bn128_r_limbs> _x);
//g1 as hex 
std::string outputPointG1AffineAsHex(libff::alt_bn128_G1 _p);
//g2 as hex
std::string outputPointG2AffineAsHex(libff::alt_bn128_G2 _p);
//string_proof as hex
std::string string_proof_as_hex(libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof);
//print vk
void exportVerificationKey(r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair);