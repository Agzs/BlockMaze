/*
VNT uses SHA256Compress as a PRF for various components
within the zkSNARK circuit.
*/

#ifndef _PRF_H_
#define _PRF_H_

#include "uint256.h"

// recv_pk_b = sha256(pk_b') 512bits => 256bits
uint256 PRF_addr_recv_pk(const uint256& pk_b1, const uint256& pk_b2);
// sn = sha256(pk_a, <balance_a, currentTime, randomNumber>) 256+64+64+128=512bits => 256bits
uint256 PRF_sn(const uint256& pk_a, const uint256& rho);

#endif // _PRF_H_
