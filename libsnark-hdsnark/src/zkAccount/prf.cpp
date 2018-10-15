#include "prf.h"
#include "crypto/sha256.h"

uint256 PRF(const uint256& x, const uint256& y)
{
    uint256 res;
    unsigned char blob[64];

    memcpy(&blob[0], x.begin(), 32);
    memcpy(&blob[32], y.begin(), 32);

    CSHA256 hasher;
    hasher.Write(blob, 64);
    hasher.FinalizeNoPadding(res.begin());

    return res;
}

uint256 PRF_addr_recv_pk(const uint256& pk_b1, const uint256& pk_b2)
{
    return PRF(pk_b1, pk_b2);
}

uint256 PRF_sn(const uint256& pk_a, const uint256& rho)
{
    return PRF(pk_a, rho);
}

