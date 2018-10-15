#ifndef _ZCADDRESS_H_
#define _ZCADDRESS_H_

#include "uint256.h"
#include "serialize.h"

namespace libvnt {

class PaymentAddress {
public:
    uint256 a_pk;
    uint256 pk_enc;

    PaymentAddress() : a_pk(), pk_enc() { }
    PaymentAddress(uint256 a_pk, uint256 pk_enc) : a_pk(a_pk), pk_enc(pk_enc) { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        unsigned char leadingByte = 0x92;
        READWRITE(leadingByte);

        if (leadingByte != 0x92) {
            throw std::ios_base::failure("unrecognized payment address lead byte");
        }

        READWRITE(a_pk);
        READWRITE(pk_enc);
    }
};

class ViewingKey : public uint256 {
public:
    ViewingKey(uint256 sk_enc) : uint256(sk_enc) { }

    uint256 pk_enc();
};

class SpendingKey : public uint256 {
public:
    SpendingKey() : uint256() { }
    SpendingKey(uint256 a_sk) : uint256(a_sk) { }

    static SpendingKey random();

    ViewingKey viewing_key();
    PaymentAddress address();
};

}

#endif // _ZCADDRESS_H_