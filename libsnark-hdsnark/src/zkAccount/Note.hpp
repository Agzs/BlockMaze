#ifndef _ZCNOTE_H_
#define _ZCNOTE_H_

#include "uint256.h"
#include "VNT.h"
#include "Address.hpp"
#include "NoteEncryption.hpp"

namespace libvnt {

class Note {
public:
    uint64_t value;
    uint256 sn;
    uint256 r;

    Note(uint64_t value, uint256 sn, uint256 r)
        : value(value), sn(sn), r(r) {}

    Note();

    uint256 cm() const;
    uint256 nullifier(const SpendingKey& a_sk) const;
};

class NotePlaintext {
public:
    uint64_t value;
    uint256 rho;
    uint256 r;
    boost::array<unsigned char, VNT_MEMO_SIZE> memo;

    NotePlaintext() {}

    NotePlaintext(const Note& note, boost::array<unsigned char, VNT_MEMO_SIZE> memo);

    Note note(const PaymentAddress& addr) const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        unsigned char leadingByte = 0x00;
        READWRITE(leadingByte);

        if (leadingByte != 0x00) {
            throw std::ios_base::failure("lead byte of NotePlaintext is not recognized");
        }

        READWRITE(value);
        READWRITE(rho);
        READWRITE(r);
        READWRITE(memo);
    }

    static NotePlaintext decrypt(const ZCNoteDecryption& decryptor,
                                 const ZCNoteDecryption::Ciphertext& ciphertext,
                                 const uint256& ephemeralKey,
                                 const uint256& h_sig,
                                 unsigned char nonce
                                );

    ZCNoteEncryption::Ciphertext encrypt(ZCNoteEncryption& encryptor,
                                         const uint256& pk_enc
                                        ) const;
};

}

#endif // _ZCNOTE_H_