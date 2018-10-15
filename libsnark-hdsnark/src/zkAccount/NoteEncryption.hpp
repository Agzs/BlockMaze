/*
See the Zcash protocol specification for more information.
https://github.com/zkAccount/zips/blob/master/protocol/protocol.pdf
*/

#ifndef VNT_NOTE_ENCRYPTION_H_
#define VNT_NOTE_ENCRYPTION_H_

#include <boost/array.hpp>
#include "uint256.h"

#include "zkAccount/VNT.h"

namespace libvnt {

#define NOTEENCRYPTION_AUTH_BYTES 16

template<size_t MLEN>
class NoteEncryption {
protected:
    enum { CLEN=MLEN+NOTEENCRYPTION_AUTH_BYTES };
    uint256 epk;
    uint256 esk;
    unsigned char nonce;
    uint256 hSig;

public:
    typedef boost::array<unsigned char, CLEN> Ciphertext;
    typedef boost::array<unsigned char, MLEN> Plaintext;

    NoteEncryption(uint256 hSig);

    // Gets the ephemeral public key
    uint256 get_epk() {
        return epk;
    }

    // Encrypts `message` with `pk_enc` and returns the ciphertext.
    // This can only be called twice for a given instantiation before
    // the nonce-space runs out.
    Ciphertext encrypt(const uint256 &pk_enc,
                       const Plaintext &message
                      );

    // Creates a NoteEncryption private key
    static uint256 generate_privkey(const uint256 &a_sk);

    // Creates a NoteEncryption public key from a private key
    static uint256 generate_pubkey(const uint256 &sk_enc);
};

template<size_t MLEN>
class NoteDecryption {
protected:
    enum { CLEN=MLEN+NOTEENCRYPTION_AUTH_BYTES };
    uint256 sk_enc;
    uint256 pk_enc;

public:
    typedef boost::array<unsigned char, CLEN> Ciphertext;
    typedef boost::array<unsigned char, MLEN> Plaintext;

    NoteDecryption(uint256 sk_enc);

    Plaintext decrypt(const Ciphertext &ciphertext,
                      const uint256 &epk,
                      const uint256 &hSig,
                      unsigned char nonce
                     ) const;
};

uint256 random_uint256();

}

typedef libvnt::NoteEncryption<VNT_NOTEPLAINTEXT_LEADING + VNT_V_SIZE + VNT_RHO_SIZE + VNT_R_SIZE + VNT_MEMO_SIZE> ZCNoteEncryption;
typedef libvnt::NoteDecryption<VNT_NOTEPLAINTEXT_LEADING + VNT_V_SIZE + VNT_RHO_SIZE + VNT_R_SIZE + VNT_MEMO_SIZE> ZCNoteDecryption;

#endif /* VNT_NOTE_ENCRYPTION_H_ */
