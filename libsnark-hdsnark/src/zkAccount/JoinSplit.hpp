#ifndef _ZCJOINSPLIT_H_
#define _ZCJOINSPLIT_H_

#include "VNT.h"
#include "Address.hpp"
#include "Note.hpp"
#include "IncrementalMerkleTree.hpp"
#include "NoteEncryption.hpp"

#include "uint256.h"

#include <boost/array.hpp>

namespace libvnt {

class JSInput { 
public:
    ZCIncrementalWitness witness;
    Note note;
    SpendingKey key;

    JSInput();
    JSInput(ZCIncrementalWitness witness,
            Note note,
            SpendingKey key) : witness(witness), note(note), key(key) { }

    uint256 nullifier() const {
        return note.nullifier(key);
    }
};

class JSOutput {
public:
    PaymentAddress addr;
    uint64_t value;

    JSOutput();
    JSOutput(PaymentAddress addr, uint64_t value) : addr(addr), value(value) { }

    Note note(const uint256& phi, const uint256& r, size_t i, const uint256& h_sig) const;
};

template<size_t NumInputs, size_t NumOutputs>
class JoinSplit {
public:
    static JoinSplit<NumInputs, NumOutputs>* Generate();
    static JoinSplit<NumInputs, NumOutputs>* Unopened();
    static uint256 h_sig(const uint256& randomSeed,
                         const boost::array<uint256, NumInputs>& nullifiers,
                         const uint256& pubKeyHash
                        );

    // TODO: #789
    virtual void setProvingKeyPath(std::string) = 0;
    virtual void loadProvingKey() = 0;

    virtual void saveProvingKey(std::string path) = 0;
    virtual void loadVerifyingKey(std::string path) = 0;
    virtual void saveVerifyingKey(std::string path) = 0;

    virtual std::string prove(
        const boost::array<JSInput, NumInputs>& inputs,
        const boost::array<JSOutput, NumOutputs>& outputs,
        boost::array<Note, NumOutputs>& out_notes,
        boost::array<ZCNoteEncryption::Ciphertext, NumOutputs>& out_ciphertexts,
        uint256& out_ephemeralKey,
        const uint256& pubKeyHash,
        uint256& out_randomSeed,
        boost::array<uint256, NumInputs>& out_hmacs,
        boost::array<uint256, NumInputs>& out_nullifiers,
        boost::array<uint256, NumOutputs>& out_commitments,
        uint64_t vpub_old,
        uint64_t vpub_new,
        const uint256& rt
    ) = 0;

    virtual bool verify(
        const std::string& proof,
        const uint256& pubKeyHash,
        const uint256& randomSeed,
        const boost::array<uint256, NumInputs>& hmacs,
        const boost::array<uint256, NumInputs>& nullifiers,
        const boost::array<uint256, NumOutputs>& commitments,
        uint64_t vpub_old,
        uint64_t vpub_new,
        const uint256& rt
    ) = 0;

protected:
    JoinSplit() {}
};

}

typedef libvnt::JoinSplit<VNT_NUM_JS_INPUTS,
                            VNT_NUM_JS_OUTPUTS> ZCJoinSplit;

#endif // _ZCJOINSPLIT_H_