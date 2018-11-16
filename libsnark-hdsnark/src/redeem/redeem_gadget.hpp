#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

static void initialize() {
    LOCK(cs_InitializeParams);

    ppzksnark_ppT::init_public_params();
}

void setProvingKeyPath(std::string path) {
    pkPath = path;
}

void loadProvingKey() {
    if (!pk) {
        if (!pkPath) {
            throw std::runtime_error("proving key path unknown");
        }
        loadFromFile(*pkPath, pk);
    }
}

void saveProvingKey(std::string path) {
    if (pk) {
        saveToFile(path, *pk);
    } else {
        throw std::runtime_error("cannot save proving key; key doesn't exist");
    }
}

void loadVerifyingKey(std::string path) {
    loadFromFile(path, vk);
}

void saveVerifyingKey(std::string path) {
    if (vk) {
        saveToFile(path, *vk);
    } else {
        throw std::runtime_error("cannot save verifying key; key doesn't exist");
    }
}

void generate() {
}

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