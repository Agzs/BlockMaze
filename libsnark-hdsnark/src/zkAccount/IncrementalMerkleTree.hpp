#ifndef VNTINCREMENTALMERKLETREE_H_
#define VNTINCREMENTALMERKLETREE_H_

#include <deque>
#include <boost/optional.hpp>
#include <boost/static_assert.hpp>

#include "uint256.h"
#include "zkAccount/serialize.h"

#include "VNT.h"

namespace libvnt {

class MerklePath {
public:
    std::vector<std::vector<bool>> authentication_path;
    std::vector<bool> index;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(authentication_path);
        READWRITE(index);
    }

    MerklePath() { }

    MerklePath(std::vector<std::vector<bool>> authentication_path, std::vector<bool> index)
    : authentication_path(authentication_path), index(index) { }
};

template<size_t Depth, typename Hash>
class EmptyMerkleRoots {
public:
    EmptyMerkleRoots() {
        empty_roots.at(0) = Hash();
        for (size_t d = 1; d <= Depth; d++) {
            empty_roots.at(d) = Hash::combine(empty_roots.at(d-1), empty_roots.at(d-1));
        }
    }
    Hash empty_root(size_t depth) {
        return empty_roots.at(depth);
    }
private:
    boost::array<Hash, Depth+1> empty_roots;
};

template<size_t Depth, typename Hash>
class IncrementalWitness;

template<size_t Depth, typename Hash>
class IncrementalMerkleTree {

friend class IncrementalWitness<Depth, Hash>;

public:
    BOOST_STTIC_ASSERT(Depth >= 1);

    IncrementalMerkleTree() { }

    void append(Hash obj);  // tree.append(
    Hash root() const {
        return root(Depth, std::deque<Hash>());
    }

    IncrementalWitness<Depth, Hash> witness() const {
        return IncrementalWitness<Depth, Hash>(*this);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(left);
        READWRITE(right);
        READWRITE(parents);

        wfcheck();
    }

    static Hash empty_root() {
        return emptyroots.empty_root(Depth);
    }

private:
    static EmptyMerkleRoots<Depth, Hash> emptyroots;
    boost::optional<Hash> left;
    boost::optional<Hash> right;

    // Collapsed "left" subtrees ordered toward the root of the tree.
    std::vector<boost::optional<Hash>> parents;
    MerklePath path(std::deque<Hash> filler_hashes = std::deque<Hash>()) const;
    Hash root(size_t depth, std::deque<Hash> filler_hashes = std::deque<Hash>()) const;
    bool is_complete(size_t depth = Depth) const;
    size_t next_depth(size_t skip) const;
    void wfcheck() const;
};

template <size_t Depth, typename Hash>
class IncrementalWitness {
friend class IncrementalMerkleTree<Depth, Hash>;

public:
    MerklePath path() const {
        return tree.path(partial_path());
    }

    Hash root() const {
        return tree.root(Depth, partial_path());
    }

    void append(Hash obj); // wit->append() or wit.append()

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(tree);
        READWRITE(filled);
        READWRITE(cursor);

        cursor_depth = tree.next_depth(filled.size());
    }

private:
    IncrementalMerkleTree<Depth, Hash> tree;
    std::vector<Hash> filled;
    boost::optional<IncrementalMerkleTree<Depth, Hash>> cursor;
    size_t cursor_depth;
    std::deque<Hash> partial_path() const;
    IncrementalWitness(IncrementalMerkleTree<Depth, Hash> tree) : tree(tree) {}
};

class SHA256Compress : public uint256 {
public:
    SHA256Compress() : uint256() {}
    SHA256Compress(uint256 contents) : uint256(contents) { }

    static SHA256Compress combine(const SHA256Compress& a, const SHA256Compress& b);
};

} // end namespace `libvnt`

typedef libvnt::IncrementalMerkleTree<INCREMENTAL_MERKLE_TREE_DEPTH, libvnt::SHA256Compress> ZCIncrementalMerkleTree;
typedef libvnt::IncrementalMerkleTree<INCREMENTAL_MERKLE_TREE_DEPTH_TESTING, libvnt::SHA256Compress> ZCTestingIncrementalMerkleTree;

typedef libvnt::IncrementalWitness<INCREMENTAL_MERKLE_TREE_DEPTH, libvnt::SHA256Compress> ZCIncrementalWitness;
typedef libvnt::IncrementalWitness<INCREMENTAL_MERKLE_TREE_DEPTH_TESTING, libvnt::SHA256Compress> ZCTestingIncrementalWitness;

#endif /* ZCINCREMENTALMERKLETREE_H_ */

