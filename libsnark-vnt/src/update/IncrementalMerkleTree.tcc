#ifndef VNTINCREMENTALMERKLETREE_TCC_
#define VNTINCREMENTALMERKLETREE_TCC_
#include <stdexcept>

#include <boost/foreach.hpp>

#include "IncrementalMerkleTree.hpp"
//#include "deps/sha256.h"
//#include "util.h" // TODO: remove these utilities

namespace libvnt {

// 合并压缩512bits
SHA256Compress SHA256Compress::combine(const SHA256Compress& a, const SHA256Compress& b)
{
    SHA256Compress res = SHA256Compress();

    CSHA256 hasher;
    hasher.Write(a.begin(), 32);
    hasher.Write(b.begin(), 32);
    hasher.FinalizeNoPadding(res.begin());

    return res;
}

// 路径填充的类模板
template <size_t Depth, typename Hash>
class PathFiller { 
private:
    std::deque<Hash> queue; //双端队列
    static EmptyMerkleRoots<Depth, Hash> emptyroots;
public:
    PathFiller() : queue() { }
    PathFiller(std::deque<Hash> queue) : queue(queue) { }

    Hash next(size_t depth) {
        if (queue.size() > 0) {
            Hash h = queue.front();
            queue.pop_front();

            return h;
        } else {
            return emptyroots.empty_root(depth);
        }
    }

};

// 为路径填充中的空根分配空间
template<size_t Depth, typename Hash>
EmptyMerkleRoots<Depth, Hash> PathFiller<Depth, Hash>::emptyroots; 

// 为MerkleTree的空根分配空间
template<size_t Depth, typename Hash>
EmptyMerkleRoots<Depth, Hash> IncrementalMerkleTree<Depth, Hash>::emptyroots; 

// MerkleTree检查
template<size_t Depth, typename Hash>
void IncrementalMerkleTree<Depth, Hash>::wfcheck() const { 
    if (parents.size() >= Depth) {
        throw std::ios_base::failure("tree has too many parents");
    }

    // The last parent cannot be null.
    if (!(parents.empty()) && !(parents.back())) {
        throw std::ios_base::failure("tree has non-canonical representation of parent");
    }

    // Left cannot be empty when right exists.
    if (!left && right) {
        throw std::ios_base::failure("tree has non-canonical representation; right should not exist");
    }

    // Left cannot be empty when parents is nonempty.
    if (!left && parents.size() > 0) {
        throw std::ios_base::failure("tree has non-canonical representation; parents should not be unempty");
    }
}

// MerkleTree追加cmt
template<size_t Depth, typename Hash>
void IncrementalMerkleTree<Depth, Hash>::append(Hash obj) { 
    if (is_complete(Depth)) {
        throw std::runtime_error("tree is full");
    }

    if (!left) {
        // Set the left leaf
        left = obj;
    } else if (!right) {
        // Set the right leaf
        right = obj;
    } else {
        // Combine the leaves and propagate it up the tree
        boost::optional<Hash> combined = Hash::combine(*left, *right);

        // Set the "left" leaf to the object and make the "right" leaf none
        left = obj;
        right = boost::none;

        for (size_t i = 0; i < Depth; i++) {
            if (i < parents.size()) { // parents为IncrementalMerkleTree私有成员变量,始终维护可进行combine的MerkleTree的节点表
                if (parents[i]) {
                    combined = Hash::combine(*parents[i], *combined);
                    parents[i] = boost::none;
                } else {
                    parents[i] = *combined;
                    break;
                }
            } else {
                parents.push_back(combined);
                break;
            }
        }

        /** 假定 Depth = 5
         *  left   right  combined      parents 0, 1, 2, 3
         *  === append(cmt1), append(cmt2) ===
         *  cmt1   cmt2     none         none, none, none, none  #size=0
         *  === append(cmt3), append(cmt4) ===
         *  cmt3   cmt4    h12           h12, none, none, none   #size=1
         *  === append(cmt5), append(cmt6) ===
         *  cmt5   cmt6    h34,h14       none, h14, none, none   #size=2
         *  === append(cmt7), append(cmt8) ===
         *  cmt7   cmt8    h56           h56, h14, none, none    #size=2,     is_complete if depth = 3
         *  === append(cmt9) ===
         *  cmt9   none    h78,h58,h18   none, none, h18, none   #size=3
         * 
         * Parents的vector，第一项是hash两个叶子，第二项是hash四个叶子，第i项是hash 2^i个叶子
        */
    }
}

// This is for allowing the witness to determine if a subtree has filled
// to a particular depth, or for append() to ensure we're not appending
// to a full tree. 判满，树满返回true
template<size_t Depth, typename Hash>
bool IncrementalMerkleTree<Depth, Hash>::is_complete(size_t depth) const {
    if (!left || !right) { // 左右孩子为空
        return false;
    }

    if (parents.size() != (depth - 1)) { // 未达到预设高度
        return false;
    }

    BOOST_FOREACH(const boost::optional<Hash>& parent, parents) { 
        if (!parent) {  //达到预设高度，但是叶子节点层未满
            return false;
        }
    }

    return true; // 满二叉树
}

// This finds the next "depth" of an unfilled subtree, given that we've filled
// `skip` uncles/subtrees. // 当前MerkleTree可构造的层数(不含叶子层)
template<size_t Depth, typename Hash>
size_t IncrementalMerkleTree<Depth, Hash>::next_depth(size_t skip) const { 
    if (!left) {
        if (skip) {
            skip--;
        } else {
            return 0;
        }
    }

    if (!right) {
        if (skip) {
            skip--;
        } else {
            return 0;
        }
    }

    size_t d = 1;

    BOOST_FOREACH(const boost::optional<Hash>& parent, parents) {
        if (!parent) {
            if (skip) {
                skip--;
            } else {
                return d;
            }
        }

        d++;
    }

    return d + skip;
}

// This calculates the root of the tree. 计算Merkle根
template<size_t Depth, typename Hash>
Hash IncrementalMerkleTree<Depth, Hash>::root(size_t depth,
                                              std::deque<Hash> filler_hashes) const {
    PathFiller<Depth, Hash> filler(filler_hashes);

    Hash combine_left =  left  ? *left  : filler.next(0);
    Hash combine_right = right ? *right : filler.next(0);

    Hash root = Hash::combine(combine_left, combine_right);

    size_t d = 1;

    BOOST_FOREACH(const boost::optional<Hash>& parent, parents) {
        if (parent) {
            root = Hash::combine(*parent, root);
        } else {
            root = Hash::combine(root, filler.next(d));
        }

        d++;
    }

    // We may not have parents for ancestor trees, so we fill
    // the rest in here.
    while (d < depth) {
        root = Hash::combine(root, filler.next(d));
        d++;
    }

    /** 假定 Depth = 5
     *  combine_left   combine_right   root      parents0, 1, 2, 3
     *    cmt7             cmt8        h78       h56, h14, none, none  // hash 7 8
     *    cmt7             cmt8        h58       h56, h14, none, none  // for d=1
     *    cmt7             cmt8        h18       h56, h14, none, none  // for d=2
     *    cmt7             cmt8        h18_d3    h56, h14, none, none  // d=3, while语句，填充
     *    cmt7             cmt8      h18_d3_d4   h56, h14, none, none  // d=4, while语句，填充
     *  d3 = hash(h0,h0,h0,h0,h0,h0,h0,h0)
     *  d4 = hash(h0,h0,h0,h0,h0,h0,h0,h0,h0,h0,h0,h0,h0,h0,h0,h0)
    */

    return root;
}

// This constructs an authentication path into the tree in the format that the circuit
// wants. The caller provides `filler_hashes` to fill in the uncle subtrees. 获取Merkle路径
template<size_t Depth, typename Hash>
MerklePath IncrementalMerkleTree<Depth, Hash>::path(std::deque<Hash> filler_hashes) const {
    if (!left) {
        throw std::runtime_error("can't create an authentication path for the beginning of the tree");
    }

    PathFiller<Depth, Hash> filler(filler_hashes);

    std::vector<Hash> path;
    std::vector<bool> index;

    /*  left   right    parents0, 1, 2, 3
     *  cmt7   cmt8     h56, h14, none, none 
     * 当前最新的节点为右节点cmt8
     */
    if (right) { // 验证右节点在merkle树上
        index.push_back(true);
        path.push_back(*left);
    } else {   // 验证左节点在merkle树上，此时右节点为空
        index.push_back(false);
        path.push_back(filler.next(0));
    }

    size_t d = 1;

    BOOST_FOREACH(const boost::optional<Hash>& parent, parents) {
        if (parent) {
            index.push_back(true);
            path.push_back(*parent);
        } else {
            index.push_back(false);
            path.push_back(filler.next(d));
        }

        d++;
    }

    while (d < Depth) {
        index.push_back(false);
        path.push_back(filler.next(d));
        d++;
    }

    std::vector<std::vector<bool>> merkle_path;
    BOOST_FOREACH(Hash b, path)
    {
        std::vector<unsigned char> hashv(b.begin(), b.end());
        std::vector<bool> tmp_b;

        convertBytesVectorToVector(hashv, tmp_b);

        merkle_path.push_back(tmp_b);
    }

    std::reverse(merkle_path.begin(), merkle_path.end()); // 由逆序转换为正序，即从root到leaf
    std::reverse(index.begin(), index.end());

    return MerklePath(merkle_path, index); // 返回MerklePath实例
}

// 获取部分路径
template<size_t Depth, typename Hash>
std::deque<Hash> IncrementalWitness<Depth, Hash>::partial_path() const {
    std::deque<Hash> uncles(filled.begin(), filled.end());

    if (cursor) { // IncrementalMerkleTree的光标
        uncles.push_back(cursor->root(cursor_depth));
    }

    return uncles;
}

// witness追加bucket_commitment
template<size_t Depth, typename Hash>
void IncrementalWitness<Depth, Hash>::append(Hash obj) {
    if (cursor) {
        cursor->append(obj);

        if (cursor->is_complete(cursor_depth)) {
            filled.push_back(cursor->root(cursor_depth));
            cursor = boost::none;
        }
    } else {
        cursor_depth = tree.next_depth(filled.size());

        if (cursor_depth >= Depth) {
            throw std::runtime_error("tree is full");
        }

        if (cursor_depth == 0) {
            filled.push_back(obj);
        } else {
            cursor = IncrementalMerkleTree<Depth, Hash>();
            cursor->append(obj);
        }
    }
}

template class IncrementalMerkleTree<INCREMENTAL_MERKLE_TREE_DEPTH, SHA256Compress>; // 20层， sha256
template class IncrementalMerkleTree<INCREMENTAL_MERKLE_TREE_DEPTH_TESTING, SHA256Compress>;

template class IncrementalWitness<INCREMENTAL_MERKLE_TREE_DEPTH, SHA256Compress>;
template class IncrementalWitness<INCREMENTAL_MERKLE_TREE_DEPTH_TESTING, SHA256Compress>;

} // end namespace `libvnt`

#endif //