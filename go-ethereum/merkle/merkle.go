package merkle

import (
	"crypto/sha256"

	"github.com/ethereum/go-ethereum/common"
)

var emptyRoot = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

type MerkleTree struct {
	MerkleRoot *MerkleNode
}

type MerkleNode struct {
	Data  []byte
	Left  *MerkleNode
	Right *MerkleNode
}

func NewMerkleNode(data []byte, left, right *MerkleNode) *MerkleNode {
	mNode := MerkleNode{}

	// 如果是叶子节点，则会有 data 值，如果不是叶子节点，则将左右子树的 data 值哈希为自己的 data
	if left == nil && right == nil {
		hash := sha256.Sum256(data)
		mNode.Data = hash[:]
	} else {
		data := append(left.Data, right.Data...)
		hash := sha256.Sum256(data)
		mNode.Data = hash[:]
	}

	mNode.Left = left
	mNode.Right = right

	return &mNode
}

func NewMerkleTree(data [][]byte) *MerkleTree {
	if len(data)%2 != 0 {
		data = append(data, data[len(data)-1])
	}
	// 将交易构造为 Merkle 节点
	var nodes []MerkleNode

	for _, perData := range data {
		node := NewMerkleNode(perData, nil, nil)
		nodes = append(nodes, *node)
	}

	// 构造 Merkle 树
	for i := 0; i < len(data)/2; i++ {
		var newLevelNodes []MerkleNode
		if len(nodes)%2 != 0 {
			nodes = append(nodes, nodes[len(nodes)-1])
		}
		for j := 0; j < len(nodes); j += 2 {
			node := NewMerkleNode(nil, &nodes[j], &nodes[j+1])
			newLevelNodes = append(newLevelNodes, *node)
		}

		nodes = newLevelNodes
		if len(nodes) == 1 {
			break
		}
	}

	mTree := MerkleTree{&nodes[0]}

	return &mTree
}

func CMTRoot(cmt []*common.Hash) common.Hash {
	if cmt == nil || len(cmt) == 0 {
		return emptyRoot
	}
	var data [][]byte
	for _, hash := range cmt {
		data = append(data, hash.Bytes())
	}
	root := NewMerkleTree(data)
	return common.BytesToHash(root.MerkleRoot.Data)
}

func quickSort(values []uint64, left, right int) {
	temp := values[left]
	p := left
	i, j := left, right
	for i <= j {
		for j >= p && values[j] >= temp {
			j--
		}
		if j >= p {
			values[p] = values[j]
			p = j
		}
		for i <= p && values[i] <= temp {
			i++
		}
		if i <= p {
			values[p] = values[i]
			p = i
		}
	}
	values[p] = temp
	if p-left > 1 {
		quickSort(values, left, p-1)
	}
	if right-p > 1 {
		quickSort(values, p+1, right)
	}
}

func QuickSortUint64(values []uint64) {

	quickSort(values, 0, len(values)-1)

}
