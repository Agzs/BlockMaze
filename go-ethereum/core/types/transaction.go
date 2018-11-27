// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"container/heap"
	"errors"
	"io"
	"math/big"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

//go:generate gencodec -type txdata -field-override txdataMarshaling -out gen_tx_json.go

var (
	ErrInvalidSig = errors.New("invalid transaction v, r, s values")
)

// Type of transaction using code --Agzs 09.17
const (
	PublicTx  uint8 = 0x00
	MintTx    uint8 = 0x01
	SendTx    uint8 = 0x02
	DepositTx uint8 = 0x03
	UpdateTx  uint8 = 0x04
	RedeemTx  uint8 = 0x05
)

// Type of transaction using string --Agzs 09.17
var PublicTxStr string = "Public Transaction"
var MintTxStr string = "Mint Transaction"
var SendTxStr string = "Send Transaction"
var DepositTxStr string = "Deposit Transaction"
var UpdateTxStr string = "Update Transaction"
var RedeemTxStr string = "Redeem Transaction"

type Transaction struct {
	data txdata
	// caches
	hash atomic.Value
	size atomic.Value
	from atomic.Value
}

type txdata struct {
	Code         uint8           `json:"code"     gencodec:"required"` // differ txs --Agzs 09.17
	AccountNonce uint64          `json:"nonce"    gencodec:"required"`
	Price        *big.Int        `json:"gasPrice" gencodec:"required"`
	GasLimit     uint64          `json:"gas"      gencodec:"required"`
	Recipient    *common.Address `json:"to"       rlp:"nil"` // nil means contract creation
	Amount       *big.Int        `json:"value"    gencodec:"required"`
	Payload      []byte          `json:"input"    gencodec:"required"`

	ZKValue   uint64
	ZKSN      *common.Hash
	ZKNounce  uint64
	ZKAdrress *common.Address
	ZKCMT     *common.Hash
	ZKProof   []byte
	//	CMTProof  []byte
	AUX []byte
	X   *big.Int
	Y   *big.Int

	//depostiTx signature values
	DepositTxV *big.Int
	DepositTxR *big.Int
	DepositTxS *big.Int

	// Signature values
	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`

	// This is only used when marshaling to JSON.
	Hash *common.Hash `json:"hash" rlp:"-"`
}

type txdataMarshaling struct {
	Code         uint8 // differ txs --Agzs 09.18
	AccountNonce hexutil.Uint64
	Price        *hexutil.Big
	GasLimit     hexutil.Uint64
	Amount       *hexutil.Big
	Payload      hexutil.Bytes
	V            *hexutil.Big
	R            *hexutil.Big
	S            *hexutil.Big
}

func NewTransaction(nonce uint64, to common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *Transaction {
	return newTransaction(nonce, &to, amount, gasLimit, gasPrice, data)
}

func NewContractCreation(nonce uint64, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *Transaction {
	return newTransaction(nonce, nil, amount, gasLimit, gasPrice, data)
}

func newTransaction(nonce uint64, to *common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *Transaction {
	if len(data) > 0 {
		data = common.CopyBytes(data)
	}
	d := txdata{
		Code:         PublicTx, // default for public transaction --Agzs 09.17
		AccountNonce: nonce,
		Recipient:    to,
		Payload:      data,
		Amount:       new(big.Int),
		GasLimit:     gasLimit,
		Price:        new(big.Int),
		V:            new(big.Int),
		R:            new(big.Int),
		S:            new(big.Int),
		X:            new(big.Int),
		Y:            new(big.Int),
	}
	if amount != nil {
		d.Amount.Set(amount)
	}
	if gasPrice != nil {
		d.Price.Set(gasPrice)
	}

	return &Transaction{data: d}
}

// ChainId returns which chain id this transaction was signed for (if at all)
func (tx *Transaction) ChainId() *big.Int {
	return deriveChainId(tx.data.V)
}

// Protected returns whether the transaction is protected from replay protection.
func (tx *Transaction) Protected() bool {
	return isProtectedV(tx.data.V)
}

func isProtectedV(V *big.Int) bool {
	if V.BitLen() <= 8 {
		v := V.Uint64()
		return v != 27 && v != 28
	}
	// anything not 27 or 28 are considered unprotected
	return true
}

// EncodeRLP implements rlp.Encoder
func (tx *Transaction) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, &tx.data)
}

// DecodeRLP implements rlp.Decoder
func (tx *Transaction) DecodeRLP(s *rlp.Stream) error {
	_, size, _ := s.Kind()
	err := s.Decode(&tx.data)
	if err == nil {
		tx.size.Store(common.StorageSize(rlp.ListSize(size)))
	}

	return err
}

// MarshalJSON encodes the web3 RPC transaction format.
func (tx *Transaction) MarshalJSON() ([]byte, error) {
	hash := tx.Hash()
	data := tx.data
	data.Hash = &hash
	return data.MarshalJSON()
}

// UnmarshalJSON decodes the web3 RPC transaction format.
func (tx *Transaction) UnmarshalJSON(input []byte) error {
	var dec txdata
	if err := dec.UnmarshalJSON(input); err != nil {
		return err
	}
	var V byte
	if isProtectedV(dec.V) {
		chainID := deriveChainId(dec.V).Uint64()
		V = byte(dec.V.Uint64() - 35 - 2*chainID)
	} else {
		V = byte(dec.V.Uint64() - 27)
	}
	if !crypto.ValidateSignatureValues(V, dec.R, dec.S, false) {
		return ErrInvalidSig
	}
	*tx = Transaction{data: dec}
	return nil
}

func (tx *Transaction) Code() uint8             { return tx.data.Code }
func (tx *Transaction) Data() []byte            { return common.CopyBytes(tx.data.Payload) }
func (tx *Transaction) Gas() uint64             { return tx.data.GasLimit }
func (tx *Transaction) GasPrice() *big.Int      { return new(big.Int).Set(tx.data.Price) }
func (tx *Transaction) SetValue(value *big.Int) { tx.data.Amount = value }
func (tx *Transaction) Value() *big.Int         { return new(big.Int).Set(tx.data.Amount) }
func (tx *Transaction) Nonce() uint64           { return tx.data.AccountNonce }
func (tx *Transaction) SetNonce(n uint64)       { tx.data.AccountNonce = n }
func (tx *Transaction) CheckNonce() bool        { return true }

// SetDefaultCode sets the transactoion's type code. --Agzs 09.18

func (tx *Transaction) ZKValue() uint64 {
	return tx.data.ZKValue
}

func (tx *Transaction) SetZKValue(Value uint64) {
	tx.data.ZKValue = Value
}

func (tx *Transaction) TxCode() uint8 {
	return tx.data.Code
}

func (tx *Transaction) SetTxCode(code uint8) {
	tx.data.Code = code
}

//
func (tx *Transaction) SetTxRecepient(address *common.Address) {
	tx.data.Recipient = address
}

//
func (tx *Transaction) ZKAddress() *common.Address {
	return tx.data.ZKAdrress
}

//
func (tx *Transaction) SetZKAddress(address *common.Address) {
	tx.data.ZKAdrress = address
}

//
func (tx *Transaction) SetZKNounce(nounce uint64) {
	tx.data.ZKNounce = nounce
}

//
func (tx *Transaction) ZKSN() *common.Hash {
	return tx.data.ZKSN
}

//
func (tx *Transaction) SetZKSN(hash *common.Hash) {
	tx.data.ZKSN = hash
}

//
func (tx *Transaction) R() (*big.Int, *big.Int) {
	return tx.data.X, tx.data.Y
}

//
func (tx *Transaction) X() *big.Int {
	return tx.data.X

}

//
func (tx *Transaction) Y() *big.Int {
	return tx.data.Y

}

//
func (tx *Transaction) SetPubKey(x *big.Int, y *big.Int) {
	tx.data.X = x
	tx.data.Y = y
}

//
func (tx *Transaction) ZKCMT() *common.Hash {
	return tx.data.ZKCMT
}

//
func (tx *Transaction) SetZKCMT(hash *common.Hash) {
	tx.data.ZKCMT = hash
}

//
func (tx *Transaction) AUX() []byte {
	return tx.data.AUX
}

//
func (tx *Transaction) SetAUX(AUX []byte) {
	tx.data.AUX = make([]byte, 0)
	copy(tx.data.AUX[:], AUX[:])
}

//
func (tx *Transaction) ZKProof() []byte {
	return tx.data.ZKProof
}

//
func (tx *Transaction) SetZKProof(proof []byte) {
	tx.data.ZKProof = make([]byte, len(proof))
	copy(tx.data.ZKProof[:], proof[:])
}

/*
func (tx *Transaction) CMTProof() []byte {
	return tx.data.CMTProof
}


func (tx *Transaction) SetCMTProof(proof []byte) {
	tx.data.CMTProof = make([]byte, 0)
	copy(tx.data.CMTProof[:], proof[:])
}

*/
func (tx *Transaction) SetPrice(price *big.Int) {
	tx.data.Price = price
}

// GetTxCode returns the transactoion's type code. --Agzs 09.18
func (tx *Transaction) GetTxCodeStr() string {
	if tx.Code() == PublicTx {
		return PublicTxStr
	} else if tx.Code() == MintTx {
		return MintTxStr
	} else if tx.Code() == SendTx {
		return SendTxStr
	} else if tx.Code() == DepositTx {
		return DepositTxStr
	} else if tx.Code() == UpdateTx {
		return UpdateTxStr
	} else if tx.Code() == RedeemTx {
		return RedeemTxStr
	} else {
		return "invaild transaction"
	}
}

// To returns the recipient address of the transaction.
// It returns nil if the transaction is a contract creation.
func (tx *Transaction) To() *common.Address {
	if tx.data.Recipient == nil {
		return nil
	}
	to := *tx.data.Recipient
	return &to
}

// Hash hashes the RLP encoding of tx.
// It uniquely identifies the transaction.
func (tx *Transaction) Hash() common.Hash {
	if hash := tx.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	v := rlpHash(tx)
	tx.hash.Store(v)
	return v
}

// Size returns the true RLP encoded storage size of the transaction, either by
// encoding and returning it, or returning a previsouly cached value.
func (tx *Transaction) Size() common.StorageSize {
	if size := tx.size.Load(); size != nil {
		return size.(common.StorageSize)
	}
	c := writeCounter(0)
	rlp.Encode(&c, &tx.data)
	tx.size.Store(common.StorageSize(c))
	return common.StorageSize(c)
}

// AsMessage returns the transaction as a core.Message.
//
// AsMessage requires a signer to derive the sender.
//
// XXX Rename message to something less arbitrary?
func (tx *Transaction) AsMessage(s Signer) (Message, error) {
	msg := Message{
		txCode:     tx.data.Code,
		cmt:        tx.data.ZKCMT,
		nonce:      tx.data.AccountNonce,
		gasLimit:   tx.data.GasLimit,
		gasPrice:   new(big.Int).Set(tx.data.Price),
		to:         tx.data.Recipient,
		amount:     tx.data.Amount,
		data:       tx.data.Payload,
		checkNonce: true,
		zkValue:    tx.ZKValue(),
	}

	var err error
	msg.from, err = Sender(s, tx)
	return msg, err
}

// WithSignature returns a new transaction with the given signature.
// This signature needs to be formatted as described in the yellow paper (v+27).
func (tx *Transaction) WithSignature(signer Signer, sig []byte) (*Transaction, error) {
	r, s, v, err := signer.SignatureValues(tx, sig)
	if err != nil {
		return nil, err
	}
	cpy := &Transaction{data: tx.data}
	cpy.data.R, cpy.data.S, cpy.data.V = r, s, v
	return cpy, nil
}

// Cost returns amount + gasprice * gaslimit.
func (tx *Transaction) Cost() *big.Int {
	total := new(big.Int).Mul(tx.data.Price, new(big.Int).SetUint64(tx.data.GasLimit))
	total.Add(total, tx.data.Amount)
	return total
}

func (tx *Transaction) RawSignatureValues() (*big.Int, *big.Int, *big.Int) {
	return tx.data.V, tx.data.R, tx.data.S
}

// Transactions is a Transaction slice type for basic sorting.
type Transactions []*Transaction

// Len returns the length of s.
func (s Transactions) Len() int { return len(s) }

// Swap swaps the i'th and the j'th element in s.
func (s Transactions) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// GetRlp implements Rlpable and returns the i'th element of s in rlp.
func (s Transactions) GetRlp(i int) []byte {
	enc, _ := rlp.EncodeToBytes(s[i])
	return enc
}

// TxDifference returns a new set which is the difference between a and b.
func TxDifference(a, b Transactions) Transactions {
	keep := make(Transactions, 0, len(a))

	remove := make(map[common.Hash]struct{})
	for _, tx := range b {
		remove[tx.Hash()] = struct{}{}
	}

	for _, tx := range a {
		if _, ok := remove[tx.Hash()]; !ok {
			keep = append(keep, tx)
		}
	}

	return keep
}

// TxByNonce implements the sort interface to allow sorting a list of transactions
// by their nonces. This is usually only useful for sorting transactions from a
// single account, otherwise a nonce comparison doesn't make much sense.
type TxByNonce Transactions

func (s TxByNonce) Len() int           { return len(s) }
func (s TxByNonce) Less(i, j int) bool { return s[i].data.AccountNonce < s[j].data.AccountNonce }
func (s TxByNonce) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// TxByPrice implements both the sort and the heap interface, making it useful
// for all at once sorting as well as individually adding and removing elements.
type TxByPrice Transactions

func (s TxByPrice) Len() int           { return len(s) }
func (s TxByPrice) Less(i, j int) bool { return s[i].data.Price.Cmp(s[j].data.Price) > 0 }
func (s TxByPrice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func (s *TxByPrice) Push(x interface{}) {
	*s = append(*s, x.(*Transaction))
}

func (s *TxByPrice) Pop() interface{} {
	old := *s
	n := len(old)
	x := old[n-1]
	*s = old[0 : n-1]
	return x
}

// TransactionsByPriceAndNonce represents a set of transactions that can return
// transactions in a profit-maximizing sorted order, while supporting removing
// entire batches of transactions for non-executable accounts.
type TransactionsByPriceAndNonce struct {
	txs    map[common.Address]Transactions // Per account nonce-sorted list of transactions
	heads  TxByPrice                       // Next transaction for each unique account (price heap)
	signer Signer                          // Signer for the set of transactions
}

// NewTransactionsByPriceAndNonce creates a transaction set that can retrieve
// price sorted transactions in a nonce-honouring way.
//
// Note, the input map is reowned so the caller should not interact any more with
// if after providing it to the constructor.
func NewTransactionsByPriceAndNonce(signer Signer, txs map[common.Address]Transactions) *TransactionsByPriceAndNonce {
	// Initialize a price based heap with the head transactions
	heads := make(TxByPrice, 0, len(txs))
	for from, accTxs := range txs {
		heads = append(heads, accTxs[0])
		// Ensure the sender address is from the signer
		acc, _ := Sender(signer, accTxs[0])
		txs[acc] = accTxs[1:]
		if from != acc {
			delete(txs, from)
		}
	}
	heap.Init(&heads)

	// Assemble and return the transaction set
	return &TransactionsByPriceAndNonce{
		txs:    txs,
		heads:  heads,
		signer: signer,
	}
}

// Peek returns the next transaction by price.
func (t *TransactionsByPriceAndNonce) Peek() *Transaction {
	if len(t.heads) == 0 {
		return nil
	}
	return t.heads[0]
}

// Shift replaces the current best head with the next one from the same account.
func (t *TransactionsByPriceAndNonce) Shift() {
	acc, _ := Sender(t.signer, t.heads[0])
	if txs, ok := t.txs[acc]; ok && len(txs) > 0 {
		t.heads[0], t.txs[acc] = txs[0], txs[1:]
		heap.Fix(&t.heads, 0)
	} else {
		heap.Pop(&t.heads)
	}
}

// Pop removes the best transaction, *not* replacing it with the next one from
// the same account. This should be used when a transaction cannot be executed
// and hence all subsequent ones should be discarded from the same account.
func (t *TransactionsByPriceAndNonce) Pop() {
	heap.Pop(&t.heads)
}

// Message is a fully derived transaction and implements core.Message
//
// NOTE: In a future PR this will be removed.
type Message struct {
	txCode     uint8
	cmt        *common.Hash
	to         *common.Address
	from       common.Address
	nonce      uint64
	amount     *big.Int
	gasLimit   uint64
	gasPrice   *big.Int
	data       []byte
	checkNonce bool
	zkValue    uint64
}

func NewMessage(from common.Address, to *common.Address, code uint8, nonce uint64, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte, checkNonce bool) Message {
	return Message{
		from: from,
		to:   to,
		//code:       code, // differ txs --Agzs 09.18
		nonce:      nonce,
		amount:     amount,
		gasLimit:   gasLimit,
		gasPrice:   gasPrice,
		data:       data,
		checkNonce: checkNonce,
	}
}

func (m Message) From() common.Address { return m.from }
func (m Message) To() *common.Address  { return m.to }
func (m Message) GasPrice() *big.Int   { return m.gasPrice }
func (m Message) Value() *big.Int      { return m.amount }
func (m Message) Gas() uint64          { return m.gasLimit }
func (m Message) Nonce() uint64        { return m.nonce }
func (m Message) Data() []byte         { return m.data }
func (m Message) CheckNonce() bool     { return m.checkNonce }
func (m Message) TxCode() uint8        { return m.txCode }
func (m Message) CMT() *common.Hash    { return m.cmt }
func (m Message) ZKValue() uint64      { return m.zkValue }
