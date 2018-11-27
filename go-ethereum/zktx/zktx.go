package zktx

/*
#cgo LDFLAGS: -L/usr/local/lib -lzk_mint -lzk_redeem -lff -lzm -lsnark -lstdc++  -lgmp -lgmpxx
#include "mintcgo.hpp"
#include "redeemcgo.hpp"
#include <stdlib.h>
*/
import "C"
import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"unsafe"

	"github.com/ethereum/go-ethereum/crypto/ecies"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type Sequence struct {
	SN     *common.Hash
	CMT    *common.Hash
	Random *common.Hash
	Value  uint64
	Valid  bool
	Lock   sync.Mutex
}

var SequenceNumber = InitializeSN()
var SequenceNumberAfter *Sequence = nil
var SNS *Sequence = nil
var ZKTxAddress = common.HexToAddress("ffffffffffffffffffffffffffffffffffffffff")

var ErrSequence = errors.New("invalid sequence")
var RandomReceiverPK *ecdsa.PublicKey = nil

func InitializeSN() *Sequence {
	sn := &common.Hash{}
	r := &common.Hash{}
	cmt := GenCMT(0, sn.Bytes(), r.Bytes())
	return &Sequence{
		SN:     sn,
		CMT:    cmt,
		Random: r,
		Value:  0,
	}
}

func NewRandomHash() *common.Hash {
	uuid := make([]byte, 32)
	io.ReadFull(rand.Reader, uuid)
	hash := common.BytesToHash(uuid)
	return &hash
}

func NewRandomAddress() *common.Address {
	uuid := make([]byte, 20)
	io.ReadFull(rand.Reader, uuid)
	addr := common.BytesToAddress(uuid)
	return &addr
}

func NewRandomInt() *big.Int {
	uuid := make([]byte, 32)
	io.ReadFull(rand.Reader, uuid)
	r := big.NewInt(0)
	r.SetBytes(uuid)
	return r
}

// func VerifyMintProof(cmtold *common.Hash, snaold *common.Hash, cmtnew *common.Hash, value uint64, balance uint64, proof []byte) error {
// 	return nil
// }

var InvalidMintProof = errors.New("Verifying mint proof failed!!!")

func VerifyMintProof(cmtold *common.Hash, snaold *common.Hash, cmtnew *common.Hash, value uint64, balance uint64, proof []byte) error {
	fmt.Println("prooflen=", len(proof))
	cproof := C.CString(string(proof))
	cmtA_old_c := C.CString(common.ToHex(cmtold[:]))
	cmtA_c := C.CString(common.ToHex(cmtnew[:]))
	sn_old_c := C.CString(string(snaold.Bytes()[:]))
	value_s_c := C.ulong(value)
	balance_c := C.ulong(balance)
	tf := C.verifyMintproof(cproof, cmtA_old_c, sn_old_c, cmtA_c, value_s_c, balance_c)
	if tf == false {
		return InvalidMintProof
	}
	return nil
}

func VerifySendProof(sna *common.Hash, cmts *common.Hash, proof []byte) error {
	return nil
}

func VerifyUpdateProof(cmta *common.Hash, rtmcmt []byte, cmtnew *common.Hash, proof []byte) error {
	return nil
}

func VerifyDepositProof(x *big.Int, y *big.Int, rtcmt *common.Hash, cmtb *common.Hash, snb *common.Hash, cmtbnew *common.Hash, proof []byte) error {
	return nil
}

var InvalidRedeemProof = errors.New("Verifying redeem proof failed!!!")

func VerifyRedeemProof(cmtold *common.Hash, snaold *common.Hash, cmtnew *common.Hash, value uint64, proof []byte) error {
	cproof := C.CString(string(proof))
	cmtA_old_c := C.CString(common.ToHex(cmtold[:]))
	cmtA_c := C.CString(common.ToHex(cmtnew[:]))
	sn_old_c := C.CString(string(snaold.Bytes()[:]))
	value_s_c := C.ulong(value)

	tf := C.verifyRedeemproof(cproof, cmtA_old_c, sn_old_c, cmtA_c, value_s_c)
	if tf == false {
		return InvalidRedeemProof
	}
	return nil
}

func VerifyDepositSIG(x *big.Int, y *big.Int, sig []byte) error {
	return nil
}

func GenCMT(value uint64, sn []byte, r []byte) *common.Hash {
	value_c := C.ulong(value)
	sn_string := string(sn[:])
	sn_c := C.CString(sn_string)
	defer C.free(unsafe.Pointer(sn_c))
	r_string := string(r[:])
	r_c := C.CString(r_string)
	defer C.free(unsafe.Pointer(r_c))

	cmtA_c := C.genCMT(value_c, sn_c, r_c)
	cmtA_go := C.GoString(cmtA_c)
	//res := []byte(cmtA_go)
	res, _ := hex.DecodeString(cmtA_go)
	reshash := common.BytesToHash(res)
	return &reshash
}

func GenCMTS(value uint64, pkX *big.Int, pkY *big.Int, sns []byte, rs []byte, sna []byte) *common.Hash {
	//add value
	all := make([]byte, 8)
	binary.BigEndian.PutUint64(all[0:8], value)
	//add pkx
	x := pkX.Bytes()
	all = append(all, x...)
	//add pky
	y := pkY.Bytes()
	all = append(all, y...)
	//add sns rs sna
	all = append(all, sns...)
	all = append(all, rs...)
	all = append(all, sna...)
	//sha256
	h := sha256.New()
	h.Write(all)
	res := h.Sum(nil)
	//bytestohash
	hash := common.BytesToHash(res)
	return &hash

}

func ComputeR(sk *big.Int) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{} //tbd
}

func Encrypt(pub *ecdsa.PublicKey, m []byte) ([]byte, error) {
	P := ecies.ImportECDSAPublic(pub)
	ke := P.X.Bytes()
	ke = ke[:16]
	ct, err := ecies.SymEncrypt(rand.Reader, P.Params, ke, m)

	return ct, err
}

func Decrypt(pub *ecdsa.PublicKey, ct []byte) ([]byte, error) {
	P := ecies.ImportECDSAPublic(pub)
	ke := P.X.Bytes()
	ke = ke[:16]
	m, err := ecies.SymDecrypt(P.Params, ke, ct)
	return m, err
}

type AUX struct {
	Value uint64
	SNs   *common.Hash
	Rs    *common.Hash
	SNa   *common.Hash
}

func ComputeAUX(randomReceiverPK *ecdsa.PublicKey, value uint64, SNs *common.Hash, Rs *common.Hash, SNa *common.Hash) []byte {
	aux := AUX{
		Value: value,
		SNs:   SNs,
		Rs:    Rs,
		SNa:   SNa,
	}
	bytes, _ := rlp.EncodeToBytes(aux)
	encbytes, _ := Encrypt(randomReceiverPK, bytes)
	return encbytes
}

func DecAUX(key *ecdsa.PublicKey, data []byte) (uint64, *common.Hash, *common.Hash, *common.Hash) {
	decdata, _ := Decrypt(key, data)
	aux := AUX{}
	r := bytes.NewReader(decdata)

	s := rlp.NewStream(r, 0)
	if err := s.Decode(aux); err != nil {
		return 0, nil, nil, nil
	}
	return aux.Value, aux.SNs, aux.Rs, aux.SNa
}

func GenerateKeyForRandomB(R *ecdsa.PublicKey, kB *ecdsa.PrivateKey) *ecdsa.PrivateKey {
	//skB*R
	c := kB.PublicKey.Curve
	tx, ty := c.ScalarMult(R.X, R.Y, kB.D.Bytes())
	tmp := tx.Bytes()
	tmp = append(tmp, ty.Bytes()...)
	//生成hash值H(skB*R)
	h := sha256.New()
	h.Write([]byte(tmp))
	bs := h.Sum(nil)

	i := new(big.Int)
	i = i.SetBytes(bs)
	//生成公钥
	sx, sy := c.ScalarBaseMult(bs)
	sskB := new(ecdsa.PrivateKey)
	sskB.PublicKey.X, sskB.PublicKey.Y = c.Add(sx, sy, kB.PublicKey.X, kB.PublicKey.Y)
	sskB.Curve = c
	//生成私钥
	sskB.D = i.Add(i, kB.D)
	return sskB
}

// func GenMintProof(ValueOld uint64, RAold *common.Hash, SNAnew *common.Hash, RAnew *common.Hash, CMTold *common.Hash, SNold *common.Hash, CMTnew *common.Hash, ValueNew uint64, balance uint64) []byte {
// 	return []byte{}
// }
func GenMintProof(ValueOld uint64, RAold *common.Hash, SNAnew *common.Hash, RAnew *common.Hash, CMTold *common.Hash, SNold *common.Hash, CMTnew *common.Hash, ValueNew uint64, balance uint64) []byte {
	value_c := C.ulong(ValueNew)     //转换后零知识余额对应的明文余额
	value_old_c := C.ulong(ValueOld) //转换前零知识余额对应的明文余额

	sn_old_c := C.CString(string(SNold.Bytes()[:]))
	r_old_c := C.CString(string(RAold.Bytes()[:]))
	sn_c := C.CString(string(SNAnew.Bytes()[:]))
	r_c := C.CString(string(RAnew.Bytes()[:]))

	cmtA_old_c := C.CString(common.ToHex(CMTold[:])) //对于CMT  需要将每一个byte拆为两个16进制字符
	cmtA_c := C.CString(common.ToHex(CMTnew[:]))

	value_s_c := C.ulong(ValueNew - ValueOld) //需要被转换的明文余额
	balance_c := C.ulong(balance)

	cproof := C.genMintproof(value_c, value_old_c, sn_old_c, r_old_c, sn_c, r_c, cmtA_old_c, cmtA_c, value_s_c, balance_c)

	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

func GenSendProof(CMTA *common.Hash, ValueA uint64, RA *common.Hash, ValueS uint64, PKX *big.Int, PKY *big.Int, SNS *common.Hash, RS *common.Hash, SNA *common.Hash, CMTS *common.Hash) []byte {
	return []byte{}
}

func GenUpdateProof(CMTS *common.Hash, ValueS uint64, PKX *big.Int, PKY *big.Int, SNS *common.Hash, RS *common.Hash, SNA *common.Hash, ValueA uint64, RA *common.Hash, SNAnew *common.Hash, RAnew *common.Hash, CMTA *common.Hash, RTcmt []byte, CMTAnew *common.Hash) []byte {
	return []byte{}
}

func GenDepositProof(CMTS *common.Hash, ValueS uint64, SNS *common.Hash, RS *common.Hash, SNA *common.Hash, ValueB uint64, RB *common.Hash, SNBnew *common.Hash, RBnew *common.Hash, PKX *big.Int, PKY *big.Int, RTcmt []byte, CMTB *common.Hash, SNB *common.Hash, CMTBnew *common.Hash) []byte {
	return []byte{}
}

func GenRedeemProof(ValueOld uint64, RAold *common.Hash, SNAnew *common.Hash, RAnew *common.Hash, CMTold *common.Hash, SNold *common.Hash, CMTnew *common.Hash, ValueNew uint64) []byte {
	value_c := C.ulong(ValueNew)     //转换后零知识余额对应的明文余额
	value_old_c := C.ulong(ValueOld) //转换前零知识余额对应的明文余额

	sn_old_c := C.CString(string(SNold.Bytes()[:]))
	r_old_c := C.CString(string(RAold.Bytes()[:]))
	sn_c := C.CString(string(SNAnew.Bytes()[:]))
	r_c := C.CString(string(RAnew.Bytes()[:]))

	cmtA_old_c := C.CString(common.ToHex(CMTold[:])) //对于CMT  需要将每一个byte拆为两个16进制字符
	cmtA_c := C.CString(common.ToHex(CMTnew[:]))

	value_s_c := C.ulong(ValueOld - ValueNew) //需要被转换的明文余额

	cproof := C.genRedeemproof(value_c, value_old_c, sn_old_c, r_old_c, sn_c, r_c, cmtA_old_c, cmtA_c, value_s_c)

	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

func GenR() *ecdsa.PrivateKey {
	Ka, err := crypto.GenerateKey()
	if err != nil {
		return nil
	}
	return Ka
}

func NewRandomPubKey(sA *big.Int, pkB ecdsa.PublicKey) *ecdsa.PublicKey {
	//sA*pkB
	c := pkB.Curve
	tx, ty := c.ScalarMult(pkB.X, pkB.Y, sA.Bytes())
	tmp := tx.Bytes()
	tmp = append(tmp, ty.Bytes()...)
	//生成hash值H(sA*pkB)
	h := sha256.New()
	h.Write([]byte(tmp))
	bs := h.Sum(nil)
	//生成用于加密的公钥H(sA*pkB)P+pkB
	sx, sy := c.ScalarBaseMult(bs)
	spkB := new(ecdsa.PublicKey)
	spkB.X, spkB.Y = c.Add(sx, sy, pkB.X, pkB.Y)
	spkB.Curve = c
	return spkB
}
