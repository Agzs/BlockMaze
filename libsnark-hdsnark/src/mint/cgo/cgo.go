package main

/*
#cgo LDFLAGS: -L/usr/local/lib -lzk_mint -lff  -lsnark -lstdc++  -lgmp -lgmpxx
#include "../mintcgo.hpp"
#include <stdlib.h>
*/
import "C"
import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
)

//-lzm -lff -lsnark
func main() {
	value_go := uint64(13) //转换后零知识余额对应的明文余额

	value_old_go := uint64(6) //转换前零知识余额对应的明文余额

	balance_go := uint64(30) //明文余额

	sn_old_c := NewRandomHash()
	r_old_c := NewRandomHash()
	sn_c := NewRandomHash()
	r_c := NewRandomHash()

	CMT := GenCMT(value_go, sn_c.Bytes(), r_c.Bytes())
	CMTOld := GenCMT(value_old_go, sn_old_c.Bytes(), r_old_c.Bytes())

	proof := GenMintProof(value_old_go, r_old_c, sn_c, r_c, CMTOld, sn_old_c, CMT, value_go, balance_go)
	//fmt.Println("proof=", proof)
	tf := VerifyMintProof(CMTOld, sn_old_c, CMT, value_go-value_old_go, balance_go, proof)
	fmt.Println(tf)

}
func NewRandomHash() *common.Hash {
	uuid := make([]byte, 32)
	io.ReadFull(rand.Reader, uuid)
	hash := common.BytesToHash(uuid)
	return &hash
}

//GenCMT返回 HASH
func GenCMT(value uint64, sn []byte, r []byte) *common.Hash {
	value_c := C.ulong(value)
	sn_string := string(sn[:])
	sn_c := C.CString(sn_string)
	defer C.free(unsafe.Pointer(sn_c))
	r_string := string(r[:])
	r_c := C.CString(r_string)
	defer C.free(unsafe.Pointer(r_c))

	cmtA_c := C.genCMT(value_c, sn_c, r_c) //64长度16进制数
	cmtA_go := C.GoString(cmtA_c)
	//res := []byte(cmtA_go)
	res, _ := hex.DecodeString(cmtA_go)
	reshash := common.BytesToHash(res) //32长度byte数组
	return &reshash
}

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

//func VerifyMintProof(cmtold *common.Hash, snaold *common.Hash, cmtnew *common.Hash, value uint64, balance uint64, proof []byte) error {
func VerifyMintProof(cmtold *common.Hash, snaold *common.Hash, cmtnew *common.Hash, value uint64, balance uint64, proof []byte) error {
	cproof := C.CString(string(proof))
	cmtA_old_c := C.CString(common.ToHex(cmtold[:]))
	cmtA_c := C.CString(common.ToHex(cmtnew[:]))
	sn_old_c := C.CString(string(snaold.Bytes()[:]))
	value_s_c := C.ulong(value)
	balance_c := C.ulong(balance)
	tf := C.verifyMintproof(cproof, cmtA_old_c, sn_old_c, cmtA_c, value_s_c, balance_c)
	if tf == false {
		return errors.New("Verifying mint proof failed!!!")
	}
	return nil
}
