package main

/*
#cgo LDFLAGS: -L/usr/local/lib -lzk_send -lff -lzm -lsnark -lstdc++  -lgmp -lgmpxx
#include "../sendcgo.hpp"
#include <stdlib.h>
*/
import "C"
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

//-lzm -lff -lsnark  //export LD_LIBRARY_PATH=/usr/local/lib
func main() {
	valuea := uint64(20) //转换后零知识余额对应的明文余额

	values := uint64(7) //转换前零知识余额对应的明文余额

	sna := NewRandomHash()
	ra := NewRandomHash()
	sns := NewRandomHash()
	rs := NewRandomHash()
	pri, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk := pri.Public()

	cmta := GenCMT(valuea, sna.Bytes(), ra.Bytes())
	cmts := GenCMTS(values, &pk, sns.Bytes(), rs.Bytes(), sna.Bytes())

	proof := GenSendProof(cmta, valuea, ra, values, &pk, sns, rs, sna, cmts)
	//fmt.Println("proof=", proof)
	tf := VerifySendProof(sna, cmts, proof)
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

//GenCMTS返回 HASH   value uint64, pkX *big.Int, pkY *big.Int, sns []byte, rs []byte, sna []byte
func GenCMTS(values uint64, pk *ecdsa.PublicKey, sns []byte, rs []byte, sna []byte) *common.Hash {

	values_c := C.ulong(values)
	PK := crypto.PubkeyToAddress(*pk)
	pk_c := C.CString(string(PK.Bytes()[:]))
	sns_string := string(sns[:])
	sns_c := C.CString(sns_string)
	defer C.free(unsafe.Pointer(sns_c))
	rs_string := string(rs[:])
	rs_c := C.CString(rs_string)
	defer C.free(unsafe.Pointer(rs_c))
	sna_string := string(sna[:])
	sna_c := C.CString(sna_string)
	defer C.free(unsafe.Pointer(sna_c))
	//uint64_t value_s,char* pk_string,char* sn_s_string,char* r_s_string,char *sn_old_string
	cmtA_c := C.genCMTS(values_c, pk_c, sns_c, rs_c, sna_c) //64长度16进制数
	cmtA_go := C.GoString(cmtA_c)
	//res := []byte(cmtA_go)
	res, _ := hex.DecodeString(cmtA_go)
	reshash := common.BytesToHash(res) //32长度byte数组
	return &reshash
}

//CMTA *common.Hash, ValueA uint64, RA *common.Hash, ValueS uint64, PKX *big.Int, PKY *big.Int, SNS *common.Hash, RS *common.Hash, SNA *common.Hash, CMTS *common.Hash
func GenSendProof(CMTA *common.Hash, ValueA uint64, RA *common.Hash, ValueS uint64, pk *ecdsa.PublicKey, SNS *common.Hash, RS *common.Hash, SNA *common.Hash, CMTS *common.Hash) []byte {
	cmtA_c := C.CString(common.ToHex(CMTA[:]))
	valueA_c := C.ulong(ValueA)
	rA_c := C.CString(string(RA.Bytes()[:]))
	valueS := C.ulong(ValueS)
	PK := crypto.PubkeyToAddress(*pk)
	pk_c := C.CString(string(PK.Bytes()[:]))
	snS := C.CString(string(SNS.Bytes()[:]))
	rS := C.CString(string(RS.Bytes()[:]))
	snA := C.CString(string(SNA.Bytes()[:]))
	cmtS := C.CString(common.ToHex(CMTS[:]))
	//uint64_t value_A,char* sn_s_string,char* r_s_string,char* sn_string,char* r_string,char* cmt_s_string, char* cmtA_string,
	//uint64_t value_s,char* pk_string
	cproof := C.genSendproof(valueA_c, snS, rS, snA, rA_c, cmtS, cmtA_c, valueS, pk_c)
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

// func pubkeyToAddress(p *ecdsa.PublicKey) common.Address {
// 	pubBytes := crypto.FromECDSAPub(p)
// 	return common.BytesToAddress(crypto.Keccak256(pubBytes[1:])[12:])
// }

//sna *common.Hash, cmts *common.Hash, proof []byte
//char *data, char* sn_old_string, char* cmtS_string
func VerifySendProof(sna *common.Hash, cmts *common.Hash, proof []byte) error {
	cproof := C.CString(string(proof))
	snA := C.CString(string(sna.Bytes()[:]))
	cmtS := C.CString(common.ToHex(cmts[:]))

	tf := C.verifySendproof(cproof, snA, cmtS)
	if tf == false {
		return errors.New("Verifying send proof failed!!!")
	}
	return nil
}
