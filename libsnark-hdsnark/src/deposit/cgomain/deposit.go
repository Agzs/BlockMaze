package main

/*
#cgo LDFLAGS: -L/usr/local/lib -lzk_update -lff -lzm -lsnark -lstdc++  -lgmp -lgmpxx
#include "../updatecgo.hpp"
#include <stdlib.h>
*/
import "C"
import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// //-lzm -lff -lsnark  //export LD_LIBRARY_PATH=/usr/local/lib
// func main() {
// 	valuea := uint64(20) //转换后零知识余额对应的明文余额

// 	values := uint64(7) //转换前零知识余额对应的明文余额

// 	sna := NewRandomHash()
// 	ra := NewRandomHash()
// 	sns := NewRandomHash()
// 	rs := NewRandomHash()
// 	pri, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	pk := pri.Public()

// 	cmta := GenCMT(valuea, sna.Bytes(), ra.Bytes())
// 	cmts := GenCMTS(values, &pk, sns.Bytes(), rs.Bytes(), sna.Bytes())

// 	proof := GenUpdateProof(cmta, valuea, ra, values, &pk, sns, rs, sna, cmts)
// 	//fmt.Println("proof=", proof)
// 	tf := VerifyUpdateProof(sna, cmts, proof)
// 	fmt.Println(tf)

func main() {
	valuea := uint64(20) //转换后零知识余额对应的明文余额

	sna := NewRandomHash()
	ra := NewRandomHash()

	cmta := GenCMT(valuea, sna.Bytes(), ra.Bytes())

	fmt.Println("cmta=", len(cmta))
	fmt.Println("cmtstring=", len(common.ToHex(cmta[:])))
	var CMTSForMerkle []*common.Hash
	for i := 0; i < 4; i++ {
		CMTSForMerkle = append(CMTSForMerkle, cmta)
	}
	rt := GenRT(cmta, CMTSForMerkle)
	fmt.Println("rt=", rt)
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
	res, _ := hex.DecodeString(cmtA_go) //返回32长度 []byte  一个byte代表两位16进制数
	reshash := common.BytesToHash(res)  //32长度byte数组
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

func GenRT(CMTS *common.Hash, CMTSForMerkle []*common.Hash) common.Hash {
	fmt.Println("cmts=", CMTS)
	fmt.Println("cmtsmerkel=", CMTSForMerkle)
	cmtS_c := C.CString(common.ToHex(CMTS[:]))
	var cmtArray string
	for i := 0; i < len(CMTSForMerkle); i++ {
		s := string(common.ToHex(CMTSForMerkle[i][:]))
		cmtArray += s
	}
	fmt.Println("cmtarray=", cmtArray)
	cmtsM := C.CString(cmtArray)
	rtC := C.genRoot(cmtS_c, cmtsM, 4) //--zy
	rtGo := C.GoString(rtC)

	res, _ := hex.DecodeString(rtGo)   //返回32长度 []byte  一个byte代表两位16进制数
	reshash := common.BytesToHash(res) //32长度byte数组
	return reshash
}

//CMTS *common.Hash, ValueS uint64, SNS *common.Hash, RS *common.Hash, SNA *common.Hash, ValueB uint64, RB *common.Hash, SNBnew *common.Hash, RBnew *common.Hash, PKX *big.Int, PKY *big.Int, RTcmt []byte, CMTB *common.Hash, SNB *common.Hash, CMTBnew *common.Hash, CMTSForMerkle []*common.Hash
func GenDepositProof(CMTS *common.Hash, ValueS uint64, SNS *common.Hash, RS *common.Hash, SNA *common.Hash, ValueB uint64, RB *common.Hash, SNBnew *common.Hash, RBnew *common.Hash, pk *ecdsa.PublicKey, RTcmt []byte, CMTB *common.Hash, CMTBnew *common.Hash, CMTSForMerkle []*common.Hash, n int) []byte {
	cmtS_c := C.CString(common.ToHex(CMTS[:]))
	valueS_c := C.ulong(ValueS)
	PK := crypto.PubkeyToAddress(*pk)
	pk_c := C.CString(string(PK.Bytes()[:]))
	SNS_c := C.CString(string(SNS.Bytes()[:])) //--zy
	RS_c := C.CString(string(RS.Bytes()[:]))   //--zy
	SNA_c := C.CString(string(SNA.Bytes()[:]))
	valueA_c := C.ulong(ValueA)
	RA_c := C.CString(string(RA.Bytes()[:])) //rA_c := C.CString(string(RA.Bytes()[:]))
	SNAnew_c := C.CString(string(SNAnew.Bytes()[:]))
	RAnew_c := C.CString(string(RAnew.Bytes()[:]))
	cmtA_c := C.CString(common.ToHex(CMTA[:]))
	RT_c := C.CString(common.ToHex(RTcmt)) //--zy

	cmtAnew_c := C.CString(common.ToHex(CMTAnew[:]))
	valueANew_c := C.ulong(ValueA - ValueS)
	var cmtArray string
	for i := 0; i < len(CMTSForMerkle); i++ {
		s := string(CMTSForMerkle[i].Bytes()[:])
		cmtArray += s

	}
	cmtsM := C.CString(cmtArray)
	nC := C.int(n)
	cproof := C.genUpdateproof(valueANew_c, valueA_c, SNA_c, RA_c, SNAnew_c, RAnew_c, SNS_c, RS_c, cmtA_c, cmtAnew_c, valueS_c, pk_c, cmtS_c, cmtsM, nC, RT_c)
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

func VerifyUpdateProof(cmta *common.Hash, rtmcmt []byte, cmtnew *common.Hash, proof []byte) error {
	cproof := C.CString(string(proof))
	rtmCmt := C.CString(common.ToHex(rtmcmt))
	cmtA := C.CString(common.ToHex(cmta[:]))
	cmtAnew := C.CString(common.ToHex(cmtnew[:]))

	tf := C.verifyUpdateproof(cproof, rtmCmt, cmtA, cmtAnew)
	if tf == false {
		return errors.New("Verifying update proof failed!!!")
	}
	return nil
}

//d4caa1e06719eab53eed5be33792d4d7cbbedbf1a9e8e8d35b0cb678eb20549e
