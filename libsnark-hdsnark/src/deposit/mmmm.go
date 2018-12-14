package main

/*
#cgo LDFLAGS: -L/usr/local/lib  -lzk_deposit -lff  -lsnark -lstdc++  -lgmp -lgmpxx
#include "depositcgo.hpp"
#include <stdlib.h>
*/
import "C"
import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

//SNBnew *common.Hash, RBnew *common.Hash, pk *ecdsa.PublicKey, RTcmt []byte, CMTB *common.Hash, SNB *common.Hash, CMTBnew *common.Hash, CMTSForMerkle []*common.Hash
func main() {
	cmt := []byte{223, 161, 168, 25, 251, 7, 166, 154, 219, 98, 135, 31, 119, 99, 124, 214, 159, 30, 143, 65, 245, 217, 17, 23, 199, 253, 243, 200, 90, 104, 178, 16}

	CMTS := common.BytesToHash(cmt[:])
	ValueS := uint64(80)
	SNS := common.BytesToHash(common.FromHex("0xd620b194a10116cf1b45651823e5c5d039e7be5062ae5be96de7e16e0107a11d"))
	RS := common.BytesToHash(common.FromHex("0x1f3fc954f39b58c2f945b108036f45bed354e57c906ef0804ea9deaf7bd245bf"))
	SNA := common.BytesToHash(common.FromHex("0x633a33dab1d49d5aef5300d6f0875af952352f5fe76923661fb97cf23f777090"))
	ValueB := uint64(0)
	RB := common.BytesToHash(common.FromHex("0x0000000000000000000000000000000000000000000000000000000000000000"))
	SNBnew := common.BytesToHash(common.FromHex("0x83481ff306309f1d74352a4d5b4b4850c18bd75aeeacb10916b16079352488e7"))
	RBnew := common.BytesToHash(common.FromHex("0xde273d88f8002d7bb5b88576f77b2099001a78b372046057328f6a4cd8c31d81"))
	var sx big.Int
	var sy big.Int
	sx.SetString("111683051027723633514448336110627766417838261840909886725272833797105343498776", 10)
	sy.SetString("84206254510545392346350698534430020108750877087840625331661984238009566962077", 10)
	pk := &ecdsa.PublicKey{crypto.S256(), &sx, &sy}
	RTcmt := common.BytesToHash(common.FromHex("36c093dbae3c5c309cb69818ff6f4cc3328e50d932cb414a7f7e783efa8201ea"))
	CMTB := common.BytesToHash(common.FromHex("0x0044f0b699cd2d866c8da0201dcc2a8b28bdf7d47f39e13ebe4e53a29b704a83"))
	SNB := common.BytesToHash(common.FromHex("0x0000000000000000000000000000000000000000000000000000000000000000"))
	CMTBnew := common.BytesToHash(common.FromHex("0xe3d05df321f770df544715d08b39180bd5811963a9e183772a4e416095aaf304"))
	CMTSForMerkle := []common.Hash{CMTS}

	pr := GenDepositProof(CMTS, ValueS, SNS, RS, SNA, ValueB, RB, SNBnew, RBnew, pk, RTcmt[:], CMTB, SNB, CMTBnew, CMTSForMerkle)
}

func GenDepositProof(CMTS common.Hash, ValueS uint64, SNS common.Hash, RS common.Hash, SNA common.Hash, ValueB uint64, RB common.Hash, SNBnew common.Hash, RBnew common.Hash, pk *ecdsa.PublicKey, RTcmt []byte, CMTB common.Hash, SNB common.Hash, CMTBnew common.Hash, CMTSForMerkle []common.Hash) []byte {
	fmt.Println("cmtbold", CMTB)
	fmt.Println("cmtboldstring", common.ToHex(CMTB[:]))
	cmtS_c := C.CString(common.ToHex(CMTS[:]))
	valueS_c := C.ulong(ValueS)
	// PK := crypto.PubkeyToAddress(*pk)
	// pk_c := C.CString(string(PK[:]))
	PK := crypto.PubkeyToAddress(*pk) //--zy
	//fmt.Println("len pk_c=", len(common.ToHex(PK[:])), common.ToHex(PK[:]))
	pk_c := C.CString(common.ToHex(PK[:]))
	SNS_c := C.CString(common.ToHex(SNS.Bytes()[:])) //--zy
	RS_c := C.CString(common.ToHex(RS.Bytes()[:]))   //--zy
	SNA_c := C.CString(common.ToHex(SNA.Bytes()[:]))
	valueB_c := C.ulong(ValueB)
	RB_c := C.CString(common.ToHex(RB.Bytes()[:])) //rA_c := C.CString(string(RA.Bytes()[:]))
	SNB_c := C.CString(common.ToHex(SNB.Bytes()[:]))
	SNBnew_c := C.CString(common.ToHex(SNBnew.Bytes()[:]))
	RBnew_c := C.CString(common.ToHex(RBnew.Bytes()[:]))
	cmtB_c := C.CString(common.ToHex(CMTB[:]))
	RT_c := C.CString(common.ToHex(RTcmt)) //--zy   rt

	cmtBnew_c := C.CString(common.ToHex(CMTBnew[:]))
	fmt.Println("cmtBnew=", common.ToHex(CMTBnew[:]))
	valueBNew_c := C.ulong(ValueB + ValueS)

	var cmtArray string
	for i := 0; i < len(CMTSForMerkle); i++ {
		s := string(common.ToHex(CMTSForMerkle[i][:]))
		cmtArray += s
	}
	fmt.Println("cmtarray=", cmtArray)
	cmtsM := C.CString(cmtArray)
	fmt.Println("--------------------------------------------lencmtarray", len(cmtArray))
	nC := C.int(len(CMTSForMerkle))

	cproof := C.genDepositproof(valueBNew_c, valueB_c, SNB_c, RB_c, SNBnew_c, RBnew_c, SNS_c, RS_c, cmtB_c, cmtBnew_c, valueS_c, pk_c, SNA_c, cmtS_c, cmtsM, nC, RT_c)
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}
