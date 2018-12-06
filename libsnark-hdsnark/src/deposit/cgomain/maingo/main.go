package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

func main() {
	a := []byte{212, 202, 161, 224, 103, 25, 234, 181, 62, 237, 91, 227, 55, 146, 212, 215, 203, 190, 219, 241, 169, 232, 232, 211, 91, 12, 182, 120, 235, 32, 84, 158}
	fmt.Println("a=", common.ToHex(a[:]))
	//0xd4caa1e06719eab53eed5be33792d4d7cbbedbf1a9e8e8d35b0cb678eb20549e
	b := []byte{130, 54, 153, 177, 48, 187, 0, 195, 16, 38, 127, 149, 20, 76, 246, 51, 157, 7, 1, 19, 173, 109, 14, 217, 87, 248, 211, 217, 241, 222, 211, 194}
	fmt.Println("b=", common.ToHex(b[:]))
	//0x823699b130bb00c310267f95144cf6339d070113ad6d0ed957f8d3d9f1ded3c2
	fmt.Println(len("0x823699b130bb00c310267f95144cf6339d070113ad6d0ed957f8d3d9f1ded3c2"))
}
