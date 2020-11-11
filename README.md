# BlockMaze

* test/clique can test geth using clique consensus algorithm (PoA)
* test/pow can run test using ethash consensus algorithm (PoW)
* go-ethereum can build and compile geth
* libsnark-vnt can provide a library for zero-knowledge proof

### 1. Setup
```
* On Ubuntu 18.04 LTS:

        $ sudo apt-get install build-essential cmake git libgmp3-dev libprocps-dev python-markdown libboost-all-dev libssl-dev pkg-config
        
* On Ubuntu 16.04 LTS:

        $ sudo apt-get install build-essential cmake git libgmp3-dev libprocps4-dev python-markdown libboost-all-dev libssl-dev pkg-config
        
* On Ubuntu 14.04 LTS:

        $ sudo apt-get install build-essential cmake git libgmp3-dev libprocps3-dev python-markdown libboost-all-dev libssl-dev

go version >= 1.10
```

### 2. Build

2.1 obtain source code
```
cd $GOPATH/src/github.com

git clone https://github.com/Agzs/BlockMaze.git ethereum
```

2.2 directory 
```
   ethereum
   -- prfKey        save the pk and vk from libsnark(Due to file size limitation on Github, please build later)
   -- test          test files
   -- go-ethereum   based on 040dd5bd5d9ecf05cce666eeb395bc18e5e91342 branch
   -- libsnark-vnt  our own gadgets
```

> Note: all geth must utilize the same "prfKey"


2.3 build `libsnark`
```
   cd ethereum
   
   mkdir prfKey

   cd libsnark-vnt
   
   mkdir build && cd build

   cmake ..

   make

   //generate vk and pk
   ./src/mint_key

   ./src/send_key

   ./src/deposit_key

   ./src/redeem_key

   mv depositpk.txt depositvk.txt mintpk.txt mintvk.txt redeempk.txt redeemvk.txt sendpk.txt sendvk.txt -t ../../prfKey

   sudo cp -i ./src/libzk* ./depends/libsnark/libsnark/libsnark.so ./depends/libsnark/depends/libff/libff/libff.so /usr/local/lib

   sudo gedit ~/.bashrc

   //add the following command and save it
   export LD_LIBRARY_PATH=/usr/local/lib
```

2.4 setup keys
```   
   sudo cp -r prfKey /usr/local
```

2.5 Build Ethereum
> Note: Since `cmts` are organized as `merkle tree`, we set a Merkle tree with `8` height in `libsnark`,叶子节点数为`2^8=256`，</br>
   In `go-ethereum/zktx/zktx.go`, we set `ZKCMTNODES = 1`; in practical, we set `ZKCMTNODES = 20`.

```
   cd ethereum/go-ethereum

   go install -v ./cmd/geth
```

### 3. Operation
```
// peer connection
admin.nodeInfo.enode
admin.addPeer()
net.peerCount 

// get balance
eth.getBlance("0x492f3232b3e2affb484ddebd3bc84c091b68626f") //plaintext balance
eth.getBlance2("0x492f3232b3e2affb484ddebd3bc84c091b68626f") //zero-knowledge balance

// miners first mines blocks, then sends transactions
miner.start()

// Node A executes Mint
eth.sendMintTransaction({from:"0x492f3232b3e2affb484ddebd3bc84c091b68626f",value:"0x1234"})

// Node B executes getPubKeyRLP() to obtain pk_B
eth.getPubKeyRLP("0x6044c69f30e5699fe6f0ee4fccbcb50b1ab11faexit7","")

// Node A executes Send to transfer money, where pubkey is the public key of B, (i.e., pk_B).
// Final return Tx_send_hash
eth.sendSendTransaction({from:"0x492f3232b3e2affb484ddebd3bc84c091b68626f",value:"0x123",pubKey:"0xf842a0dfdc52fc4652e878a5ab8b714c493ccf4b8fc1106d457941a25989ce4ee2f5d7a0e600c1f446799b44e9e5d23712176a12dec4f4731e1adc7cc26f74b5e8a3d9c0"})

// Node B executes Deposit, where txHash is Tx_send_hash obtained from A.
eth.sendDepositTransaction({from:"0x29eec49600049eb192b860121447bfc72fe7ebac",txHash:"0xb13787daae6718378334577d9ed16fda0575ddfa0511546d79c3eea1970f9753",key:""})

// Node A executes Redeem
eth.sendRedeemTransaction({from:"0x492f3232b3e2affb484ddebd3bc84c091b68626f",value:"0x123"})
```

### 4. Large-scale testing

refer to [BlockMaze-Test](https://github.com/Agzs/BlockMaze-Test)
