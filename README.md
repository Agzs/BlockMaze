# VNT
官方网址：http://www.vntchain.io/

官方项目汇报：https://www.jinse.com/search/VNT

* clique can run geth using clique consensus algorithm
* go-ethereum can build and compile geth
* libsnark can provide a library for zero-knowledge proof

### How to clone ?
```
cd gopath/src/github.com

git clone https://github.com/Agzs/VNT.git ethereum

cd ethereum/go-ethereum

make

cd ..

cd libsnark-hdsnark

mkdir build && cd build

cmake ..

make

sudo cp ./src/libzk* ./depends/libsnark/libsnark/libsnark.so ./depends/libsnark/depends/libff/libff/libff.so /usr/local/lib

```

### How to run geth ?
```
cd ethereum/clique

../go-ethereum/build/bin/geth --datadir signer/data account new

../go-ethereum/build/bin/geth --datadir signer/data init clique.json

../go-ethereum/build/bin/geth --datadir signer/data --networkid 55661 --port 2002 --unlock 492f3232b3e2affb484ddebd3bc84c091b68626f --password signer/passwd.txt console

eth.getBalance(eth.accounts[0])

eth.getBalance(eth.accounts[1])

sha3Msg = web3.sha3("blockchain")

signedData = eth.sign(eth.accounts[0], sha3Msg)

eth.sendPublicTransaction({from:eth.accounts[0],to:eth.accounts[1],value:web3.toWei(0.05, "ether"), data:sha3Msg})


txpool.status

miner.start()

miner.stop()


eth.getBalance(eth.accounts[0])

eth.getBalance(eth.accounts[1])


eth.getBlock()

eth.getTransaction("")

```

###简易测试步骤
1.节点相连 nodeA 与nodeB互连 在clique文件夹下打开两个终端
```
cd ethereum/clique

nodeA
1 ../go-ethereum/build/bin/geth --datadir signer/data init clique.json

2 ../go-ethereum/build/bin/geth --datadir signer/data --networkid 55661 --port 2002 --unlock 492f3232b3e2affb484ddebd3bc84c091b68626f --password signer/passwd.txt console

5 admin.nodeInfo.enode

nodeB
3 ../go-ethereum/build/bin/geth --datadir node/data init clique.json

4  ../go-ethereum/build/bin/geth --datadir node/data --networkid 55661 --port 2003 --unlock 29eec49600049eb192b860121447bfc72fe7ebac --password node/passwd.txt console

6 admin.addPeer("enode://52a517f7c39eda20e807a453c924d693fb25498eb2569e059e6094e0bfaa9398f09296cc532b9eeaf56d09618ccb7b9ea28ab4e428a0e0b06b695045b2bc978b@127.0.0.1:2002")

```
2.测试mint+redeem  nodeA
```
eth.sendMintTransaction({from:"0x492f3232b3e2affb484ddebd3bc84c091b68626f",value:"0x1234"})
miner.start()
miner.stop()
eth.sendRedeemTransaction({from:"0x492f3232b3e2affb484ddebd3bc84c091b68626f",value:"0x123"})
miner.start()
miner.stop()
```
3.测试mint+send+update   nodeA   简陋测试可以只用一个节点的两个账户
```
eth.sendMintTransaction({from:"0x492f3232b3e2affb484ddebd3bc84c091b68626f",value:"0x1234"})
miner.start()
miner.stop()
eth.getPubKeyRLP("0x6044c69f30e5699fe6f0ee4fccbcb50b1ab11faexit7","")
eth.sendSendTransaction({from:"0x492f3232b3e2affb484ddebd3bc84c091b68626f",value:"0x123",pubKey:"0xf842a0dfdc52fc4652e878a5ab8b714c493ccf4b8fc1106d457941a25989ce4ee2f5d7a0e600c1f446799b44e9e5d23712176a12dec4f4731e1adc7cc26f74b5e8a3d9c0"})//pubkey:上一个命令的结果
miner.start()
miner.stop()
eth.sendUpdateTransaction({from:"0x492f3232b3e2affb484ddebd3bc84c091b68626f",txHash:"0x3493dc889528bc975436fcfb2fae9fd3d1829ecac0161e966a1459ab9df36f88"})//txHash:send 交易的hash
miner.start()
miner.stop()
```
4.测试mint+send+deposit  nodeA：mint+send   nodeB：deposit 两个节点的两个账户 #所有挖矿由节点A进行
```
eth.sendMintTransaction({from:"0x492f3232b3e2affb484ddebd3bc84c091b68626f",value:"0x1234"}) //nodeA
miner.start()
miner.stop()
eth.getPubKeyRLP("0x29eec49600049eb192b860121447bfc72fe7ebac","") //nodeB
eth.sendSendTransaction({from:"0x492f3232b3e2affb484ddebd3bc84c091b68626f",value:"0x123",pubKey:"0xf842a060e7f3a9fb0aff7485bcc189d1775789eba8022d9eb1d3b3c8809191964e7a0da0ecf05f7cfc6a6d18ff0831e6ef0097d1bfa7a6b6efcda6557431b2ae72429a79"})
//nodeA
miner.start()
miner.stop()
eth.sendDepositTransaction({from:"0x29eec49600049eb192b860121447bfc72fe7ebac",txHash:"0xb13787daae6718378334577d9ed16fda0575ddfa0511546d79c3eea1970f9753",key:""})//nodeB
miner.start()//nodeA
miner.stop()
```
