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
