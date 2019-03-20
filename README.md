# VNT
官方网址：http://www.vntchain.io/

* test/clique can test geth using clique consensus algorithm (PoA)
* test/pow can run test using ethash consensus algorithm (PoW)
* go-ethereum can build and compile geth
* libsnark-vnt can provide a library for zero-knowledge proof

### 一、搭建环境
```
* On Ubuntu 18.04 LTS:

        $ sudo apt-get install build-essential cmake git libgmp3-dev libprocps-dev python-markdown libboost-all-dev libssl-dev pkg-config
        
* On Ubuntu 16.04 LTS:

        $ sudo apt-get install build-essential cmake git libgmp3-dev libprocps4-dev python-markdown libboost-all-dev libssl-dev pkg-config
        
* On Ubuntu 14.04 LTS:

        $ sudo apt-get install build-essential cmake git libgmp3-dev libprocps3-dev python-markdown libboost-all-dev libssl-dev

go version >= 1.10
```

> Note: 从共享文件夹中将prfKey文件夹拷贝至/usr/local目录下!!!

### 二、压缩版编译

1、将项目源码拷贝到 `$GOPATH/src/github.com`目录，解压到ethereum文件夹下
```
tar -xzvf VNT-libsnark.tar.gz ethereum
```

2、项目路径为`$GOPATH/src/github.com/ethereum/`，项目目录为：
```
   ethereum
   -- prfKey        保存libsnark的pk和vk
   -- test          以太坊的私有链搭建及项目整体测试
   -- go-ethereum   基于040dd5bd5d9ecf05cce666eeb395bc18e5e91342分支进行修改
   -- libsnark      基于libsnark实现的云象零知识证明方案
```
> Note: 所有geth终端使用同一份prfKey

3、将`prfKey`文件夹拷贝至`/usr/local`目录下，并查看是否有读写的权限
```   
   sudo cp -r prfKey /usr/local
```

4、编译`libsnark`，并设置动态库
```
   cd ethereum/libsnark-vnt
   
   mkdir build && cd build

   cmake ..

   make

   sudo cp -i ./src/libzk* ./depends/libsnark/libsnark/libsnark.so ./depends/libsnark/depends/libff/libff/libff.so /usr/local/lib

   sudo gedit ~/.bashrc

   //将下面一行添加到文件最后，保存
   export LD_LIBRARY_PATH=/usr/local/lib
```

5、编译以太坊
> Note: 由于`cmts`将被组织为`merkle tree`, 考虑效率问题，`libsnark`中将其树高设为`5`,叶子节点数为`2^5=32`，</br>
   `go-ethereum`测试时可将`go-ethereum/zktx/zktx.go`中的`ZKCMTNODES`设为`1`, 实际使用时，`ZKCMTNODES`设为`20`即可。

```
   cd ethereum/go-ethereum

   go install -v ./cmd/geth
```

> Note: 运行上述指令时，可能提示权限不够，使用`sudo`提示找不到命令，可参考[博客](https://www.cnblogs.com/chr-wonder/p/8464224.html) </br>
必须设置`env_keep` 中的`Defaults  env_keep="GOPATH"` </br>
运行geth时，必须指定相对或绝对路径的`geth`，本机可能之前装过`geth`，注意区分; </br>
不再使用make编译geth，通过go install编译的geth在$GOPATH/bin目录下 </br>
可以将$GOPATH/bin添加到~/.bashrc中，然后就可以直接在任何目录下执行geth的指令了 </br>

### 三、github版编译

首先，将prfKey文件夹拷贝至/usr/local目录下，并查看是否有读写的权限
```
sudo cp -r prfKey /usr/local
```

> Note: 由于`cmts`将被组织为`merkle tree`, 考虑效率问题，`libsnark`中将其树高设为`5`,叶子节点数为`2^5=32`，</br>
   `go-ethereum`测试时可将`go-ethereum/zktx/zktx.go`中的`ZKCMTNODES`设为`1`, 实际使用时，`ZKCMTNODES`设为`20`即可。

然后执行以下命令
```
cd $GOPATH/src/github.com

git clone https://github.com/Agzs/VNT.git ethereum

cd ethereum

git checkout final

git branch //确定当前分支为final

cd libsnark-vnt

mkdir build && cd build

cmake ..

make

sudo cp -i ./src/libzk* ./depends/libsnark/libsnark/libsnark.so ./depends/libsnark/depends/libff/libff/libff.so /usr/local/lib
// 提示是否覆盖，输入y，敲回车

sudo gedit ~/.bashrc

将下面一行添加到文件最后，保存
export LD_LIBRARY_PATH=/usr/local/lib

cd ethereum/go-ethereum

go install -v ./cmd/geth

```
> Note: 运行上述指令时，可能提示权限不够，使用`sudo`提示找不到命令，可参考[博客](https://www.cnblogs.com/chr-wonder/p/8464224.html) </br>
必须设置`env_keep` 中的`Defaults  env_keep="GOPATH"` </br>
运行geth时，必须指定相对或绝对路径的`geth`，本机可能之前装过`geth`，注意区分; </br>
不再使用make编译geth，通过go install编译的geth在$GOPATH/bin目录下 </br>
可以将$GOPATH/bin添加到~/.bashrc中，然后就可以直接在任何目录下执行geth的指令了 </br>

### 四、操作步骤
> Note: 执行零知识操作的账户的明文余额不得超过64bits
```
// 节点连接
admin.nodeInfo.enode
admin.addPeer()
net.peerCount //节点连接信息

// 账户余额查询
eth.getBlance("0x492f3232b3e2affb484ddebd3bc84c091b68626f") //明文余额
eth.getBlance2("0x492f3232b3e2affb484ddebd3bc84c091b68626f") //零知识余额

// miners必须先启动挖矿，才能进行交易
miner.start()

// 节点A执行Mint操作，转化零知识余额到自己的账户中
eth.sendMintTransaction({from:"0x492f3232b3e2affb484ddebd3bc84c091b68626f",value:"0x1234"})

// 节点B执行getPubKeyRLP()根据其账户地址获取其公钥，线下告诉节点A，
// 其中第一个参数是账户，第二个参数是账户的密码
eth.getPubKeyRLP("0x6044c69f30e5699fe6f0ee4fccbcb50b1ab11faexit7","")

// 节点A执行Send操作进行转账，并更新自己的零知识余额，其中pubkey为接收方(节点B)的公钥  (上一步的结果)
// 线下告诉节点B 交易SendTransaction的hash
eth.sendSendTransaction({from:"0x492f3232b3e2affb484ddebd3bc84c091b68626f",value:"0x123",pubKey:"0xf842a0dfdc52fc4652e878a5ab8b714c493ccf4b8fc1106d457941a25989ce4ee2f5d7a0e600c1f446799b44e9e5d23712176a12dec4f4731e1adc7cc26f74b5e8a3d9c0"})

// 节点B执行Deposit操作，其中txHash为节点A产生的send 交易的hash
// 其中key为账户的密码
eth.sendDepositTransaction({from:"0x29eec49600049eb192b860121447bfc72fe7ebac",txHash:"0xb13787daae6718378334577d9ed16fda0575ddfa0511546d79c3eea1970f9753",key:""})

// 节点A执行Redeem操作，转化明文余额到自己的账户中
eth.sendRedeemTransaction({from:"0x492f3232b3e2affb484ddebd3bc84c091b68626f",value:"0x123"})
```
