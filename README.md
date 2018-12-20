# VNT
官方网址：http://www.vntchain.io/

* test/clique can test geth using clique consensus algorithm (PoA)
* test/pow can run test using ethash consensus algorithm (PoW)
* go-ethereum can build and compile geth
* libsnark-vnt can provide a library for zero-knowledge proof

### 环境搭建
```
* On Ubuntu 18.04 LTS:

        $ sudo apt-get install build-essential cmake git libgmp3-dev libprocps-dev python-markdown libboost-all-dev libssl-dev pkg-config
        
* On Ubuntu 16.04 LTS:

        $ sudo apt-get install build-essential cmake git libgmp3-dev libprocps4-dev python-markdown libboost-all-dev libssl-dev pkg-config
        
* On Ubuntu 14.04 LTS:

        $ sudo apt-get install build-essential cmake git libgmp3-dev libprocps3-dev python-markdown libboost-all-dev libssl-dev

go version >= 1.10
```

> Note: 从共享文件夹中将prfkey文件夹拷贝至/usr/local目录下!!!

### How to compile ?

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

> Note: 运行geth时，必须指定相对或绝对路径的`geth`，本机可能之前装过`geth`，注意区分; </br>
不再使用make编译geth，通过go install编译的geth在$GOPATH/bin目录下 </br>
可以将$GOPATH/bin添加到~/.bashrrc中，然后就可以直接在任何目录下执行geth的指令了 </br>


