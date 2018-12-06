### 文件说明

#### 1、circuit 目录

##### 1.1 commitment.tcc文件
基于`libsnark`自带的`sha256`的电路，重新构造`sha256_two_block_gadget`电路，支持两个`blocks`的哈希，

证明`cmt_B_old == sha256(value_old, sn_old, r_old)`

证明`cmt_B == sha256(value, sn, r)`

重新构造`sha256_three_block_gadget`电路，支持三个`blocks`的哈希，

证明`cmt_S == sha256(value_s, pk_B, sn_s, r_s, sn_A)`

##### 1.2 gadget.tcc文件
整合上述子电路，构造支持`deposit`的电路，根据以下已知条件：
```
 * ************* for cmtB_old **************
 * publicData: cmtB_old, sn_old,  
 * privateData: value_old, r_old
 * ************** for cmtB_new **************
 * publicData: cmtB_new  
 * privateData: value_new, sn_new, r_new
 * ************** for cmtS **************
 * publicData: pk_B  
 * privateData: value_s, sn_s, r_s, sn_A
 * ************** for MerkleTree  **********
 * publicData: rt_cmt  
 * privateData: authPath, cmtS
 ```
 证明以下等式成立：
```
cmtS == sha256(value_s, pk_B, sn_s, r_s, sn_A)
cmt_B_old == sha256(value_old, sn_old, r_old)
cmtB_new == sha256(value_new, sn_new, r_new)
value_new == value_old + value_s
cmtS在以rt_cmt为根的MerkleTree上
```

##### 1.3 merkle.tcc文件
基于`libsnark`自带的`sha256_two_to_one_hash_gadget`和`merkle_tree_check_read_gadget`，仿照`zcash`中的`merkle_tree_gadget`实现，注意`witness`的`root`和`path`的初始化。

##### 1.4 note.tcc文件
基于`libsnark`自带的`packing_gadget`的, 重新改写`get_field_element_from_bits_by_order()`函数，实现域上二进制到域上十进制的转化

##### 1.5 utils.tcc文件
包含`gadget`辅助函数，实现类型转化等操作

#### 2、deps 目录
该目录复制于`zcash`，主要是使用正常`sha256`函数所依赖的的库文件，需要特别说明的是`libsodium`,该库主要用来产生`uint256`类型的随机数;

`libsodium`库下载地址：https://download.libsodium.org/libsodium/releases/old/unsupported/libsodium-1.0.8.tar.gz

`libsodium`安装方法：https://download.libsodium.org/doc/installation

`libsodium`编译方法：在`CMakeLists.txt`的`target_link_libraries()`中添加`sodium`，并在相应的文件中导入`#include "deps/sodium.h"`

#### 3、其他文件

##### 3.1 main.cpp文件
简单封装，内含函数入口，支持测试

##### 3.2 deposit_gadget.cpp文件
仿照`zcash`封装`Init`，`Generate`，`Prove`和`Verify`操作

##### 3.3 deposit_gadget.hpp文件
仿照`zcash`实现`Init`，`Generate`，`Prove`和`Verify`操作

##### 3.4 IncrementalMerkleTree.hpp文件
仿照`zcash`中的`IncrementalMerkleTree`和`IncrementalWitness`，实现`merkleTree`的组织处理，包括`path`、`root`、`tree`和`witness`，该文件主要包括`MerklePath`，`EmptyMerkleRoots`，`IncrementalWitness`，和`IncrementalMerkleTree`，`SHA256Compress`的类模板及其方法。

##### 3.5 IncrementalMerkleTree.tcc文件
仿照`zcash`中的`IncrementalMerkleTree`和`IncrementalWitness`，实现`merkleTree`的组织处理，包括`path`、`root`、`tree`和`witness`，该文件主要包括`MerklePath`，`EmptyMerkleRoots`，`IncrementalWitness`，和`IncrementalMerkleTree`，`SHA256Compress`的类模板中方法的实现。

##### 3.6 Note.h文件
含有`Note`结构体，用于包装`value`，`sn`和`r`，计算`cmtB`的哈希值

含有`NoteS`结构体，用于包装`value_s`，`pk_B`, `sn_s`, `r_s`和`sn_A_old`，计算`cmtS`的哈希值

##### 3.7 uint256.h文件
从`bitcoin`中导入的文件，支持`uint256`相关操作

##### 3.8 util.h文件
包含辅助函数，实现`vector`类型的相关转换等操作

##### 3.9 VNT.h文件
定义一些宏，比如`INCREMENTAL_MERKLE_TREE_DEPTH`
