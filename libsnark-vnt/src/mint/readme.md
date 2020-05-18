### 文件说明

#### 1、circuit 目录
##### 1.1 add_cmp.tcc文件
重写`libsnark`自带的比较电路，添加加法约束，构造`note_gadget_with_comparison_for_balance`的电路, 

证明 `value_old + value_s = value` 并且 `value_s < balance`

##### 1.2 commitment.tcc文件
基于`libsnark`自带的`sha256`的电路，重新构造`sha256_CMTA_gadget`电路，支持两个`blocks`的哈希，

证明`cmt_A = sha256(value, sn, r)`

##### 1.3 comparison.tcc文件
基于`libsnark`自带的`comparison_gadget`的, 重新构造`less_comparison_gadget`电路，证明`A < B`的关系

##### 1.4 gadget.tcc文件
整合上述子电路，构造支持`mint`的电路，根据以下已知条件：
```
 * ************* for cmtA_old **************
 * publicData: cmtA_old, sn_old,  
 * privateData: value_old, r_old

 * ************** for cmtA_new **************
 * publicData: cmtA_new, (value_s, balance)  
 * privateData: value_new, sn_new, r_new
 ```
 证明以下等式成立：
```
cmt_A_old = sha256(value_old, sn_old, r_old)
cmtA_new = sha256(value_new, sn_new, r_new)
value_new = value_old + value_s
value_s < balance
```

##### 1.5 note.tcc文件
基于`libsnark`自带的`packing_gadget`的, 重新改写`get_field_element_from_bits_by_order()`函数，实现域上二进制到域上十进制的转化

##### 1.6 utils.tcc文件
包含`gadget`辅助函数，实现类型转化等操作

#### 2、deps 目录
该目录复制于`zcash`，主要是使用正常`sha256`函数所依赖的的库文件，需要特别说明的是`libsodium`,该库主要用来产生`uint256`类型的随机数;

`libsodium`库下载地址：https://download.libsodium.org/libsodium/releases/old/unsupported/libsodium-1.0.8.tar.gz

`libsodium`安装方法：https://download.libsodium.org/doc/installation

`libsodium`编译方法：在`CMakeLists.txt`的`target_link_libraries()`中添加`sodium`，并在相应的文件中导入`#include "deps/sodium.h"`

#### 3、其他文件

##### 3.1 main.cpp文件
简单封装，内含函数入口，支持测试

##### 3.2 mint_gadget.cpp文件
仿照`zcash`封装`Init`，`Generate`，`Prove`和`Verify`操作

##### 3.3 mint_gadget.hpp文件
仿照`zcash`实现`Init`，`Generate`，`Prove`和`Verify`操作

##### 3.4 Note.h文件
含有`Note`结构体，用于包装`value`，`sn`和`r`，计算`cmtA`的哈希值

##### 3.5 uint256.h文件
从`bitcoin`中导入的文件，支持`uint256`相关操作

##### 3.6 util.h文件
包含辅助函数，实现`vector`类型的相关转换等操作