### 文件说明
- addByOrder.cpp
基于打包bits为域值的函数，自构造`get_field_element_from_bits_by_order()`函数，实现域上的二进制到域上十进制的转化

- addPack.cpp 
基于libsnark自带的packing_gadget的构造的add_pack_gadget文件, 证明A+B=C
 
- gadget.hpp 和 main_fail.cpp
新构造的加法约束条件，但是失败了，不支持带有bit进位的情况，即可证明1+2=3,但是无法证明1+3=4

- util.h
如果单纯的使用packing_gadget，需要将修改部分代码如下：
```C++
//v.at((i*8)+(7-j)) = ((c >> (7-j)) & 1); //正序bit序列 --Agzs 11.9
 v.at((i*8)+j) = ((c >> (7-j)) & 1);
```
然后使用addPack.cpp文件
