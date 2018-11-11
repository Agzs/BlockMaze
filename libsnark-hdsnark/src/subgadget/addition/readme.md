### 文件说明

- addPack.cpp 
基于libsnark自带的packing_gadget的构造的add_pack_gadget文件, 证明A+B=C
 
- gadget.hpp 和 main_fail.cpp
新构造的加法约束条件，但是失败了，不支持带有bit进位的情况，即可证明1+2=3,但是无法证明1+3=4