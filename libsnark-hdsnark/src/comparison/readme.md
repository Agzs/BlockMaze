### 文件说明

- cmp_test.cpp 
基于libsnark自带的comparison_gadget的测试文件, 证明A与B的关系

- less_cmp_test.cpp
基于comparison_gadget修改的less_cmp，证明A < B
 
- comparison_gadget.tcc, comparison_gadget.hpp 和 main.cpp
拆分版的less_cmp，外加64bit的输入检查