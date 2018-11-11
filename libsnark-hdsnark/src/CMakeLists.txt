include_directories(
  .
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

# ======== addition ======================
# test default_r1cs_ppzksnark_pp with addition
add_executable(
  addition

  subgadget/addition/addPack.cpp
)
target_link_libraries(
  addition

  snark
)

target_include_directories(
  addition

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# ========= additionLess ========================
# test default_r1cs_ppzksnark_pp with addition and less_cmp
add_executable(
  lessADD

  subgadget/additionLess/main.cpp
)
target_link_libraries(
  lessADD

  snark
)

target_include_directories(
  lessADD

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)


# ========= comparison ========================
# test default_r1cs_ppzksnark_pp with cmp
add_executable(
  cmp

  subgadget/comparison/less_cmp_test.cpp
)
target_link_libraries(
  cmp

  snark
)

target_include_directories(
  cmp

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# ============= pack_gadget ===============
# test default_r1cs_ppzksnark_pp with packing
add_executable(
  pack

  subgadget/pack_gadget/main.cpp
)
target_link_libraries(
  pack

  snark
)

target_include_directories(
  pack

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# ============== hdsnark ===============
# test default_r1cs_ppzksnark_pp with hdsnark
add_executable(
  shaOneBlock

  subgadget/hdsnark/main.cpp
)
target_link_libraries(
  shaOneBlock

  snark
)

target_include_directories(
  shaOneBlock

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# ============== shaTwoBlock ===============
# test default_r1cs_ppzksnark_pp with shaTwoBlock
add_executable(
  shaTwoBlock

  subgadget/shaTwoBlock/main.cpp
)
target_link_libraries(
  shaTwoBlock

  snark
)

target_include_directories(
  shaTwoBlock

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# ============== shaThreeBlock ===============
# test default_r1cs_ppzksnark_pp with shaThreeBlock
add_executable(
  shaThreeBlock

  subgadget/shaThreeBlock/main.cpp
)
target_link_libraries(
  shaThreeBlock

  snark
)

target_include_directories(
  shaThreeBlock

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

#set(SRC_LISTS ./hdsnark/test.cpp)


#add_library(libsnark-hdsnark SHARED ${SRC_LISTS})




