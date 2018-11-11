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

  addition/addPack.cpp
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

# ========= comparison ========================
# test default_r1cs_ppzksnark_pp with cmp
add_executable(
  cmp

  comparison/less_cmp_test.cpp
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

  pack_gadget/main.cpp
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

  hdsnark/main.cpp
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

  shaTwoBlock/main.cpp
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

  shaThreeBlock/main.cpp
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




