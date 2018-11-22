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

  subgadget/addition/addByOrder.cpp
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

# ========= subtractionLess ===================
# test default_r1cs_ppzksnark_pp with subtraction and less_cmp
add_executable(
  lessSub

  subgadget/subtractionLess/main.cpp
)
target_link_libraries(
  lessSub

  snark
)

target_include_directories(
  lessSub

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

# ========= mintGadget ========================
# test default_r1cs_ppzksnark_pp with addition and less_cmp
# There needs libsodium
# https://download.libsodium.org/libsodium/releases/old/unsupported/libsodium-1.0.8.tar.gz
# https://download.libsodium.org/doc/installation
add_executable(
  mintTest

  subgadget/mintGadget/main.cpp
)
target_link_libraries(
  mintTest

  snark
  sodium 
)

target_include_directories(
  mintTest

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# =========== twoBlock =============
add_executable(
  twoBlock

  subgadget/twoBlock/main.cpp
)
target_link_libraries(
  twoBlock

  snark
  sodium 
)

target_include_directories(
  twoBlock

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# =========== threeBlock =============
add_executable(
  threeBlock

  subgadget/threeBlock/main.cpp
)
target_link_libraries(
  threeBlock

  snark
  sodium 
)

target_include_directories(
  threeBlock

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
##################################################################
#                     五大主要gadget                              #
##################################################################
# ========= mint ========================
add_executable(
  mint

  mint/main.cpp
)
target_link_libraries(
  mint

  snark
)

target_include_directories(
  mint

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# ========= redeem ========================
add_executable(
  redeem

  redeem/main.cpp
)
target_link_libraries(
  redeem

  snark
)

target_include_directories(
  redeem

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# ========= send ========================
add_executable(
  send

  send/main.cpp
)
target_link_libraries(
  send

  snark
)

target_include_directories(
  send

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# ========= update ========================
add_executable(
  update

  update/main.cpp
)
target_link_libraries(
  update

  snark
)

target_include_directories(
  update

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# ========= deposit ========================
add_executable(
  deposit

  deposit/main.cpp
)
target_link_libraries(
  deposit

  snark
)

target_include_directories(
  deposit

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

#set(SRC_LISTS ./hdsnark/test.cpp)


#add_library(libsnark-hdsnark SHARED ${SRC_LISTS})