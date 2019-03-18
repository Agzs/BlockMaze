include_directories(
  .
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

################
# 生成链接库
################
#shared library
add_library(
  zk_mint
  SHARED
  mint/mintcgo.cpp
)

add_library(
  zk_redeem
  SHARED
  redeem/redeemcgo.cpp
)

add_library(
  zk_send
  SHARED
  send/sendcgo.cpp
)

#add_library(
#  zk_update
#  SHARED
#  update/updatecgo.cpp
#)

add_library(
  zk_deposit
  SHARED
  deposit/depositcgo.cpp
)

###############################
# 生成各个gadget的所需的pk，vk
###############################
add_executable(
  mint_key

  mint/getpvk.cpp
)

target_link_libraries(
  mint_key

  snark
)

target_include_directories(
  mint_key

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
#########################
add_executable(
  send_key

  send/getpvk.cpp
)

target_link_libraries(
  send_key

  snark
)

target_include_directories(
  send_key

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
#########################
#add_executable(
#  update_key
#
#  update/getpvk.cpp
#)

#target_link_libraries(
#  update_key
#
#  snark
#)

#target_include_directories(
#  update_key

#  PUBLIC
#  ${DEPENDS_DIR}/libsnark
#  ${DEPENDS_DIR}/libsnark/depends/libfqfft
#)
#########################
add_executable(
  deposit_key

  deposit/getpvk.cpp
)

target_link_libraries(
  deposit_key

  snark
)

target_include_directories(
  deposit_key

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
#########################
add_executable(
  redeem_key

  redeem/getpvk.cpp
)

target_link_libraries(
  redeem_key

  snark
)

target_include_directories(
  redeem_key

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

