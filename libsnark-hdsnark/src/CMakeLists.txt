include_directories(
  .
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)



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

add_library(
  zk_update
  SHARED
  update/updatecgo.cpp
)

add_library(
  zk_deposit
  SHARED
  deposit/depositcgo.cpp
)