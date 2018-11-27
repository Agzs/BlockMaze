include_directories(
  .
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

# ======== addition ======================

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