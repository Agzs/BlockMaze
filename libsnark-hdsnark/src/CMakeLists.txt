include_directories(
  .
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)



#shared library
# add_library(
#   zk_mint
#   SHARED
#   mint/mintcgo.cpp
# )

# add_library(
#   zk_redeem
#   SHARED
#   redeem/redeemcgo.cpp
# )

# add_library(
#   zk_send
#   SHARED
#   send/sendcgo.cpp
# )

# add_library(
#   zk_update
#   SHARED
#   update/updatecgo.cpp
# )

# add_library(
#   zk_deposit
#   SHARED
#   deposit/depositcgo.cpp
# )
#########################
add_executable(
  mint

  mint/main.cpp
  #subgadget/addition/addByOrder.cpp
  #subgadget/additionLess/main.cpp
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
#########################
# add_executable(
#   send

#   send/getpvk.cpp
# )

# target_link_libraries(
#   send

#   snark
# )

# target_include_directories(
#   send

#   PUBLIC
#   ${DEPENDS_DIR}/libsnark
#   ${DEPENDS_DIR}/libsnark/depends/libfqfft
# )
# #########################
# add_executable(
#   update

#   update/getpvk.cpp
# )

# target_link_libraries(
#   update

#   snark
# )

# target_include_directories(
#   update

#   PUBLIC
#   ${DEPENDS_DIR}/libsnark
#   ${DEPENDS_DIR}/libsnark/depends/libfqfft
# )
# #########################
# add_executable(
#   deposit

#   deposit/getpvk.cpp
# )

# target_link_libraries(
#   deposit

#   snark
# )

# target_include_directories(
#   deposit

#   PUBLIC
#   ${DEPENDS_DIR}/libsnark
#   ${DEPENDS_DIR}/libsnark/depends/libfqfft
# )
# #########################
# add_executable(
#   redeem

#   redeem/getpvk.cpp
# )

# target_link_libraries(
#   redeem

#   snark
# )

# target_include_directories(
#   redeem

#   PUBLIC
#   ${DEPENDS_DIR}/libsnark
#   ${DEPENDS_DIR}/libsnark/depends/libfqfft
# )
# #########################
# add_executable(
#   aaaa

#   deposit/aaaa.cpp
# )

# target_link_libraries(
#   aaaa

#   snark
#   zk_deposit
# )

# target_include_directories(
#   aaaa

#   PUBLIC
#   ${DEPENDS_DIR}/libsnark
#   ${DEPENDS_DIR}/libsnark/depends/libfqfft
# )
