include_directories(
  .
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)


# test default_r1cs_ppzksnark_pp with hdsnark
add_executable(
  hdsnark

  shaOneBlock/main.cpp
)
target_link_libraries(
  hdsnark

  snark
  boost_system
)

target_include_directories(
  hdsnark

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# test default_r1cs_ppzksnark_pp with hdsnark
add_executable(
  singlehdsnark

  shaOneBlock/test_notcp.cpp
)
target_link_libraries(
  singlehdsnark

  snark
)

target_include_directories(
  singlehdsnark

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

#set(SRC_LISTS ./hdsnark/test.cpp)


#add_library(libsnark-hdsnark SHARED ${SRC_LISTS})




