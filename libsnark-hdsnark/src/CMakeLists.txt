include_directories(
  .
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

add_executable(
  addidition

  addition/main.cpp
)
target_link_libraries(
  addidition

  snark
)

target_include_directories(
  addidition

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# test default_r1cs_ppzksnark_pp with cmp
add_executable(
  cmp

  comparison/cmp_test.cpp
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




