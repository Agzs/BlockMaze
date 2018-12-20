/********************************************************
 * copy from util.tcc
 * ******************************************************/
// 进行bit转换
template<typename FieldT>
pb_variable_array<FieldT> from_bits(std::vector<bool> bits, pb_variable<FieldT>& ZERO) {
    pb_variable_array<FieldT> acc;

    BOOST_FOREACH(bool bit, bits) {
        acc.emplace_back(bit ? ONE : ZERO); // ONE是常数项，ZERO对应FiledT::zero()为零元
    }

    return acc;
}

// 从256位中截取后252位
std::vector<bool> trailing252(std::vector<bool> input) {
    if (input.size() != 256) {
        throw std::length_error("trailing252 input invalid length");
    }

    return std::vector<bool>(input.begin() + 4, input.end());
}

// 类型转换，将u256转换为bit数组
std::vector<bool> uint256_to_bool_vector(uint256 input) {
    std::vector<unsigned char> input_v(input.begin(), input.end());
    std::vector<bool> output_bv(256, 0);
    convertBytesVectorToVector(
        input_v,
        output_bv
    );

    return output_bv;
}

// 类型转换，将u64转换为bit数组
std::vector<bool> uint64_to_bool_vector(uint64_t input) {
    auto num_bv = convertIntToVectorLE(input);
    std::vector<bool> num_v(64, 0);
    convertBytesVectorToVector(num_bv, num_v);

    return num_v;
}

// 向into数组后追加from
void insert_uint256(std::vector<bool>& into, uint256 from) {
    std::vector<bool> blob = uint256_to_bool_vector(from);
    into.insert(into.end(), blob.begin(), blob.end());
}

// 向into数组后追加from
void insert_uint64(std::vector<bool>& into, uint64_t from) {
    std::vector<bool> num = uint64_to_bool_vector(from);
    into.insert(into.end(), num.begin(), num.end());
}

// 以32为对称线，每8位进行逆序转换
template<typename T>
T swap_endianness_u64(T v) {
    if (v.size() != 64) {
        throw std::length_error("invalid bit length for 64-bit unsigned integer");
    }

    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 8; j++) {
            std::swap(v[i*8 + j], v[((7-i)*8)+j]);
        }
    }

    return v;
}

// bit形式转换为十进制形式，但是仍然是线性组合的形式
template<typename FieldT>
linear_combination<FieldT> packed_addition(pb_variable_array<FieldT> input) {
    auto input_swapped = swap_endianness_u64(input);

    return pb_packing_sum<FieldT>(pb_variable_array<FieldT>( 
        input_swapped.rbegin(), input_swapped.rend() // 逆序的reverse_iterator
    ));
}

// bit形式转换为十进制形式，域的形式
template<typename FieldT>
FieldT packed_addition_fieldT(pb_variable_array<FieldT> input) {
    auto input_swapped = swap_endianness_u64(input);

    return pb_packing_filedT_sum<FieldT>(pb_variable_array<FieldT>( 
        input_swapped.rbegin(), input_swapped.rend() // 逆序的reverse_iterator
    ));
}