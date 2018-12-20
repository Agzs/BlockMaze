// sha256(data+padding), 512bits < data.size() < 1024-64-1bits
template<typename FieldT>
class sha256_two_block_gadget : gadget<FieldT> {
private:
    std::shared_ptr<block_variable<FieldT>> block1;
    std::shared_ptr<block_variable<FieldT>> block2;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher1;
    std::shared_ptr<digest_variable<FieldT>> intermediate_hash; // 中间hash值
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher2;

public:
    sha256_two_block_gadget(              // cmt_A = sha256(value, sn, r, padding)
        protoboard<FieldT> &pb,
        pb_variable<FieldT>& ZERO,
        pb_variable_array<FieldT>& v,        // 64bits value
        pb_variable_array<FieldT>& sn_old,   // 256bits serial number
        pb_variable_array<FieldT>& rho,      // 256bits random number
        std::shared_ptr<digest_variable<FieldT>> cmtB // 256bits hash
    ) : gadget<FieldT>(pb, "sha256_two_block_gadget") {

        pb_variable_array<FieldT> first_of_r(rho.begin(), rho.begin()+192);
        pb_variable_array<FieldT> last_of_r(rho.begin()+192, rho.end());

        intermediate_hash.reset(new digest_variable<FieldT>(pb, 256, ""));

        // final padding = base_padding + length
        pb_variable_array<FieldT> length_padding =
            from_bits({
                1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, // 12*4*8 = 384bits
                // length of message (576 bits)
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,1,0, 0,1,0,0,0,0,0,0 // 8*8 = 64bits
            }, ZERO); // 56*8=448bits

        block1.reset(new block_variable<FieldT>(pb, {
            v,           // 64bits
            sn_old,      // 256bits
            first_of_r   // 192bits
        }, "sha256_two_block_gadget_block1"));

        block2.reset(new block_variable<FieldT>(pb, {
            last_of_r,      // (256-192)=64bits
            length_padding  // 448bits
        }, "sha256_two_block_gadget_block2"));

        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher1.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block1->bits,
            *intermediate_hash,
        "sha256_two_block_hash1"));

        pb_linear_combination_array<FieldT> IV2(intermediate_hash->bits); // hash迭代

        hasher2.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV2,
            block2->bits,
            *cmtB,
        "sha256_two_block_hash2"));
    }

    void generate_r1cs_constraints() {
        // TODO: This may not be necessary if SHA256 constrains
        // its output digests to be boolean anyway.
        intermediate_hash->generate_r1cs_constraints();

        hasher1->generate_r1cs_constraints();
        hasher2->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        hasher1->generate_r1cs_witness();
        hasher2->generate_r1cs_witness();
    }
};

// sha256(data+padding), 1024bits < data.size() < 1536-64-1bits
template<typename FieldT>
class sha256_three_block_gadget : gadget<FieldT> {
private:
    std::shared_ptr<block_variable<FieldT>> block1;
    std::shared_ptr<block_variable<FieldT>> block2;
    std::shared_ptr<block_variable<FieldT>> block3;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher1;
    std::shared_ptr<digest_variable<FieldT>> intermediate_hash1; // 中间hash值
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher2;
    std::shared_ptr<digest_variable<FieldT>> intermediate_hash2; // 中间hash值
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher3;

public:
    sha256_three_block_gadget(                // cmt_s = sha256(value, pk_B, sn_s, r, sn_A, padding)
        protoboard<FieldT> &pb,
        pb_variable<FieldT>& ZERO,
        pb_variable_array<FieldT>& v,       // 64bits value for Send
        pb_variable_array<FieldT>& pk_recv, // a random 160bits receiver's address
        pb_variable_array<FieldT>& sn_s,    // 256bits serial number associsated with a balance transferred between two accounts
        pb_variable_array<FieldT>& r,       // 256bits random number
        pb_variable_array<FieldT>& sn_old,  // 256bits serial number about sender
        std::shared_ptr<digest_variable<FieldT>> cmtS // 256bits hash
    ) : gadget<FieldT>(pb, "sha256_three_block_gadget") {

        // final padding = base_padding + length
        pb_variable_array<FieldT> length_padding =
            from_bits({
                1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, // 15*4*8 = 480bits

                // length of message (992 bits)
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,1,1, 1,1,1,0,0,0,0,0 // 8*8 = 64bits
            }, ZERO); // 68*8=544bits

        pb_variable_array<FieldT> first_of_r(r.begin(), r.begin()+32);
        pb_variable_array<FieldT> last_of_r(r.begin()+32, r.end());

        pb_variable_array<FieldT> first_of_padding(length_padding.begin(), length_padding.begin()+32);
        pb_variable_array<FieldT> last_of_padding(length_padding.begin()+32, length_padding.end());

        intermediate_hash1.reset(new digest_variable<FieldT>(pb, 256, ""));
        intermediate_hash2.reset(new digest_variable<FieldT>(pb, 256, ""));

        block1.reset(new block_variable<FieldT>(pb, {
            v,                // 64bits
            pk_recv,          // 160bits
            sn_s,             // 256bits
            first_of_r        // 32bits
        }, "sha256_three_block_gadget_block1"));

        block2.reset(new block_variable<FieldT>(pb, {
            last_of_r,         // (256-32)=224bits
            sn_old,            // 256bits
            first_of_padding   // 32bits 
        }, "sha256_three_block_gadget_block2"));

        block3.reset(new block_variable<FieldT>(pb, {
            last_of_padding    // (544-32)=512bits
        }, "sha256_three_block_gadget_block3"));

        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher1.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block1->bits,
            *intermediate_hash1,
        "sha256_three_block_hash1"));

        pb_linear_combination_array<FieldT> IV2(intermediate_hash1->bits); // hash迭代

        hasher2.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV2,
            block2->bits,
            *intermediate_hash2,
        "sha256_three_block_hash2"));

        pb_linear_combination_array<FieldT> IV3(intermediate_hash2->bits); // hash迭代

        hasher3.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV3,
            block3->bits,
            *cmtS,
        "sha256_three_block_hash3"));
    }

    void generate_r1cs_constraints() {
        // TODO: This may not be necessary if SHA256 constrains
        // its output digests to be boolean anyway.
        intermediate_hash1->generate_r1cs_constraints();
        intermediate_hash2->generate_r1cs_constraints();

        hasher1->generate_r1cs_constraints();
        hasher2->generate_r1cs_constraints();
        hasher3->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        hasher1->generate_r1cs_witness();
        hasher2->generate_r1cs_witness();
        hasher3->generate_r1cs_witness();
    }
};