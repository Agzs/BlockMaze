// This file achieves commitments with sha256_gadget
/*
 * sha256算法流程：https://blog.csdn.net/code_segment/article/details/80273482
 * bit填充的最高位是1，sha256算法要求
 * 最后64-bit 表示的初始报文（填充前）的位长度
*/
bool sha256_base_padding[384] = {
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
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0
}; // 12*4*8 = 384bits};

bool sha256_two_block_message_length[64] = {
        // length of message (576 bits)
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,1,0, 0,1,0,0,0,0,0,0 // 8*8 = 64bits
};

bool sha256_three_block_message_length[64] = {
        // length of message (1088 bits)
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,1,0,0, 0,1,0,0,0,0,0,0 // 8*8 = 64bits
};

template<typename FieldT>
class sha256_two_block_gadget : gadget<FieldT> {
private:
    std::shared_ptr<block_variable<FieldT>> block1;
    std::shared_ptr<block_variable<FieldT>> block2;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher1;
    std::shared_ptr<digest_variable<FieldT>> intermediate_hash; // 中间hash值
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher2;

public:
    sha256_two_block_gadget(              // cmt_A = sha256(value, sn, r, padding) for Mint
        protoboard<FieldT> &pb,
        pb_variable<FieldT>& ZERO,
        pb_variable_array<FieldT>& v,      // 64bits value for Mint
        pb_variable_array<FieldT>& sn_old, // 256bits serial number
        pb_variable_array<FieldT>& r,      // 256bits random number
        std::shared_ptr<digest_variable<FieldT>> cmtA // 256bits hash
    ) : gadget<FieldT>(pb, "sha256_two_block_gadget") {

        pb_variable_array<FieldT> first_of_r(rho.begin(), rho.begin()+192);
        pb_variable_array<FieldT> last_of_r(rho.begin()+192, rho.end());

        intermediate_hash.reset(new digest_variable<FieldT>(pb, 256, ""));

        // final padding = base_padding + length
        pb_variable_array<FieldT> length_padding =
            from_bits({  
                sha256_base_padding,            // base_padding
                sha256_two_block_message_length // length of message (576 bits)
            }); // 56*8=448bits

        block1.reset(new block_variable<FieldT>(pb, {
            v,           // 64bits
            sn,          // 256bits
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
            *cmtA,
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
        pb_variable_array<FieldT>& pk_recv, // a random 256bits receiver's address
        pb_variable_array<FieldT>& sn_s,    // 256bits serial number associsated with a balance transferred between two accounts
        pb_variable_array<FieldT>& r,       // 256bits random number
        pb_variable_array<FieldT>& sn_old,  // 256bits serial number about sender
        std::shared_ptr<digest_variable<FieldT>> cmtS // 256bits hash
    ) : gadget<FieldT>(pb, "sha256_three_block_gadget") {

        pb_variable_array<FieldT> first_of_sn_s(sn_s.begin(), sn_s.begin()+192);
        pb_variable_array<FieldT> last_of_sn_s(sn_s.begin()+192, sn_s.end());

        pb_variable_array<FieldT> first_of_sn_old(sn_old.begin(), sn_old.begin()+192);
        pb_variable_array<FieldT> last_of_sn_old(sn_old.begin()+192, sn_old.end());

        intermediate_hash1.reset(new digest_variable<FieldT>(pb, 256, ""));
        intermediate_hash2.reset(new digest_variable<FieldT>(pb, 256, ""));

        // final padding = base_padding + length
        pb_variable_array<FieldT> length_padding =
            from_bits({  
                sha256_base_padding,            // base_padding
                sha256_two_block_message_length // length of message (576 bits)
            }); // 56*8=448bits

        block1.reset(new block_variable<FieldT>(pb, {
            v,                // 64bits
            pk_recv,          // 256bits
            first_of_sn_s     // 192bits
        }, "sha256_three_block_gadget_block1"));

        block2.reset(new block_variable<FieldT>(pb, {
            last_of_sn_s,      // (256-192)=64bits
            r,                 // 256bits
            first_of_sn_old    // 192bits 
        }, "sha256_three_block_gadget_block2"));

        block3.reset(new block_variable<FieldT>(pb, {
            last_of_sn_old,    // (256-192)=64bits
            length_padding     // 448bits 
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

        hasher2.reset(new sha256_compression_function_gadget<FieldT>(
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