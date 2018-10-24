/**********************************************
 * Just note_gadget
 * ********************************************/
template<typename FieldT>
class note_gadget : public gadget<FieldT> { // 基类，基本的note_gadget,仅含value和随机数r
public:
    pb_variable_array<FieldT> value; // 64位的value
    std::shared_ptr<digest_variable<FieldT>> r; // 256位的随机数r

    note_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb) {
        value.allocate(pb, 64);
        r.reset(new digest_variable<FieldT>(pb, 256, "random number"));
    }

    void generate_r1cs_constraints() {
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value[i],
                "boolean_value"
            );
        }

        r->generate_r1cs_constraints(); // 随机数的约束
    }

    void generate_r1cs_witness(const Note& note) { // 为变量生成约束
        r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note.r));
        value.fill_with_bits(this->pb, uint64_to_bool_vector(note.value));
    }
};

/**********************************************
 * note_gadget and add_gadget
 * ********************************************/
template<typename FieldT>
class note_gadget_with_add : public gadget<FieldT> { // 基类，基本的note_gadget,仅含value和随机数r
public:
    pb_variable_array<FieldT> value; // 64位的value
    pb_variable_array<FieldT> value_old; // 64位的value
    pb_variable_array<FieldT> value_s; // 64位的value
    std::shared_ptr<digest_variable<FieldT>> r; // 256位的随机数r

    note_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb) {
        value.allocate(pb, 64);
        value_old.allocate(pb, 64);
        value_s.allocate(pb, 64);
        r.reset(new digest_variable<FieldT>(pb, 256, "random number"));
    }

    void generate_r1cs_constraints() { // const Note& note
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value[i],
                "boolean_value"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value_old[i],
                "boolean_value_old"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value_s[i],
                "boolean_value_s"
            );
        }

        // Addition constraint
        // 1 * (value_old + value_s) = this->value 
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
            1,
            (packed_addition(this->value_old) + packed_addition(this->value_s)),
            packed_addition(this->value)
        ), "1 * (value_old + value_s) = this->value");

        // There may exist error !!!!
        // this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
        //     1,
        //     (packed_addition_fieldT(this->value_old) + packed_addition_fieldT(this->value_s)),
        //     packed_addition_fieldT(this->value)
        // ), "1 * (value_old + value_s) = this->value"));
        
        // this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
        //     packed_addition(this->value),
        //     FieldT::one(),
        //     FieldT::one() * (note.value_old + note.value_s)
        // ), "");

        r->generate_r1cs_constraints(); // 随机数的约束
    }

    void generate_r1cs_witness(uint256 r, uint64_t value, uint64_t value_old, uint64_t value_s) { // 为变量生成约束
        r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note.r));
        value.fill_with_bits(this->pb, uint64_to_bool_vector(note.value));
        value_old.fill_with_bits(this->pb, uint64_to_bool_vector(note.value_old));
        value_s.fill_with_bits(this->pb, uint64_to_bool_vector(note.value_s));
    }
};

/***********************************************
 * note_gadget, add_gadget and comparison_gadget
 * ********************************************/
template<typename FieldT>
class note_gadget_with_add_and_comparison : public gadget<FieldT> { // 基类，基本的note_gadget,仅含value和随机数r
public:
    pb_variable_array<FieldT> value; // 64位的value
    pb_variable_array<FieldT> value_old; // 64位的value
    pb_variable_array<FieldT> value_s; // 64位的value
    std::shared_ptr<digest_variable<FieldT>> r; // 256位的随机数r

    note_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb) {
        value.allocate(pb, 64);
        value_old.allocate(pb, 64);
        value_s.allocate(pb, 64);
        r.reset(new digest_variable<FieldT>(pb, 256, "random number"));
    }

    void generate_r1cs_constraints() { // const Note& note
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value[i],
                "boolean_value"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value_old[i],
                "boolean_value_old"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value_s[i],
                "boolean_value_s"
            );
        }

        // Addition constraint
        // 1 * (value_old + value_s) = this->value 
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
            1,
            (packed_addition(this->value_old) + packed_addition(this->value_s)),
            packed_addition(this->value)
        ), "1 * (value_old + value_s) = this->value");

        // There may exist error !!!!
        // this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
        //     1,
        //     (packed_addition_fieldT(this->value_old) + packed_addition_fieldT(this->value_s)),
        //     packed_addition_fieldT(this->value)
        // ), "1 * (value_old + value_s) = this->value"));
        
        // this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
        //     packed_addition(this->value),
        //     FieldT::one(),
        //     FieldT::one() * (note.value_old + note.value_s)
        // ), "");

        r->generate_r1cs_constraints(); // 随机数的约束
    }

    void generate_r1cs_witness(uint256 r, uint64_t value, uint64_t value_old, uint64_t value_s) { // 为变量生成约束
        r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note.r));
        value.fill_with_bits(this->pb, uint64_to_bool_vector(note.value));
        value_old.fill_with_bits(this->pb, uint64_to_bool_vector(note.value_old));
        value_s.fill_with_bits(this->pb, uint64_to_bool_vector(note.value_s));
    }
};

/**********************************************
 * note_gadget, sub_gadget and comparison_gadget
 * ********************************************/
template<typename FieldT>
class note_gadget_with_sub_and_comparison : public gadget<FieldT> { // 基类，基本的note_gadget,仅含value和随机数r
public:
    pb_variable_array<FieldT> value; // 64位的value
    pb_variable_array<FieldT> value_old; // 64位的value
    pb_variable_array<FieldT> value_s; // 64位的value
    std::shared_ptr<digest_variable<FieldT>> r; // 256位的随机数r

    note_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb) {
        value.allocate(pb, 64);
        value_old.allocate(pb, 64);
        value_s.allocate(pb, 64);
        r.reset(new digest_variable<FieldT>(pb, 256, "random number"));
    }

    void generate_r1cs_constraints() { // const Note& note
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value[i],
                "boolean_value"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value_old[i],
                "boolean_value_old"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value_s[i],
                "boolean_value_s"
            );
        }

        // Addition constraint
        // 1 * (value_old + value_s) = this->value 
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
            1,
            (packed_addition(this->value_old) + packed_addition(this->value_s)),
            packed_addition(this->value)
        ), "1 * (value_old + value_s) = this->value");

        // There may exist error !!!!
        // this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
        //     1,
        //     (packed_addition_fieldT(this->value_old) + packed_addition_fieldT(this->value_s)),
        //     packed_addition_fieldT(this->value)
        // ), "1 * (value_old + value_s) = this->value"));
        
        // this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
        //     packed_addition(this->value),
        //     FieldT::one(),
        //     FieldT::one() * (note.value_old + note.value_s)
        // ), "");

        r->generate_r1cs_constraints(); // 随机数的约束
    }

    void generate_r1cs_witness(uint256 r, uint64_t value, uint64_t value_old, uint64_t value_s) { // 为变量生成约束
        r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note.r));
        value.fill_with_bits(this->pb, uint64_to_bool_vector(note.value));
        value_old.fill_with_bits(this->pb, uint64_to_bool_vector(note.value_old));
        value_s.fill_with_bits(this->pb, uint64_to_bool_vector(note.value_s));
    }
};

/**********************************************************
 * sha256_two_block_gadget, Add_gadget, Comparison_gadget
 **********************************************************/
template<typename FieldT>
class commitment_with_add_and_less_gadget : note_gadget<FieldT> {
private:
    // commitment with sha256_two_block_gadget
    std::shared_ptr<digest_variable<FieldT>> commitment; // cm
    std::shared_ptr<sha256_two_block_gadget<FieldT>> commit_to_inputs; // note_commitment
    
    // comparison_gadget 

public:
    commitment_with_add_and_less_gadget(
        protoboard<FieldT>& pb,
        pb_variable<FieldT>& ZERO,
        pb_variable_array<FieldT>& sn // serial number
    ) : note_gadget<FieldT>(pb) {
        commitment.reset(new digest_variable<FieldT>(pb, 256, "commmitment"));

        commit_to_inputs.reset(new note_commitment_gadget<FieldT>( 
            pb,
            ZERO,
            this->value,      // 64bits value for Mint
            sn,                // 256bits serial number
            this->r->bits,     // 256bits random number
            commitment
        ));
    }

    // 约束函数，为commitment_with_add_and_less_gadget的变量生成约束
    void generate_r1cs_constraints() { 
        note_gadget<FieldT>::generate_r1cs_constraints(); // 为基类生成约束

        // TODO: These constraints may not be necessary if SHA256
        // already boolean constrains its outputs.
        commitment->generate_r1cs_constraints();

        commit_to_inputs->generate_r1cs_constraints();

        // value * (1 - enforce) = 0
        // Given `enforce` is boolean constrained:
        // If `value` is zero, `enforce` _can_ be zero.
        // If `value` is nonzero, `enforce` _must_ be one.
        generate_boolean_r1cs_constraint<FieldT>(this->pb, value_enforce,"");

        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
            packed_addition(this->value),
            (1 - value_enforce),
            0
        ), "");

        // Add constraint
        // 1 * (value_old + value_s) = this->value
    }

    // 证据函数，为commitment_with_add_and_less_gadget的变量生成证据
    void generate_r1cs_witness(
        const MerklePath& path,
        const SpendingKey& key,
        const Note& note
    ) {
        note_gadget<FieldT>::generate_r1cs_witness(note);

        // Witness a_sk for the input
        a_sk->bits.fill_with_bits(
            this->pb,
            trailing252(uint256_to_bool_vector(key))
        );

        // Witness a_pk for a_sk with PRF_addr
        spend_authority->generate_r1cs_witness();

        // [SANITY CHECK] Witness a_pk with note information
        a_pk->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.a_pk)
        );

        // Witness rho for the input note
        rho->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.rho)
        );

        // Witness the nullifier for the input note
        expose_nullifiers->generate_r1cs_witness();

        // Witness the commitment of the input note
        commit_to_inputs->generate_r1cs_witness();

        // [SANITY CHECK] Ensure the commitment is
        // valid.
        commitment->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.cm())
        );

        // Set enforce flag for nonzero input value
        this->pb.val(value_enforce) = (note.value != 0) ? FieldT::one() : FieldT::zero();

        // Witness merkle tree authentication path
        witness_input->generate_r1cs_witness(path);
    }
};

// ===================================================

template<typename FieldT>
class input_note_gadget : public note_gadget<FieldT> { // 输入的note_gadget
private:
    std::shared_ptr<digest_variable<FieldT>> a_pk; // addr_pk
    std::shared_ptr<digest_variable<FieldT>> rho; // 使用phi和h_sig计算得到rho，用于计算sn P56

    std::shared_ptr<digest_variable<FieldT>> commitment; // cm
    std::shared_ptr<note_commitment_gadget<FieldT>> commit_to_inputs; // note_commitment P39+P62
    pb_variable<FieldT> value_enforce; // merkle_tree_gadget的参数
    std::shared_ptr<merkle_tree_gadget<FieldT>> witness_input; // merkle_tree_gadget

    std::shared_ptr<PRF_addr_a_pk_gadget<FieldT>> spend_authority; // 可花费证明 PRF_addr_a_pk P56
    std::shared_ptr<PRF_nf_gadget<FieldT>> expose_nullifiers; // PRF_nf was called PRF_sn in P18 P40
public:
    std::shared_ptr<digest_variable<FieldT>> a_sk;

    // 构造函数，初始化input_note_gadget的私有变量
    input_note_gadget(
        protoboard<FieldT>& pb,
        pb_variable<FieldT>& ZERO,
        std::shared_ptr<digest_variable<FieldT>> nullifier, // serial number
        digest_variable<FieldT> rt
    ) : note_gadget<FieldT>(pb) {
        a_sk.reset(new digest_variable<FieldT>(pb, 252, ""));
        a_pk.reset(new digest_variable<FieldT>(pb, 256, ""));
        rho.reset(new digest_variable<FieldT>(pb, 256, ""));
        commitment.reset(new digest_variable<FieldT>(pb, 256, ""));

        spend_authority.reset(new PRF_addr_a_pk_gadget<FieldT>( 
            pb,
            ZERO,
            a_sk->bits,
            a_pk
        ));

        expose_nullifiers.reset(new PRF_nf_gadget<FieldT>( 
            pb,
            ZERO,
            a_sk->bits,
            rho->bits,
            nullifier
        ));

        commit_to_inputs.reset(new note_commitment_gadget<FieldT>( 
            pb,
            ZERO,
            a_pk->bits,
            this->value,
            rho->bits,
            this->r->bits,
            commitment
        ));

        value_enforce.allocate(pb);

        witness_input.reset(new merkle_tree_gadget<FieldT>(
            pb,
            *commitment,
            rt,
            value_enforce
        ));
    }
    
    // 约束函数，为input_note_gadget的变量生成约束
    void generate_r1cs_constraints() { 
        note_gadget<FieldT>::generate_r1cs_constraints(); // 为基类生成约束

        a_sk->generate_r1cs_constraints();
        rho->generate_r1cs_constraints();

        // TODO: These constraints may not be necessary if SHA256
        // already boolean constrains its outputs.
        a_pk->generate_r1cs_constraints();
        commitment->generate_r1cs_constraints();

        spend_authority->generate_r1cs_constraints();
        expose_nullifiers->generate_r1cs_constraints();

        commit_to_inputs->generate_r1cs_constraints();

        // value * (1 - enforce) = 0
        // Given `enforce` is boolean constrained:
        // If `value` is zero, `enforce` _can_ be zero.
        // If `value` is nonzero, `enforce` _must_ be one.
        generate_boolean_r1cs_constraint<FieldT>(this->pb, value_enforce,"");

        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
            packed_addition(this->value),
            (1 - value_enforce),
            0
        ), "");

        witness_input->generate_r1cs_constraints();
    }

    // 证据函数，为input_note_gadget的变量生成证据
    void generate_r1cs_witness(
        const MerklePath& path,
        const SpendingKey& key,
        const Note& note
    ) {
        note_gadget<FieldT>::generate_r1cs_witness(note);

        // Witness a_sk for the input
        a_sk->bits.fill_with_bits(
            this->pb,
            trailing252(uint256_to_bool_vector(key))
        );

        // Witness a_pk for a_sk with PRF_addr
        spend_authority->generate_r1cs_witness();

        // [SANITY CHECK] Witness a_pk with note information
        a_pk->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.a_pk)
        );

        // Witness rho for the input note
        rho->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.rho)
        );

        // Witness the nullifier for the input note
        expose_nullifiers->generate_r1cs_witness();

        // Witness the commitment of the input note
        commit_to_inputs->generate_r1cs_witness();

        // [SANITY CHECK] Ensure the commitment is
        // valid.
        commitment->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.cm())
        );

        // Set enforce flag for nonzero input value
        this->pb.val(value_enforce) = (note.value != 0) ? FieldT::one() : FieldT::zero();

        // Witness merkle tree authentication path
        witness_input->generate_r1cs_witness(path);
    }
};

template<typename FieldT>
class output_note_gadget : public note_gadget<FieldT> { // 输出的note_gadget
private:
    std::shared_ptr<digest_variable<FieldT>> rho;
    std::shared_ptr<digest_variable<FieldT>> a_pk;

    std::shared_ptr<PRF_rho_gadget<FieldT>> prevent_faerie_gold; // PRF_rho_gadget P56
    std::shared_ptr<note_commitment_gadget<FieldT>> commit_to_outputs;

public:
    output_note_gadget(
        protoboard<FieldT>& pb,
        pb_variable<FieldT>& ZERO,
        pb_variable_array<FieldT>& phi,
        pb_variable_array<FieldT>& h_sig,
        bool nonce,
        std::shared_ptr<digest_variable<FieldT>> commitment
    ) : note_gadget<FieldT>(pb) {
        rho.reset(new digest_variable<FieldT>(pb, 256, ""));
        a_pk.reset(new digest_variable<FieldT>(pb, 256, ""));

        // Do not allow the caller to choose the same "rho"
        // for any two valid notes in a given view of the
        // blockchain. See protocol specification for more
        // details.
        prevent_faerie_gold.reset(new PRF_rho_gadget<FieldT>(
            pb,
            ZERO,
            phi,
            h_sig,
            nonce,
            rho
        ));

        // Commit to the output notes publicly without
        // disclosing them.
        commit_to_outputs.reset(new note_commitment_gadget<FieldT>(
            pb,
            ZERO,
            a_pk->bits,
            this->value,
            rho->bits,
            this->r->bits,
            commitment
        ));
    }

    void generate_r1cs_constraints() {
        note_gadget<FieldT>::generate_r1cs_constraints();

        a_pk->generate_r1cs_constraints();

        // TODO: This constraint may not be necessary if SHA256
        // already boolean constrains its outputs.
        rho->generate_r1cs_constraints();

        prevent_faerie_gold->generate_r1cs_constraints();

        commit_to_outputs->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(const Note& note) {
        note_gadget<FieldT>::generate_r1cs_witness(note);

        prevent_faerie_gold->generate_r1cs_witness();

        // [SANITY CHECK] Witness rho ourselves with the
        // note information.
        rho->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.rho)
        );

        a_pk->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.a_pk)
        );

        commit_to_outputs->generate_r1cs_witness();
    }
};
