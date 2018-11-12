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

    // void generate_r1cs_witness(const Note& note) { // 为变量生成约束
    void generate_r1cs_witness(uint64_t rr, uint64_t v) { // 为变量生成约束
        r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(rr));
        value.fill_with_bits(this->pb, uint64_to_bool_vector(v));
    }
};

/*****************************************************
 * note_gadget_with_packing for packing value, value_old and value_s
 * ***************************************************/
template<typename FieldT>
class note_gadget_with_packing : public gadget<FieldT> { // 基类和比较类组合，基本的note_gadget和comparison_gadget (value_s)
public:
    pb_variable_array<FieldT> value; // 64位的value, 操作后的账户余额，也是当前最新的账户余额
    pb_variable<FieldT> value_packed;
    std::shared_ptr<packing_gadget<FieldT> > pack_value;
    
    pb_variable_array<FieldT> value_old; // 64位的value，操作前的账户余额
    pb_variable<FieldT> value_old_packed;
    std::shared_ptr<packing_gadget<FieldT> > pack_value_old;

    pb_variable_array<FieldT> value_s; // 64位的value，待操作的账户余额
    pb_variable<FieldT> value_s_packed;
    std::shared_ptr<packing_gadget<FieldT> > pack_value_s;

    std::shared_ptr<digest_variable<FieldT>> r; // 256位的随机数r

    note_gadget_with_packing(protoboard<FieldT> &pb) : gadget<FieldT>(pb) {
        value.allocate(pb, 64);
        value_packed.allocate(pb);
        pack_value.reset(new packing_gadget<FieldT>(pb, value, value_packed,
                                                    FMT(this->annotation_prefix, " pack_value")));
        
        value_old.allocate(pb, 64);
        value_old_packed.allocate(pb);
        pack_value_old.reset(new packing_gadget<FieldT>(pb, value_old, value_old_packed,
                                                    FMT(this->annotation_prefix, " pack_value_old")));

        value_s.allocate(pb, 64);
        value_s_packed.allocate(pb, "value_s_packed");
        pack_value_s.reset(new packing_gadget<FieldT>(pb, value_s, value_s_packed,
                                                    FMT(this->annotation_prefix, " pack_value_s")));
        
        r.reset(new digest_variable<FieldT>(pb, 256, "random number"));
    }

    void generate_r1cs_constraints() { // const Note& note

        pack_value_old->generate_r1cs_constraints(true);

        pack_value_s->generate_r1cs_constraints(true);

        pack_value->generate_r1cs_constraints(true);

        r->generate_r1cs_constraints(); // 随机数的约束
    }

    void generate_r1cs_witness(uint64_t rr, uint64_t v, uint64_t v_old, uint64_t v_s) { // 为变量生成约束

        value.fill_with_bits(this->pb, uint64_to_bool_vector(v));
        pack_value->generate_r1cs_witness_from_bits();
        
        value_old.fill_with_bits(this->pb, uint64_to_bool_vector(v_old));
        pack_value_old->generate_r1cs_witness_from_bits();

        value_s.fill_with_bits(this->pb, uint64_to_bool_vector(v_s));
        pack_value_s->generate_r1cs_witness_from_bits();

        r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(rr));
    }
};


/****************************************************************************
 * note_gadget_with_packing and add_gadget, for A + B == C
 * (value_old_packed + value_s_packed) == value_packed for Mint and Deposit
 * ***************************************************************************/
template<typename FieldT>
class note_gadget_with_add : public gadget<FieldT> { // 基类和加法类组合，基本的note_gadget和加法的约束(value = value_old + value_s)
public:
    std::shared_ptr<note_gadget_with_packing<FieldT>> packThree;

    note_gadget_with_add(protoboard<FieldT>& pb) : gadget<FieldT>(pb) {
        packThree.reset(new note_gadget_with_packing<FieldT>(pb));
    }

    void generate_r1cs_constraints() { // const Note& note

        packThree->generate_r1cs_constraints();
        
        // 1 * (value_old + value_s) = this->value 
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, (value_old_packed + value_s_packed), value_packed),
                                 FMT(this->annotation_prefix, " equal"));
    }

    void generate_r1cs_witness(uint256 rr, uint64_t v, uint64_t v_old, uint64_t v_s) { // 为变量生成约束
        packThree->generate_r1cs_witness(rr, v, v_old, v_s);
    }
};

/****************************************************************************
 * note_gadget_with_packing and sub_gadget, for A - B == C
 * (value_old_packed - value_s_packed) == value_packed for Update and Redeem
 * ***************************************************************************/
template<typename FieldT>
class note_gadget_with_sub : public gadget<FieldT> { // 基类和加法类组合，基本的note_gadget和加法的约束(value = value_old + value_s)
public:
    std::shared_ptr<note_gadget_with_packing<FieldT>> packThree;

    note_gadget_with_sub(protoboard<FieldT>& pb) : gadget<FieldT>(pb) {
        packThree.reset(new note_gadget_with_packing<FieldT>(pb));
    }

    void generate_r1cs_constraints() { // const Note& note

        packThree->generate_r1cs_constraints();
        
        // 1 * (value_old + value_s) = this->value 
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, (value_old_packed - value_s_packed), value_packed),
                                 FMT(this->annotation_prefix, " equal"));
    }

    void generate_r1cs_witness(uint256 rr, uint64_t v, uint64_t v_old, uint64_t v_s) { // 为变量生成约束
        packThree->generate_r1cs_witness(rr, v, v_old, v_s);
    }
};

/**********************************************
 * less_cmp_gadget for judging A < B
 * ********************************************/
template<typename FieldT>
class less_comparison_gadget : public gadget<FieldT> {
private:
    pb_variable_array<FieldT> alpha;
    pb_variable<FieldT> alpha_packed;
    std::shared_ptr<packing_gadget<FieldT> > pack_alpha;

    std::shared_ptr<disjunction_gadget<FieldT> > all_zeros_test;
    pb_variable<FieldT> not_all_zeros;
public:
    const size_t n = 64;
    const pb_linear_combination<FieldT> A;
    const pb_linear_combination<FieldT> B;

    less_cmp_gadget(protoboard<FieldT>& pb,
                      const pb_linear_combination<FieldT> &A,
                      const pb_linear_combination<FieldT> &B,
                      const std::string &annotation_prefix="") :
        gadget<FieldT>(pb, annotation_prefix), A(A), B(B)
    {
        alpha.allocate(pb, n, FMT(this->annotation_prefix, " alpha"));
        alpha.emplace_back(0); // alpha[n] is less_or_eq, set alpha[n] = 0, just proof A <= B

        // this->pb.val(alpha) = this->pb.val(1);

        alpha_packed.allocate(pb, FMT(this->annotation_prefix, " alpha_packed"));
        not_all_zeros.allocate(pb, FMT(this->annotation_prefix, " not_all_zeros"));

        pack_alpha.reset(new packing_gadget<FieldT>(pb, alpha, alpha_packed,
                                                    FMT(this->annotation_prefix, " pack_alpha")));

        all_zeros_test.reset(new disjunction_gadget<FieldT>(pb,
                                                            pb_variable_array<FieldT>(alpha.begin(), alpha.begin() + n),
                                                            not_all_zeros,
                                                            FMT(this->annotation_prefix, " all_zeros_test")));
    };

    void generate_r1cs_constraints()
    {
        /*
        packed(alpha) = 2^n + B - A

        not_all_zeros = \bigvee_{i=0}^{n-1} alpha_i 或取

        if B - A > 0, then 2^n + B - A > 2^n,
            so alpha_n = 1 and not_all_zeros = 1
        if B - A = 0, then 2^n + B - A = 2^n,
            so alpha_n = 1 and not_all_zeros = 0
        if B - A < 0, then 2^n + B - A \in {0, 1, \ldots, 2^n-1},
            so alpha_n = 0

        therefore alpha_n = less_or_eq and alpha_n * not_all_zeros = 1
        */

        /* not_all_zeros to be Boolean, alpha_i are Boolean by packing gadget */
        generate_boolean_r1cs_constraint<FieldT>(this->pb, not_all_zeros,
                                        FMT(this->annotation_prefix, " not_all_zeros"));

        /* constraints for packed(alpha) = 2^n + B - A */
        pack_alpha->generate_r1cs_constraints(true);

        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, (FieldT(2)^n) + B - A, alpha_packed), FMT(this->annotation_prefix, " main_constraint"));

        /* compute result */
        all_zeros_test->generate_r1cs_constraints();
        
        /*********************************************************************************
         * 初始化时，我们预设 less_or_eq = 0, 即 alpha_n = 0,
         * less_or_eq * not_all_zeros = less
         * 0 * not_all_zeros = 0 => less => A < B
         * 0 * not_all_zeros = 1 => eq => A = B   
         * 1 * not_all_zeros = 1 => less_or_eq => A <= B
         * 1 * not_all_zeros = 0 => nothing
         * 1 * not_all_zeros = not_all_zeros => less_or_eq => A <= B
         * 0 * not_all_zeros = not_all_zeros => eq => A = B  
         * this->pb.val(0)== this->pb.val(1), 所以 not_all_zeros=1 时成立
         * ********************************************************************************/
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(FieldT::one(), not_all_zeros, FieldT::one()),
                                    FMT(this->annotation_prefix, " less"));
    }
    void generate_r1cs_witness(){
        A.evaluate(this->pb);
        B.evaluate(this->pb);

        /* unpack 2^n + B - A into alpha_packed */
        this->pb.val(alpha_packed) = (FieldT(2)^n) + this->pb.lc_val(B) - this->pb.lc_val(A);
        pack_alpha->generate_r1cs_witness_from_packed();

        /* compute result */
        all_zeros_test->generate_r1cs_witness();
    }
};

/**********************************************
 * comparison_gadget and addition_constraint
 * value_s < balance for Mint, 
 * value_old + value_s == value for Mint
 * ********************************************/
template<typename FieldT>
class note_gadget_with_comparison_and_addition_for_balance : public gadget<FieldT> { // 基类和比较类组合，基本的note_gadget和comparison_gadget (value_s)
public:
    std::shared_ptr<note_gadget_with_packing<FieldT>> packThree;
   
    pb_variable_array<FieldT> balance; // 64位的value
    pb_variable<FieldT> balance_packed;
    std::shared_ptr<packing_gadget<FieldT> > pack_balance;

    std::shared_ptr<less_comparison_gadget<FieldT> > less_cmp;

    note_gadget_with_comparison_and_addition_for_balance(protoboard<FieldT> &pb) : gadget<FieldT>(pb) {
        packThree.reset(new note_gadget_with_packing<FieldT>(pb));

        balance.allocate(pb, 64);
        balance_packed.allocate(pb, "balance_packed");
        pack_balance.reset(new packing_gadget<FieldT>(pb, balance, balance_packed,
                                                    FMT(this->annotation_prefix, " pack_balance")));

        less_cmp.reset(new less_comparison_gadget<FieldT>(pb, packThree->value_s_packed, balance_packed,
                                                    FMT(this->annotation_prefix, " less_cmp")));
    }

    void generate_r1cs_constraints() { // const Note& note
        packThree->generate_r1cs_constraints();

        // 1 * (value_old + value_s) = this->value 
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, (packThree->value_old_packed + packThree->value_s_packed), packThree->value_packed),
                                 FMT(this->annotation_prefix, " equal"));

        pack_balance->generate_r1cs_constraints(true);

        less_cmp->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(uint64_t rr, uint64_t v, uint64_t v_old, uint64_t v_s, uint64_t b) { // 为变量生成约束
        packThree->generate_r1cs_witness(rr, v, v_old, v_s);

        balance.fill_with_bits(this->pb, uint64_to_bool_vector(b));
        pack_balance->generate_r1cs_witness_from_bits();

        less_cmp->generate_r1cs_witness();
    }
};

/**********************************************
 * comparison_gadget and subtraction_constraint 
 * value_s < value_old for Update and Redeem
 * value_old - value_s == value for Update and Redeem
 * ********************************************/
template<typename FieldT>
class note_gadget_with_comparison_and_subtraction_for_value_old : public gadget<FieldT> { // 基类和比较类组合，基本的note_gadget和comparison_gadget (value_s)
public:
    std::shared_ptr<note_gadget_with_packing<FieldT>> packThree;

    std::shared_ptr<less_comparison_gadget<FieldT> > less_cmp;

    note_gadget_with_comparison_and_subtraction_for_value_old(protoboard<FieldT> &pb) : gadget<FieldT>(pb) {
        packThree.reset(new note_gadget_with_packing<FieldT>(pb));

        less_cmp.reset(new less_comparison_gadget<FieldT>(pb, packThree->value_s_packed, packThree->value_old_packed,
                                                    FMT(this->annotation_prefix, " less_cmp")));
    }

    void generate_r1cs_constraints() { // const Note& note
        packThree->generate_r1cs_constraints();

        // 1 * (value_old - value_s) = this->value 
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, (packThree->value_old_packed - packThree->value_s_packed), packThree->value_packed),
                                 FMT(this->annotation_prefix, " equal"));

        less_cmp->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(uint64_t rr, uint64_t v, uint64_t v_old, uint64_t v_s, uint64_t b) { // 为变量生成约束
        packThree->generate_r1cs_witness(rr, v, v_old, v_s);

        less_cmp->generate_r1cs_witness();
    }
};

//=================== All above are successful ==================================================

/**********************************************************
 * sha256_two_block_gadget, Add_gadget, Comparison_gadget
 **********************************************************/
template<typename FieldT>
class commitment_with_add_and_less_gadget : note_gadget_with_packing<FieldT> {
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
    ) : note_gadget_with_packing<FieldT>(pb) {
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
        note_gadget_with_packing<FieldT>::generate_r1cs_constraints(); // 为基类生成约束

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

// ====================== original code =============================

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
