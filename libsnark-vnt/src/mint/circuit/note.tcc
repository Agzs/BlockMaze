//=============================================================
/*****************************************************
 * note_gadget_with_packing for packing value, value_old and value_s
 * ***************************************************/
template<typename FieldT>
class note_gadget_with_packing : public gadget<FieldT> { // 基类和比较类组合，基本的note_gadget和comparison_gadget (value_s)
public:
    pb_variable_array<FieldT> value; // 64位的value, 操作后的账户余额，也是当前最新的账户余额
    pb_variable<FieldT> value_packed;
    
    pb_variable_array<FieldT> value_old; // 64位的value，操作前的账户余额
    pb_variable<FieldT> value_old_packed;

    pb_variable_array<FieldT> value_s; // 64位的value，待操作的账户余额
    pb_variable<FieldT> value_s_packed;

    std::shared_ptr<digest_variable<FieldT>> sk; // 256位的sk

    std::shared_ptr<digest_variable<FieldT>> r; // 256位的随机数r
    std::shared_ptr<digest_variable<FieldT>> r_old; // 256位的随机数r

    note_gadget_with_packing(
        protoboard<FieldT> &pb,
        pb_variable_array<FieldT> &value,
        pb_variable_array<FieldT> &value_old,
        pb_variable_array<FieldT> &value_s,
        std::shared_ptr<digest_variable<FieldT>> &sk,
        std::shared_ptr<digest_variable<FieldT>> &r,
        std::shared_ptr<digest_variable<FieldT>> &r_old
    ) : gadget<FieldT>(pb), value(value), 
        value_old(value_old), 
        value_s(value_s), 
        sk(sk),
        r(r),
        r_old(r_old)
    {
        value_packed.allocate(pb, "value_packed");
        
        value_old_packed.allocate(pb, "value_old_packed");

        value_s_packed.allocate(pb, "value_s_packed");
    }

    void generate_r1cs_constraints() { // const Note& note

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
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value[i],
                "boolean_value"
            );
        }

        sk->generate_r1cs_constraints(); // 随机数的约束

        r->generate_r1cs_constraints(); // 随机数的约束
        r_old->generate_r1cs_constraints(); // 随机数的约束
    }

    void generate_r1cs_witness(const Note& note_old, const Note& note, uint64_t v_s, uint256 sk_data) { // 为变量生成约束
        value.fill_with_bits(this->pb, uint64_to_bool_vector(note.value));
        this->pb.lc_val(value_packed) = value.get_field_element_from_bits_by_order(this->pb);
        
        value_old.fill_with_bits(this->pb, uint64_to_bool_vector(note_old.value));
        this->pb.lc_val(value_old_packed) = value_old.get_field_element_from_bits_by_order(this->pb);

        value_s.fill_with_bits(this->pb, uint64_to_bool_vector(v_s));
        this->pb.lc_val(value_s_packed) = value_s.get_field_element_from_bits_by_order(this->pb);

        sk->bits.fill_with_bits(this->pb, uint256_to_bool_vector(sk_data));

        r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note.r));
        r_old->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note_old.r));
    }
};