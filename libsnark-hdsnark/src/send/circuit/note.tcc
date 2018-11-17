/*****************************************************
 * note_gadget_with_packing for packing value_old and value_s
 * ***************************************************/
template<typename FieldT>
class note_gadget_with_packing : public gadget<FieldT> { // 基类和比较类组合，基本的note_gadget
public:    
    pb_variable_array<FieldT> value_old; // 64位的value，操作前的账户余额
    pb_variable<FieldT> value_old_packed;

    std::shared_ptr<digest_variable<FieldT>> sn_old; // 256位的随机数serial number
    std::shared_ptr<digest_variable<FieldT>> r_old; // 256位的随机数r
    
    pb_variable_array<FieldT> value_s; // 64位的value，待操作的账户余额
    pb_variable<FieldT> value_s_packed;

    std::shared_ptr<digest_variable<FieldT>> pk_recv; // a random 160bits receiver's address
    std::shared_ptr<digest_variable<FieldT>> sn_s; // 256位的随机数serial number
    std::shared_ptr<digest_variable<FieldT>> r_s; // 256位的随机数r

    note_gadget_with_packing(
        protoboard<FieldT> &pb,
        pb_variable_array<FieldT> &value_old,
        std::shared_ptr<digest_variable<FieldT>> &sn_old,
        std::shared_ptr<digest_variable<FieldT>> &r_old,
        pb_variable_array<FieldT> &value_s,
        std::shared_ptr<digest_variable<FieldT>> &pk_recv,
        std::shared_ptr<digest_variable<FieldT>> &sn_s,
        std::shared_ptr<digest_variable<FieldT>> &r_s
    ) : gadget<FieldT>(pb), 
        value_old(value_old), 
        sn_old(sn_old), 
        r_old(r_old),
        value_s(value_s), 
        pk_recv(pk_recv),
        sn_s(sn_s),
        r_s(r_s)
    {        
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

        sn_old->generate_r1cs_constraints(); // 随机数的约束
        r_old->generate_r1cs_constraints(); // 随机数的约束
        pk_recv->generate_r1cs_constraints(); // 随机数的约束
        sn_s->generate_r1cs_constraints(); // 随机数的约束
        r_s->generate_r1cs_constraints(); // 随机数的约束
    }

    void generate_r1cs_witness(const Note& note_old, const NoteS& notes) { // 为变量生成约束        
        value_old.fill_with_bits(this->pb, uint64_to_bool_vector(note_old.value));
        this->pb.lc_val(value_old_packed) = value_old.get_field_element_from_bits_by_order(this->pb);

        sn_old->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note_old.sn));
        r_old->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note_old.r));

        value_s.fill_with_bits(this->pb, uint64_to_bool_vector(notes.value));
        this->pb.lc_val(value_s_packed) = value_s.get_field_element_from_bits_by_order(this->pb);

        pk_recv->bits.fill_with_bits(this->pb, uint160_to_bool_vector(notes.pk));
        sn_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(notes.sn_s));
        r_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(notes.r));
    }
};