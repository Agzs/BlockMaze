/**********************************************
 * comparison_gadget and addition_constraint
 * value_s < balance for Mint, 
 * value_old + value_s == value for Mint
 * publicData: balance, value_s, 
 * privateData: value_old, value, 
 * ********************************************/
template<typename FieldT>
class note_gadget_with_comparison_and_addition_for_balance : public note_gadget_with_packing<FieldT> { // 基类和比较类组合，基本的note_gadget和comparison_gadget (value_s)
public:   

    note_gadget_with_comparison_and_addition_for_balance(
        protoboard<FieldT> &pb,
        pb_variable_array<FieldT> &value,
        pb_variable_array<FieldT> &value_old,
        pb_variable_array<FieldT> &value_s,
        std::shared_ptr<digest_variable<FieldT>> &r,
        std::shared_ptr<digest_variable<FieldT>> &r_old,
        std::shared_ptr<digest_variable<FieldT>> &sn,
        std::shared_ptr<digest_variable<FieldT>> &sn_old
    ) : note_gadget_with_packing<FieldT>(pb, value, value_old, value_s, r, r_old, sn, sn_old)
    { }

    void generate_r1cs_constraints() { // const Note& note
        note_gadget_with_packing<FieldT>::generate_r1cs_constraints();

        // 1 * (value_old + value_s) = this->value 
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, (this->value_old_packed + this->value_s_packed), this->value_packed),
                                 FMT(this->annotation_prefix, " equal"));

    }
    
    void generate_r1cs_witness(const Note& note_old, const Note& note, uint64_t v_s) { // 为变量生成约束
        note_gadget_with_packing<FieldT>::generate_r1cs_witness(note_old, note, v_s);
    }
};
