/**********************************************
 * comparison_gadget and addition_constraint
 * value_s < balance for Mint, 
 * value_old + value_s == value for Mint
 * publicData: balance, value_s, 
 * privateData: value_old, value, 
 * ********************************************/
template<typename FieldT>
class note_gadget_with_comparison_and_subtraction_for_value_old : public note_gadget_with_packing<FieldT> { // 基类和比较类组合，基本的note_gadget和comparison_gadget (value_s)
public:   
    std::shared_ptr<less_comparison_gadget<FieldT> > less_cmp;

    note_gadget_with_comparison_and_subtraction_for_value_old(
        protoboard<FieldT> &pb,
        pb_variable_array<FieldT> &value,
        pb_variable_array<FieldT> &value_old,
        pb_variable_array<FieldT> &value_s,
        std::shared_ptr<digest_variable<FieldT>> &r,
        std::shared_ptr<digest_variable<FieldT>> &r_old,
        std::shared_ptr<digest_variable<FieldT>> &sn,
        std::shared_ptr<digest_variable<FieldT>> &sn_old
    ) : note_gadget_with_packing<FieldT>(pb, value, value_old, value_s, r, r_old, sn, sn_old)
    {
        less_cmp.reset(new less_comparison_gadget<FieldT>(pb, this->value_s_packed, this->value_old_packed,
                                                    FMT(this->annotation_prefix, " less_cmp")));
    }

    void generate_r1cs_constraints() { // const Note& note
        note_gadget_with_packing<FieldT>::generate_r1cs_constraints();

        // 1 * (value_old + value_s) = this->value 
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, (this->value_old_packed - this->value_s_packed), this->value_packed),
                                 FMT(this->annotation_prefix, " equal"));

        less_cmp->generate_r1cs_constraints();
    }
    
    void generate_r1cs_witness(const Note& note_old, const Note& note, uint64_t v_s) { // 为变量生成约束
        note_gadget_with_packing<FieldT>::generate_r1cs_witness(note_old, note, v_s);

        less_cmp->generate_r1cs_witness();
    }
};
