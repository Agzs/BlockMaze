/**********************************************
 * comparison_gadget
 * value_s < value_old for Send, 
 * publicData: 
 * privateData: value_old, value_s, 
 * ********************************************/
template<typename FieldT>
class note_gadget_with_comparison_for_value_old : public note_gadget_with_packing<FieldT> { // 基类和比较类组合，基本的note_gadget和comparison_gadget (value_s)
public:   
    std::shared_ptr<less_comparison_gadget<FieldT> > less_cmp;

    note_gadget_with_comparison_for_value_old(
        protoboard<FieldT> &pb,
        pb_variable_array<FieldT> &value_old,
        std::shared_ptr<digest_variable<FieldT>> &sn_old,
        std::shared_ptr<digest_variable<FieldT>> &r_old,
        pb_variable_array<FieldT> &value_s,
        std::shared_ptr<digest_variable<FieldT>> &pk,
        std::shared_ptr<digest_variable<FieldT>> &sn_s,
        std::shared_ptr<digest_variable<FieldT>> &r_s
    ) : note_gadget_with_packing<FieldT>(pb, value_old, sn_old, r_old, value_s, pk, sn_s, r_s)
    {
        less_cmp.reset(new less_comparison_gadget<FieldT>(pb, this->value_s_packed, this->value_old_packed,
                                                    FMT(this->annotation_prefix, " less_cmp")));
    }

    void generate_r1cs_constraints() { 
        note_gadget_with_packing<FieldT>::generate_r1cs_constraints();

        less_cmp->generate_r1cs_constraints();
    }
    
    void generate_r1cs_witness(const Note& note_old, const NoteS& notes) { // 为变量生成约束
        note_gadget_with_packing<FieldT>::generate_r1cs_witness(note_old, notes);

        less_cmp->generate_r1cs_witness();
    }
};
