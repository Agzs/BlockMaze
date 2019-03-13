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

    less_comparison_gadget(protoboard<FieldT>& pb,
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
         * 1 * not_all_zeros = 1 => less_or_eq => A < B  正确 
         * 1 * not_all_zeros = 0 => nothing
         * 1 * not_all_zeros = not_all_zeros => less_or_eq => A <= B  正确
         * 0 * not_all_zeros = not_all_zeros => eq => A = B  
         * this->pb.val(0)== this->pb.val(1), 所以 not_all_zeros=1 时成立
         * ********************************************************************************/
        // this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(FieldT::one(), not_all_zeros, FieldT::one()),
        //                             FMT(this->annotation_prefix, "less"));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(FieldT::one(), not_all_zeros, not_all_zeros),
                                    FMT(this->annotation_prefix, "less_or_eq"));
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