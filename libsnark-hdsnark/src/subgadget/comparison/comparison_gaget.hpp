#include <cassert>
#include <memory>

#include <libsnark/gadgetlib1/gadget.hpp>

namespace libsnark {

template<typename FieldT>
class less_cmp_gadget : public gadget<FieldT> {
private:
    pb_variable_array<FieldT> alpha;
    pb_variable<FieldT> alpha_packed;
    std::shared_ptr<packing_gadget<FieldT> > pack_alpha;

    std::shared_ptr<disjunction_gadget<FieldT> > all_zeros_test;
    pb_variable<FieldT> not_all_zeros;
public:
    const size_t n;
    const pb_linear_combination<FieldT> A;
    const pb_linear_combination<FieldT> B;

    less_cmp_gadget(protoboard<FieldT>& pb,
                      const size_t n,
                      const pb_linear_combination<FieldT> &A,
                      const pb_linear_combination<FieldT> &B,
                      const std::string &annotation_prefix="") :
        gadget<FieldT>(pb, annotation_prefix), n(n), A(A), B(B)
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

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};
}

#include "comparison_gadget.tcc"