#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

namespace libsnark {

template<typename FieldT>
void less_cmp_gadget<FieldT>::generate_r1cs_constraints()
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
    // this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(this->pb.val(1), (FieldT(2)^n) + B - A, this->pb.val(alpha_packed)), FMT(this->annotation_prefix, " main_constraint"));
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, (FieldT(2)^n) + B - A, alpha_packed), FMT(this->annotation_prefix, " main_constraint"));

    /* compute result */
    all_zeros_test->generate_r1cs_constraints();
    // this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(less_or_eq, not_all_zeros, less),
    //                              FMT(this->annotation_prefix, " less"));
    
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
     * ********************************************************************************
     * 初始化时，我们预设 less_or_eq = 1, 即 alpha_n = 1,
     * less_or_eq * not_all_zeros = less
     * 0 * not_all_zeros = 0 => nothing
     * 0 * not_all_zeros = 1 => nothing
     * 1 * not_all_zeros = 1 => nothing
     * 1 * not_all_zeros = 0 => nothing
     * 1 * not_all_zeros = not_all_zeros => nothing
     * 0 * not_all_zeros = not_all_zeros => nothing
     * ********************************************************************************/
    // this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(this->pb.val(0), not_all_zeros, this->pb.val(0)),
    //                             FMT(this->annotation_prefix, " less"));
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(FieldT::one(), not_all_zeros, FieldT::one()),
                                FMT(this->annotation_prefix, " less"));
}

template<typename FieldT>
void less_cmp_gadget<FieldT>::generate_r1cs_witness()
{
    A.evaluate(this->pb);
    B.evaluate(this->pb);

    /* unpack 2^n + B - A into alpha_packed */
    this->pb.val(alpha_packed) = (FieldT(2)^n) + this->pb.lc_val(B) - this->pb.lc_val(A);
    pack_alpha->generate_r1cs_witness_from_packed();

    /* compute result */
    all_zeros_test->generate_r1cs_witness();

    // printf("****************\n FieldT(2)^n) = %zu\n ****************\n", FieldT(2)^n);
    // printf("****************\n A = %zu\n ****************\n", A);
    // printf("****************\n B = %zu\n ****************\n", B);
    // printf("****************\n not_all_zeros = %zu\n ****************\n", not_all_zeros);
    // printf("****************\n alpha = %zu\n ****************\n", alpha);
    // printf("****************\n (FieldT(2)^n) + B - A = %zu\n ****************\n", (FieldT(2)^n) + B - A);
    // printf("****************\n alpha_packed = %zu\n ****************\n", alpha_packed);
    
    // printf("****************\n this->pb.val(0) = %zu\n ****************\n", this->pb.val(0));
    // printf("****************\n this->pb.val(1) = %zu\n ****************\n", this->pb.val(1));

    // this->pb.val(less) = this->pb.val(less_or_eq) * this->pb.val(not_all_zeros);
}

}
