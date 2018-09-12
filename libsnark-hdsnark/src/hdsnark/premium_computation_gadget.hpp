#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libff/common/utils.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include <boost/optional.hpp>
#include <libff/algebra/fields/field_utils.hpp>

#include <iostream>
#include <math.h>


using namespace libff;
using namespace libsnark;
using namespace std;

//namespace libsnark {
template<typename FieldT>
class premium_computation_gadget : public gadget<FieldT> {
private:
    /* S_i = \sum_{k=0}^{i+1} A[i] * B[i] */
    pb_variable_array<FieldT> S;
public:
    const pb_linear_combination_array<FieldT> A;
    const pb_linear_combination_array<FieldT> B;
    const pb_variable_array<FieldT> result_field;

    pb_variable<FieldT> result;

    premium_computation_gadget(protoboard<FieldT>& pb,
                         const pb_linear_combination_array<FieldT> &A,
                         const pb_linear_combination_array<FieldT> &B,
                         const pb_variable_array<FieldT> &result_field,
                         //const pb_variable<FieldT> &result,
                         const std::string &annotation_prefix="") :
        gadget<FieldT>(pb, annotation_prefix), A(A), B(B), result_field(result_field)//result(result)
    {
        assert(A.size() >= 1);
        assert(A.size() == B.size());

        result.allocate(pb, "result");
        S.allocate(pb, A.size()-1, FMT(this->annotation_prefix, " S"));
    }

    void generate_r1cs_constraints()
    {
        /*
        S_i = \sum_{k=0}^{i+1} A[i] * B[i]
        S[0] = A[0] * B[0]
        S[i+1] - S[i] = A[i] * B[i]
        */
        for (size_t i = 0; i < A.size(); ++i)
        {
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(A[i], B[i],
                                        (i == A.size()-1 ? result : S[i]) + (i == 0 ? 0 * ONE : -S[i-1])),
                FMT(this->annotation_prefix, " S_%zu", i));
        }


    }

    void generate_r1cs_witness()
    {
        FieldT total = FieldT::zero();
        for (size_t i = 0; i < A.size(); ++i)
        {
            A[i].evaluate(this->pb);
            B[i].evaluate(this->pb);

            total += this->pb.lc_val(A[i]) * this->pb.lc_val(B[i]);
            this->pb.val(i == A.size()-1 ? result : S[i]) = total;
        }
        
        FieldT result_field_total = FieldT::zero();
        size_t result_field_len = result_field.size();

        for (size_t i = 0; i < result_field_len; ++i)
        {
            result_field_total += ((this->pb.val(result_field[i]) == FieldT(1)) ? pow(2, result_field_len-1-i) : 0);
            
            //std::cout<<"this->pb.val(result_field["<<i<<"]) is " << this->pb.val(result_field[i]) <<endl;
        }   
        // std::cout<<"result_field_total is " << result_field_total <<endl;
        // printf("test is %zu \n", test);
        // printf("result_field_len is %zu \n", result_field_len);
        // std::cout << "FieldT::zero() is "<<FieldT::zero() <<endl;
        // std::cout << "FieldT::one() is " << FieldT::one() <<endl;
        // printf("result_field_len is %zu \n", result);

        assert(this->pb.val(result) == result_field_total);
    }
};