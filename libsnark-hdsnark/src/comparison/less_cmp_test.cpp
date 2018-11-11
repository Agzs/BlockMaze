#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp> //--Agzs

//#include <libsnark/gadgetlib1/examples/simple_example.hpp>
//#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
// #include "libsnark/common/utils.hpp"
#include <boost/optional.hpp>


using namespace libsnark;
using namespace std;

/**
 * The code below provides an example of all stages of running a R1CS GG-ppzkSNARK.
 *
 * Of course, in a real-life scenario, we would have three distinct entities,
 * mangled into one in the demonstration below. The three entities are as follows.
 * (1) The "generator", which runs the ppzkSNARK generator on input a given
 *     constraint system CS to create a proving and a verification key for CS.
 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
 *     a primary input for CS, and an auxiliary input for CS.
 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
 *     a primary input for CS, and a proof.
 */

#define DEBUG 0

template<typename FieldT>
class less_cmp_gadget : public gadget<FieldT> {
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
        // this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(this->pb.val(0), not_all_zeros, this->pb.val(0)),
        //                             FMT(this->annotation_prefix, " less"));
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

// 生成proof
template<typename ppzksnark_ppT>
boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> generate_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
protoboard<libff::Fr<ppzksnark_ppT>> pb)
{
//    typedef Fr<ppzksnark_ppT> FieldT;

//    protoboard<FieldT> pb;
//    l_gadget<FieldT> g(pb);
//    g.generate_r1cs_constraints();
//    g.generate_r1cs_witness(h1, h2, x, r1, r2);

    if (!pb.is_satisfied()) {
        return boost::none;
    }

    return r1cs_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}


// 验证proof
template<typename ppzksnark_ppT>
bool verify_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key, r1cs_ppzksnark_proof<ppzksnark_ppT> proof)
{
    typedef libff::Fr<ppzksnark_ppT> FieldT;

    const r1cs_primary_input<FieldT> input; // ????
    //const r1cs_primary_input<FieldT> input = l_input_map<FieldT>(h1, h2, x); // 获取输入，并转换为有限域上的值

    // 调用libsnark库中验证proof的函数
    return r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}

template<typename ppzksnark_ppT>
void PrintProof(r1cs_ppzksnark_proof<ppzksnark_ppT> proof)
{
    printf("================== Print proof ==================================\n");
    //printf("proof is %x\n", *proof);
    std::cout << "comparison proof:\n";

    std::cout << "\n knowledge_commitment<G1<ppT>, G1<ppT> > g_A: ";
    std::cout << "\n   knowledge_commitment.g: \n     " << proof.g_A.g;
    std::cout << "\n   knowledge_commitment.h: \n     " << proof.g_A.h << endl;

    std::cout << "\n knowledge_commitment<G2<ppT>, G1<ppT> > g_B: ";
    std::cout << "\n   knowledge_commitment.g: \n     " << proof.g_B.g;
    std::cout << "\n   knowledge_commitment.h: \n     " << proof.g_B.h << endl;

    std::cout << "\n knowledge_commitment<G1<ppT>, G1<ppT> > g_C: ";
    std::cout << "\n   knowledge_commitment.g: \n     " << proof.g_C.g;
    std::cout << "\n   knowledge_commitment.h: \n     " << proof.g_C.h << endl;


    std::cout << "\n G1<ppT> g_H: " << proof.g_H << endl;
    std::cout << "\n G1<ppT> g_K: " << proof.g_K << endl;
    printf("=================================================================\n");
}

// test_comparison_gadget_with_instance
template<typename ppzksnark_ppT> //--Agzs
bool test_comparison_gadget_with_instance(const size_t a, const size_t b)
{
   const size_t n = 63; // 由于 1ul 表示无符号长整形(64bit), 最高位不作符号位，所以n最大取63

    printf("testing comparison_gadget on all %zu bit inputs: a = %zu, b = %zu\n", n, a, b);

    typedef libff::Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;

    pb_variable<FieldT> A, B;
    A.allocate(pb, "A");
    B.allocate(pb, "B");

    // printf("****************\n A = %zu\n ****************\n", A);
    // printf("****************\n B = %zu\n ****************\n", B);

    less_cmp_gadget<FieldT> comparison(pb, A, B, "cmp");
    comparison.generate_r1cs_constraints();// 生成约束

    // check conatraints
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    // key pair generation
    r1cs_ppzksnark_keypair<ppzksnark_ppT> keypair =  r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);

    /* ****************************************************************
     * ul 表示无符号长整形, 最高位不作符号位
     * 1ul<<63 = 1000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 = 9223372036854775808
     * 64个1 = 18446744073709551615
     * *****************************************************************/
    if (a < 1ul<<n && b < 1ul<<n) // 
    {
        
        pb.val(A) = FieldT(a);
        pb.val(B) = FieldT(b);

        /*
          A = 140731837292432
          B = 140731837292480
        */
        // std::cout << "****************\n FieldT(a) = " << FieldT(a) << "\n ****************\n";
        // std::cout << "****************\n FieldT(b) = " << FieldT(b) << "\n ****************\n";
        // printf("****************\n A = %zu\n ****************\n", A);
        // printf("****************\n B = %zu\n ****************\n", B);

        comparison.generate_r1cs_witness(); // 为新模型的参数生成证明
        
#ifdef DEBUG
        printf("positive test for %zu < %zu\n", a, b);
#endif
        assert(pb.val(less) == (a < b ? FieldT::one() : FieldT::zero()));
        assert(pb.val(less_or_eq) == (a <= b ? FieldT::one() : FieldT::zero()));
        assert(pb.is_satisfied());

	    // generate proof
        auto proof = generate_proof(keypair.pk, pb);

        // if (pb.val(less_or_eq) == FieldT::one())
        // {
        //     if (pb.val(less) == FieldT::one()) {
        //         printf("result test for %zu < %zu\n", a, b);
        //     } else {
        //         printf("result test for %zu = %zu\n", a, b);
        //     }
        // } else {
        //     printf("result test for %zu > %zu\n", a, b);
        // }

        // verify proof
        if (!proof) {
            return false;
        } else {
            // const r1cs_primary_input<FieldT> input();
            // std::cout<<"NULL input: "<<input<<endl;
            
            // PrintProof(*proof);

            assert(verify_proof(keypair.vk, *proof));
        }

    } else {
        printf("the size of a = %zu or b = %zu is larger than the %zu bit inputs\n", a, b, n);
        return false;
    }

    printf("the %zu bit inputs, comparison tests successful", n);
    // libff::print_time("the %zu bit inputs, comparison tests successful", n);
    printf("\n");
    return true;
}

int main () {
    default_r1cs_ppzksnark_pp::init_public_params();
    //test_r1cs_gg_ppzksnark<default_r1cs_gg_ppzksnark_pp>(1000, 100);

    libff::print_header("#             test comparison gadget with assert()");

    // test_comparison_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(45, 40);
    
    // 9223372036854775807
    // 18446744073709551615
    // test_comparison_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(40, 45);
    // 前提 B > 0, 否则 (2, -18446744073709551610)会验证正确，因为补码：2 < 6
    // test_comparison_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(-18446744073709551610, 9223372036854775807);
    test_comparison_gadget_with_instance<default_r1cs_ppzksnark_pp>(14, 9223372036854775807);

    // assert(test_comparison_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(6, 45, 40)); 
    // Note. cmake can not compile the assert()  --Agzs
    
    return 0;
}

