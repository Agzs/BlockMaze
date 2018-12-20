template<typename FieldT>
class merkle_tree_gadget : gadget<FieldT> {
private:
    typedef sha256_two_to_one_hash_gadget<FieldT> sha256_gadget; // sha256(left, right)

    pb_variable_array<FieldT> positions; // 当前层数
    std::shared_ptr<merkle_authentication_path_variable<FieldT, sha256_gadget>> authvars; // Merkle认证路径变量
    std::shared_ptr<merkle_tree_check_read_gadget<FieldT, sha256_gadget>> auth; // 检查Merkle的gadget

public:
    // 构造函数
    merkle_tree_gadget(
        protoboard<FieldT>& pb,
        digest_variable<FieldT> leaf, // 叶子节点哈希值
        digest_variable<FieldT> root, // 根哈希值
        pb_variable<FieldT>& enforce
    ) : gadget<FieldT>(pb) {
        positions.allocate(pb, INCREMENTAL_MERKLE_TREE_DEPTH);
        authvars.reset(new merkle_authentication_path_variable<FieldT, sha256_gadget>(
            pb, INCREMENTAL_MERKLE_TREE_DEPTH, "auth"
        ));
        auth.reset(new merkle_tree_check_read_gadget<FieldT, sha256_gadget>(
            pb,
            INCREMENTAL_MERKLE_TREE_DEPTH, // 树高
            positions,  // address_bits 当前层数，其大小应与树高相同
            leaf,
            root,
            *authvars,
            enforce, // read_successful，do_copy
            ""
        ));
    }
    
    // 为Merkle_gadget的私有变量生成约束
    void generate_r1cs_constraints() {
        for (size_t i = 0; i < INCREMENTAL_MERKLE_TREE_DEPTH; i++) {
            // TODO: This might not be necessary, and doesn't
            // appear to be done in libsnark's tests, but there
            // is no documentation, so let's do it anyway to
            // be safe.
            generate_boolean_r1cs_constraint<FieldT>( // 为positions添加bool约束
                this->pb,
                positions[i],
                "boolean_positions"
            );
        }

        authvars->generate_r1cs_constraints();
        auth->generate_r1cs_constraints();
    }

    // 为Merkle_gadget的私有变量生成证据
    void generate_r1cs_witness(const MerklePath& path) {
        // TODO: Change libsnark so that it doesn't require this goofy
        // number thing in its API.
        size_t path_index = convertVectorToInt(path.index);

        positions.fill_with_bits_of_ulong(this->pb, path_index);

        authvars->generate_r1cs_witness(path_index, path.authentication_path);
        auth->generate_r1cs_witness();
    }
};
