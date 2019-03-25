#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

    char *genCMT(uint64_t value, char *sn_string, char *r_string);
    char *genCMTS(uint64_t value_s, char *pk_string, char *sn_s_string, char *r_s_string, char *sn_old_string);
    char* genRoot(char* cmtarray,int n);
    char *genDepositproof(uint64_t value,
                          uint64_t value_old,
                          char *sn_old_string,
                          char *r_old_string,
                          char *sn_string,
                          char *r_string,
                          char *sns_string,
                          char *rs_string,
                          char *cmtB_old_string,
                          char *cmtB_string,
                          uint64_t value_s,
                          char *pk_string,
                          char *sn_A_oldstring,
                          char *cmtS_string,
                          char *cmtarray,
                          int n,
                          char *RT);

    bool verifyDepositproof(char *data, char *RT, char *pk, char *cmtb_old, char *snold, char *cmtb);

#ifdef __cplusplus
} // extern "C"
#endif