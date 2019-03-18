#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

    char *genCMT(uint64_t value, char *sn_string, char *r_string);
    char *genCMTS(uint64_t value_s, char *pk_string, char *sn_s_string, char *r_s_string, char *sn_old_string);

    char *genSendproof(uint64_t value_A,
                   char *sn_s_string,
                   char *r_s_string,
                   char *sn_string,
                   char *r_string,
                   char *cmt_s_string,
                   char *cmtA_string,
                   uint64_t value_s,
                   char *pk_string,
                   uint64_t value_A_new,
                   char *sn_A_new,
                   char *r_A_new,
                   char *cmt_A_new);

    bool verifySendproof(char *data, char *cmtA_old_string, char *sn_old_string, char *cmtS_string ,char *cmtA_new_string);

#ifdef __cplusplus
} // extern "C"
#endif