#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

char* genCMT(uint64_t value,char* sn_string,char* r_string);

char* genRedeemproof(uint64_t value,
                   uint64_t value_old,
                //    uint256 sn_old,
                char* sn_old_string,
                //    uint256 r_old,
                 char* r_old_string,
                //    uint256 sn,
                char* sn_string,
                //    uint256 r,
                char* r_string,
                //    uint256 cmtA_old,
                char* cmtA_old_string, //111
                //    uint256 cmtA,
                char* cmtA_string, //111
                   uint64_t value_s);

bool verifyRedeemproof(char *data, char* cmtA_old_string, char* sn_old_string, char* cmtA_string,uint64_t value_s);

#ifdef __cplusplus
} // extern "C"
#endif