#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

   char *genCMT(uint64_t value, char *sn_string, char *r_string);

   char *genMintproof(uint64_t value,
                      uint64_t value_old,
                      char *sn_old_string,
                      char *r_old_string,
                      char *sn_string,
                      char *r_string,
                      char *cmtA_old_string, 
                      char *cmtA_string, 
                      uint64_t value_s);

   bool verifyMintproof(char *data, char *cmtA_old_string, char *sn_old_string, char *cmtA_string, uint64_t value_s);

#ifdef __cplusplus
} // extern "C"
#endif