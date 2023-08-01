#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define LANGUAGE_ENGLISH 1

#define LANGUAGE_CHINESE_SIMPLIFIED 2

#define LANGUAGE_CHINESE_TRADITIONAL 3

#define LANGUAGE_FRENCH 4

#define LANGUAGE_ITALIAN 5

#define LANGUAGE_JAPANESE 6

#define LANGUAGE_KOREAN 7

#define LANGUAGE_SPANISH 8

#define UNKNOWN_ERROR 101

#define INVALID_ENCODING_ERROR 102

#define INVALID_PARTICIPANT_ERROR 103

#define INVALID_SHARE_ERROR 104

#define ZERO_PARAMETER_ERROR 201

#define INVALID_THRESHOLD_ERROR 202

#define INVALID_NAME_ERROR 203

#define UNKNOWN_LANGUAGE_ERROR 204

#define INVALID_SEED_ERROR 205

#define INVALID_AMOUNT_OF_COMMITMENTS_ERROR 206

#define INVALID_COMMITMENTS_ERROR 207

#define INVALID_AMOUNT_OF_SHARES_ERROR 208

#define INVALID_OUTPUT_ERROR 301

#define INVALID_ADDRESS_ERROR 302

#define INVALID_NETWORK_ERROR 303

#define NO_INPUTS_ERROR 304

#define NO_OUTPUTS_ERROR 305

#define DUST_ERROR 306

#define NOT_ENOUGH_FUNDS_ERROR 307

#define TOO_LARGE_TRANSACTION_ERROR 308

#define WRONG_KEYS_ERROR 309

#define INVALID_PREPROCESS_ERROR 310

typedef struct KeyMachineWrapper KeyMachineWrapper;

typedef struct MultisigConfig MultisigConfig;

typedef struct SecretShareMachineWrapper SecretShareMachineWrapper;

typedef struct String String;

typedef struct ThresholdKeysWrapper ThresholdKeysWrapper;

typedef struct Vec_u8 Vec_u8;

typedef struct OwnedString {
  struct String *str_box;
  const uint8_t *ptr;
  uintptr_t len;
} OwnedString;

typedef struct StringView {
  const uint8_t *ptr;
  uintptr_t len;
} StringView;

typedef struct MultisigConfigWithName {
  struct MultisigConfig config;
  struct String my_name;
} MultisigConfigWithName;

typedef struct MultisigConfigRes {
  struct MultisigConfig *config;
  struct OwnedString encoded;
} MultisigConfigRes;

typedef struct CResult_MultisigConfigRes {
  struct MultisigConfigRes *value;
  uint16_t err;
} CResult_MultisigConfigRes;

typedef struct CResult_MultisigConfig {
  struct MultisigConfig *value;
  uint16_t err;
} CResult_MultisigConfig;

typedef struct StartKeyGenRes {
  struct OwnedString seed;
  struct MultisigConfigWithName *config;
  struct SecretShareMachineWrapper *machine;
  struct OwnedString commitments;
} StartKeyGenRes;

typedef struct CResult_StartKeyGenRes {
  struct StartKeyGenRes *value;
  uint16_t err;
} CResult_StartKeyGenRes;

typedef struct SecretSharesRes {
  struct KeyMachineWrapper *machine;
  struct Vec_u8 *internal_commitments;
  struct OwnedString shares;
} SecretSharesRes;

typedef struct CResult_SecretSharesRes {
  struct SecretSharesRes *value;
  uint16_t err;
} CResult_SecretSharesRes;

typedef struct KeyGenRes {
  uint8_t multisig_id[32];
  struct ThresholdKeysWrapper *keys;
  struct OwnedString recovery;
} KeyGenRes;

typedef struct CResult_KeyGenRes {
  struct KeyGenRes *value;
  uint16_t err;
} CResult_KeyGenRes;

typedef struct CResult_ThresholdKeysWrapper {
  struct ThresholdKeysWrapper *value;
  uint16_t err;
} CResult_ThresholdKeysWrapper;

void free(struct OwnedString self);

struct StringView multisig_name(const struct MultisigConfig *self);

uint16_t threshold(const struct MultisigConfig *self);

uintptr_t participants(const struct MultisigConfig *self);

struct StringView participant(const struct MultisigConfig *self, uintptr_t i);

const uint8_t *salt(const struct MultisigConfig *self);

const struct MultisigConfig *config(const struct MultisigConfigWithName *self);

struct StringView my_name(const struct MultisigConfigWithName *self);

struct CResult_MultisigConfigRes new_multisig_config(const uint8_t *multisig_name,
                                                     uintptr_t multisig_name_len,
                                                     uint16_t threshold,
                                                     const struct StringView *participants,
                                                     uint16_t participants_len);

struct CResult_MultisigConfig decode_multisig_config(struct StringView config);

struct CResult_StartKeyGenRes start_key_gen(struct MultisigConfig *config,
                                            struct StringView my_name,
                                            uint16_t language);

struct CResult_SecretSharesRes get_secret_shares(struct MultisigConfigWithName *config,
                                                 uint16_t language,
                                                 struct StringView seed,
                                                 struct SecretShareMachineWrapper *machine,
                                                 const struct StringView *commitments,
                                                 uintptr_t commitments_len);

struct CResult_KeyGenRes complete_key_gen(struct MultisigConfigWithName *config,
                                          struct SecretSharesRes machine_and_commitments,
                                          const struct StringView *shares,
                                          uintptr_t shares_len);

struct OwnedString serialize_keys(struct ThresholdKeysWrapper *keys);

struct CResult_ThresholdKeysWrapper deserialize_keys(struct StringView keys);
