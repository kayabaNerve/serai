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

typedef enum Network {
  Mainnet,
  Testnet,
  Regtest,
} Network;

typedef struct KeyMachineWrapper KeyMachineWrapper;

typedef struct MultisigConfig MultisigConfig;

typedef struct OwnedPortableOutput OwnedPortableOutput;

typedef struct SecretShareMachineWrapper SecretShareMachineWrapper;

typedef struct SignConfig SignConfig;

typedef struct String String;

typedef struct ThresholdKeysWrapper ThresholdKeysWrapper;

typedef struct TransactionSignMachineWrapper TransactionSignMachineWrapper;

typedef struct TransactionSignatureMachineWrapper TransactionSignatureMachineWrapper;

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

typedef struct SignConfigRes {
  struct SignConfig *config;
  struct OwnedString encoded;
} SignConfigRes;

typedef struct CResult_SignConfigRes {
  struct SignConfigRes *value;
  uint16_t err;
} CResult_SignConfigRes;

typedef struct PortableOutput {
  uint8_t hash[32];
  uint32_t vout;
  uint64_t value;
  const uint8_t *script_pubkey;
  uintptr_t script_pubkey_len;
} PortableOutput;

typedef struct CResult_SignConfig {
  struct SignConfig *value;
  uint16_t err;
} CResult_SignConfig;

typedef struct AttemptSignRes {
  struct TransactionSignMachineWrapper *machine;
  struct OwnedString preprocess;
} AttemptSignRes;

typedef struct CResult_AttemptSignRes {
  struct AttemptSignRes *value;
  uint16_t err;
} CResult_AttemptSignRes;

typedef struct ContinueSignRes {
  struct TransactionSignatureMachineWrapper *machine;
  struct OwnedString preprocess;
} ContinueSignRes;

typedef struct CResult_ContinueSignRes {
  struct ContinueSignRes *value;
  uint16_t err;
} CResult_ContinueSignRes;

typedef struct CResult_OwnedString {
  struct OwnedString *value;
  uint16_t err;
} CResult_OwnedString;

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

const uint8_t *hash(const struct OwnedPortableOutput *self);

uint32_t vout(const struct OwnedPortableOutput *self);

uint64_t value(const struct OwnedPortableOutput *self);

uintptr_t script_pubkey_len(const struct OwnedPortableOutput *self);

const uint8_t *script_pubkey(const struct OwnedPortableOutput *self);

uintptr_t inputs(const struct SignConfig *self);

struct OwnedPortableOutput *const *input(const struct SignConfig *self, uintptr_t i);

uintptr_t payments(const struct SignConfig *self);

struct StringView payment_address(const struct SignConfig *self, uintptr_t i);

uint64_t payment_amount(const struct SignConfig *self, uintptr_t i);

struct StringView change(const struct SignConfig *self);

uint64_t fee_per_weight(const struct SignConfig *self);

struct CResult_SignConfigRes new_sign_config(enum Network network,
                                             const struct PortableOutput *outputs,
                                             uintptr_t outputs_len,
                                             uintptr_t payments,
                                             const struct StringView *payment_addresses,
                                             const uint64_t *payment_amounts,
                                             struct StringView change,
                                             uint64_t fee_per_weight);

struct CResult_SignConfig decode_sign_config(enum Network network, struct StringView encoded);

struct CResult_AttemptSignRes attempt_sign(struct ThresholdKeysWrapper *keys,
                                           struct SignConfig *const *config);

struct CResult_ContinueSignRes continue_sign(struct TransactionSignMachineWrapper *machine,
                                             const struct StringView *preprocesses,
                                             uintptr_t preprocesses_len);

struct CResult_OwnedString complete_sign(struct TransactionSignatureMachineWrapper *machine,
                                         const struct StringView *shares,
                                         uintptr_t shares_len);
