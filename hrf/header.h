#pragma once

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

#define UNKNOWN_ERROR 21

#define INVALID_ENCODING_ERROR 22

#define INVALID_PARTICIPANT_ERROR 23

#define INVALID_SHARE_ERROR 24

#define ZERO_PARAMETER_ERROR 41

#define INVALID_THRESHOLD_ERROR 42

#define INVALID_NAME_ERROR 43

#define UNKNOWN_LANGUAGE_ERROR 44

#define INVALID_SEED_ERROR 45

#define INVALID_AMOUNT_OF_COMMITMENTS_ERROR 46

#define INVALID_COMMITMENTS_ERROR 47

#define INVALID_AMOUNT_OF_SHARES_ERROR 48

#define INVALID_OUTPUT_ERROR 61

#define INVALID_ADDRESS_ERROR 62

#define INVALID_NETWORK_ERROR 63

#define NO_INPUTS_ERROR 64

#define NO_OUTPUTS_ERROR 65

#define DUST_ERROR 66

#define NOT_ENOUGH_FUNDS_ERROR 67

#define TOO_LARGE_TRANSACTION_ERROR 68

#define WRONG_KEYS_ERROR 69

#define INVALID_PREPROCESS_ERROR 70

#define INVALID_PARTICIPANTS_AMOUNT_ERROR 81

#define DUPLICATED_PARTICIPANT_ERROR 82

#define NOT_ENOUGH_RESHARERS_ERROR 83

#define INVALID_RESHARED_MSG_ERROR 84

#define INVALID_RESHARER_MSG_ERROR 85

typedef enum Network {
  Mainnet,
  Testnet,
  Regtest,
} Network;

typedef struct KeyMachineWrapper KeyMachineWrapper;

typedef struct MultisigConfig MultisigConfig;

typedef struct OpaqueResharedMachine OpaqueResharedMachine;

typedef struct OpaqueResharingMachine OpaqueResharingMachine;

typedef struct OwnedPortableOutput OwnedPortableOutput;

typedef struct ResharerConfig ResharerConfig;

typedef struct SecretShareMachineWrapper SecretShareMachineWrapper;

typedef struct SignConfig SignConfig;

typedef struct RustString RustString;

typedef struct ThresholdKeysWrapper ThresholdKeysWrapper;

typedef struct TransactionSignMachineWrapper TransactionSignMachineWrapper;

typedef struct TransactionSignatureMachineWrapper TransactionSignatureMachineWrapper;

typedef struct Vec_u8 Vec_u8;

typedef struct OwnedString {
  struct RustString *str_box;
  const uint8_t *ptr;
  uintptr_t len;
} OwnedString;

typedef struct StringView {
  const uint8_t *ptr;
  uintptr_t len;
} StringView;

typedef struct MultisigConfigWithName {
  struct MultisigConfig *config;
  struct RustString *my_name;
} MultisigConfigWithName;

typedef struct MultisigConfigRes {
  struct MultisigConfig *config;
  struct OwnedString encoded;
} MultisigConfigRes;

typedef struct CResult_MultisigConfigRes {
  struct MultisigConfigRes *value;
  uint8_t err;
} CResult_MultisigConfigRes;

typedef struct CResult_MultisigConfig {
  struct MultisigConfig *value;
  uint8_t err;
} CResult_MultisigConfig;

typedef struct StartKeyGenRes {
  struct OwnedString seed;
  struct MultisigConfigWithName *config;
  struct SecretShareMachineWrapper *machine;
  struct OwnedString commitments;
} StartKeyGenRes;

typedef struct CResult_StartKeyGenRes {
  struct StartKeyGenRes *value;
  uint8_t err;
} CResult_StartKeyGenRes;

typedef struct SecretSharesRes {
  struct KeyMachineWrapper *machine;
  struct Vec_u8 *internal_commitments;
  struct OwnedString shares;
} SecretSharesRes;

typedef struct CResult_SecretSharesRes {
  struct SecretSharesRes *value;
  uint8_t err;
} CResult_SecretSharesRes;

typedef struct KeyGenRes {
  uint8_t multisig_id[32];
  struct ThresholdKeysWrapper *keys;
  struct OwnedString recovery;
} KeyGenRes;

typedef struct CResult_KeyGenRes {
  struct KeyGenRes *value;
  uint8_t err;
} CResult_KeyGenRes;

typedef struct CResult_ThresholdKeysWrapper {
  struct ThresholdKeysWrapper *value;
  uint8_t err;
} CResult_ThresholdKeysWrapper;

typedef struct SignConfigRes {
  struct SignConfig *config;
  struct OwnedString encoded;
} SignConfigRes;

typedef struct CResult_SignConfigRes {
  struct SignConfigRes *value;
  uint8_t err;
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
  uint8_t err;
} CResult_SignConfig;

typedef struct AttemptSignRes {
  struct TransactionSignMachineWrapper *machine;
  struct OwnedString preprocess;
} AttemptSignRes;

typedef struct CResult_AttemptSignRes {
  struct AttemptSignRes *value;
  uint8_t err;
} CResult_AttemptSignRes;

typedef struct ContinueSignRes {
  struct TransactionSignatureMachineWrapper *machine;
  struct OwnedString preprocess;
} ContinueSignRes;

typedef struct CResult_ContinueSignRes {
  struct ContinueSignRes *value;
  uint8_t err;
} CResult_ContinueSignRes;

typedef struct CResult_OwnedString {
  struct OwnedString *value;
  uint8_t err;
} CResult_OwnedString;

typedef struct ResharerConfigRes {
  struct ResharerConfig config;
  struct OwnedString encoded;
} ResharerConfigRes;

typedef struct CResult_ResharerConfigRes {
  struct ResharerConfigRes *value;
  uint8_t err;
} CResult_ResharerConfigRes;

typedef struct CResult_ResharerConfig {
  struct ResharerConfig *value;
  uint8_t err;
} CResult_ResharerConfig;

typedef struct StartResharerRes {
  uintptr_t new_participants_len;
  struct OpaqueResharingMachine *machine;
  struct OwnedString encoded;
} StartResharerRes;

typedef struct CResult_StartResharerRes {
  struct StartResharerRes *value;
  uint8_t err;
} CResult_StartResharerRes;

typedef struct StartResharedRes {
  uintptr_t resharers_len;
  struct OpaqueResharedMachine *machine;
  struct OwnedString encoded;
} StartResharedRes;

typedef struct CResult_StartResharedRes {
  struct StartResharedRes *value;
  uint8_t err;
} CResult_StartResharedRes;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void free_owned_string(struct OwnedString self);

struct StringView multisig_name(const struct MultisigConfig *self);

uint16_t multisig_threshold(const struct MultisigConfig *self);

uintptr_t multisig_participants(const struct MultisigConfig *self);

struct StringView multisig_participant(const struct MultisigConfig *self, uintptr_t i);

const uint8_t *multisig_salt(const struct MultisigConfig *self);

const struct MultisigConfig *multisig_config(const struct MultisigConfigWithName *self);

struct StringView multisig_my_name(const struct MultisigConfigWithName *self);

struct CResult_MultisigConfigRes new_multisig_config(const uint8_t *multisig_name,
                                                     uintptr_t multisig_name_len,
                                                     uint16_t threshold,
                                                     const struct StringView *participants,
                                                     uint16_t participants_len);

struct CResult_MultisigConfig decode_multisig_config(struct StringView config);

struct CResult_StartKeyGenRes start_key_gen(struct MultisigConfig *config,
                                            struct StringView my_name,
                                            uint8_t language);

struct CResult_SecretSharesRes get_secret_shares(const struct MultisigConfigWithName *config,
                                                 uint8_t language,
                                                 struct StringView seed,
                                                 struct SecretShareMachineWrapper *machine,
                                                 const struct StringView *commitments,
                                                 uintptr_t commitments_len);

struct CResult_KeyGenRes complete_key_gen(const struct MultisigConfigWithName *config,
                                          struct SecretSharesRes machine_and_commitments,
                                          const struct StringView *shares,
                                          uintptr_t shares_len);

uint16_t keys_threshold(const struct ThresholdKeysWrapper *keys);

uint16_t keys_participants(const struct ThresholdKeysWrapper *keys);

uint16_t keys_index(const struct ThresholdKeysWrapper *keys);

struct OwnedString serialize_keys(const struct ThresholdKeysWrapper *keys);

struct CResult_ThresholdKeysWrapper deserialize_keys(struct StringView keys);

struct OwnedString address_for_keys(enum Network network, const struct ThresholdKeysWrapper *keys);

struct OwnedString script_pubkey_for_keys(const struct ThresholdKeysWrapper *keys);

const uint8_t *output_hash(const struct OwnedPortableOutput *self);

uint32_t output_vout(const struct OwnedPortableOutput *self);

uint64_t output_value(const struct OwnedPortableOutput *self);

uintptr_t output_script_pubkey_len(const struct OwnedPortableOutput *self);

const uint8_t *output_script_pubkey(const struct OwnedPortableOutput *self);

uintptr_t sign_inputs(const struct SignConfig *self);

const struct OwnedPortableOutput *sign_input(const struct SignConfig *self, uintptr_t i);

uintptr_t sign_payments(const struct SignConfig *self);

struct StringView sign_payment_address(const struct SignConfig *self, uintptr_t i);

uint64_t sign_payment_amount(const struct SignConfig *self, uintptr_t i);

struct StringView sign_change(const struct SignConfig *self);

uint64_t sign_fee_per_weight(const struct SignConfig *self);

struct CResult_SignConfigRes new_sign_config(enum Network network,
                                             const struct PortableOutput *outputs,
                                             uintptr_t outputs_len,
                                             uintptr_t payments,
                                             const struct StringView *payment_addresses,
                                             const uint64_t *payment_amounts,
                                             struct StringView change,
                                             uint64_t fee_per_weight);

struct CResult_SignConfig decode_sign_config(enum Network network, struct StringView encoded);

struct CResult_AttemptSignRes attempt_sign(const struct ThresholdKeysWrapper *keys,
                                           const struct SignConfig *config);

struct CResult_ContinueSignRes continue_sign(struct TransactionSignMachineWrapper *machine,
                                             const struct StringView *preprocesses,
                                             uintptr_t preprocesses_len);

struct CResult_OwnedString complete_sign(struct TransactionSignatureMachineWrapper *machine,
                                         const struct StringView *shares,
                                         uintptr_t shares_len);

uint16_t resharer_new_threshold(const struct ResharerConfig *self);

uintptr_t resharer_resharers(const struct ResharerConfig *self);

uint16_t resharer_resharer(const struct ResharerConfig *self, uintptr_t i);

uintptr_t resharer_new_participants(const struct ResharerConfig *self);

struct StringView resharer_new_participant(const struct ResharerConfig *self, uintptr_t i);

const uint8_t *resharer_salt(const struct ResharerConfig *self);

struct CResult_ResharerConfigRes new_resharer_config(uint16_t new_threshold,
                                                     const uint16_t *resharers,
                                                     uint16_t resharers_len,
                                                     const struct StringView *new_participants,
                                                     uint16_t new_participants_len);

struct CResult_ResharerConfig decode_resharer_config(struct StringView config);

struct CResult_StartResharerRes start_resharer(const struct ThresholdKeysWrapper *keys,
                                               struct ResharerConfig *config);

struct CResult_StartResharedRes start_reshared(struct ResharerConfig *resharer_config,
                                               struct StringView my_name,
                                               const struct StringView *resharer_starts);

struct CResult_OwnedString complete_resharer(struct StartResharerRes machine,
                                             const struct StringView *encryption_keys_of_reshared_to);

struct CResult_ThresholdKeysWrapper complete_reshared(struct StartResharedRes prior,
                                                      const struct StringView *resharer_completes);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
