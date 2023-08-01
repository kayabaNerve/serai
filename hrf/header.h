#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

constexpr static const uint16_t LANGUAGE_ENGLISH = 1;

constexpr static const uint16_t LANGUAGE_CHINESE_SIMPLIFIED = 2;

constexpr static const uint16_t LANGUAGE_CHINESE_TRADITIONAL = 3;

constexpr static const uint16_t LANGUAGE_FRENCH = 4;

constexpr static const uint16_t LANGUAGE_ITALIAN = 5;

constexpr static const uint16_t LANGUAGE_JAPANESE = 6;

constexpr static const uint16_t LANGUAGE_KOREAN = 7;

constexpr static const uint16_t LANGUAGE_SPANISH = 8;

constexpr static const uint16_t UNKNOWN_ERROR = 101;

constexpr static const uint16_t INVALID_ENCODING_ERROR = 102;

constexpr static const uint16_t INVALID_PARTICIPANT_ERROR = 103;

constexpr static const uint16_t INVALID_SHARE_ERROR = 104;

constexpr static const uint16_t ZERO_PARAMETER_ERROR = 201;

constexpr static const uint16_t INVALID_THRESHOLD_ERROR = 202;

constexpr static const uint16_t INVALID_NAME_ERROR = 203;

constexpr static const uint16_t UNKNOWN_LANGUAGE_ERROR = 204;

constexpr static const uint16_t INVALID_SEED_ERROR = 205;

constexpr static const uint16_t INVALID_AMOUNT_OF_COMMITMENTS_ERROR = 206;

constexpr static const uint16_t INVALID_COMMITMENTS_ERROR = 207;

constexpr static const uint16_t INVALID_AMOUNT_OF_SHARES_ERROR = 208;

constexpr static const uint16_t INVALID_OUTPUT_ERROR = 301;

constexpr static const uint16_t INVALID_ADDRESS_ERROR = 302;

constexpr static const uint16_t INVALID_NETWORK_ERROR = 303;

constexpr static const uint16_t NO_INPUTS_ERROR = 304;

constexpr static const uint16_t NO_OUTPUTS_ERROR = 305;

constexpr static const uint16_t DUST_ERROR = 306;

constexpr static const uint16_t NOT_ENOUGH_FUNDS_ERROR = 307;

constexpr static const uint16_t TOO_LARGE_TRANSACTION_ERROR = 308;

constexpr static const uint16_t WRONG_KEYS_ERROR = 309;

constexpr static const uint16_t INVALID_PREPROCESS_ERROR = 310;

template<typename T = void>
struct Box;

struct MultisigConfig;

struct OwnedPortableOutput;

template<typename T = void, typename E = void>
struct Result;

struct SignConfig;

struct String;

template<typename T = void>
struct Vec;

struct OwnedString {
  String *str_box;
  const uint8_t *ptr;
  uintptr_t len;
};

struct StringView {
  const uint8_t *ptr;
  uintptr_t len;
};

struct MultisigConfigWithName {
  MultisigConfig config;
  String my_name;
};

extern "C" {

void free(OwnedString self);

StringView multisig_name(const MultisigConfig *self);

uint16_t threshold(const MultisigConfig *self);

uintptr_t participants(const MultisigConfig *self);

StringView participant(const MultisigConfig *self, uintptr_t i);

const uint8_t *salt(const MultisigConfig *self);

const MultisigConfig *config(const MultisigConfigWithName *self);

StringView my_name(const MultisigConfigWithName *self);

Result<Box<MultisigConfig>, uint16_t> decode_multisig_config(StringView config);

const uint8_t *hash(const OwnedPortableOutput *self);

uint32_t vout(const OwnedPortableOutput *self);

uint64_t value(const OwnedPortableOutput *self);

const uint8_t *script_pubkey(const OwnedPortableOutput *self);

uintptr_t inputs(const SignConfig *self);

const Box<OwnedPortableOutput> *input(const SignConfig *self, uintptr_t i);

StringView change(const SignConfig *self);

uint64_t fee_per_weight(const SignConfig *self);

Result<SignConfig, uint16_t> decode_sign_config(Network network, StringView encoded);

Result<Vec<uint8_t>, uint16_t> complete_sign(Box<TransactionSignatureMachine> machine,
                                             const StringView *shares,
                                             uintptr_t shares_len);

} // extern "C"
