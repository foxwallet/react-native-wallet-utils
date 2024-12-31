// Copyright 2021-2021 FoxWallet.
#pragma once

#include <stdint.h>

// rust ffi

struct ExternError {
    int32_t code;
    char *message; // note: nullable
};

void core_destroy_string(const char* cstring);

// ironfish
const char* ironfish_create_account(struct ExternError*);

const char* ironfish_create_account_from_pk(struct ExternError*, const char* pk);

const char* ironfish_sign_transaction(struct ExternError*, const char* raw_tx_str, const char* spend_key);

const char* ironfish_init_sapling_params(struct ExternError*, const char* mint_params_path, const char* spend_params_path, const char* output_params_path);

const char* ironfish_is_valid_public_address(struct ExternError*, const char* hex_address);

// aleo
const char* aleo_create_account_from_pk(struct ExternError*, const char* pk);

const char* aleo_create_account_from_seed(struct ExternError*, const char* seed);

const char* aleo_is_valid_public_address(struct ExternError*, const char* address);

const char* aleo_view_key_to_address(struct ExternError*, const char* view_key);

const char* aleo_deserialize_credits_record(struct ExternError*, const char* record_str);

const char* aleo_decrypt_ciphertext(struct ExternError*, const char* ciphertext, const char* view_key);

const char* aleo_decrypt_record(struct ExternError*, const char* ciphertext, const char* view_key);

const char* aleo_sign_message(struct ExternError*, const char* pk, const char* message);

const char* aleo_generate_prover_files(struct ExternError*, const char* dir, const char* rpc_url, const char* network, const char* program_id, const char* function_name, const char* prover_file_path, const char* verifier_file_path);

const char* aleo_execute_program(struct ExternError*, const char* dir, const char* rpc_url, const char* network, const char* pk, const char* program_id, const char* function_name, const char* inputs, const char* fee_record, const char* base_fee, const char* priority_fee, const char* prover_file_path, const char* verifier_file_path, const char* fee_prover_file_path, const char* fee_verifier_file_path);

const char* aleo_parse_record(struct ExternError*, const char* plaintext);

const char* aleo_hash_bhp256(struct ExternError*, const char* str);

const char* polkadot_scrypt(struct ExternError*, const char* password_str, const char* salt_str, uint8_t log2_n, uint32_t r, uint32_t p);