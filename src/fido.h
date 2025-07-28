/*
 * Copyright (c) 2018-2024 Yubico AB. All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _FIDO_H
#define _FIDO_H

#include <openssl/ec.h>
#include <openssl/evp.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <cbor.h>

#ifdef _FIDO_INTERNAL
#include <sys/types.h>

#include <limits.h>

#include "../openbsd-compat/openbsd-compat.h"
#include "blob.h"
#include "iso7816.h"
#include "extern.h"
#endif

#include "fido/err.h"
#include "fido/param.h"
#include "fido/types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

fido_assert_t *fido_assert_new(void);
fido_cred_t *fido_cred_new(void);
fido_dev_t *fido_dev_new(void);
fido_dev_t *fido_dev_new_with_info(const fido_dev_info_t *);
fido_dev_info_t *fido_dev_info_new(size_t);
fido_cbor_info_t *fido_cbor_info_new(void);
void *fido_dev_io_handle(const fido_dev_t *);
void fido_dev_set_io_handle(fido_dev_t*, void*);

void fido_assert_free(fido_assert_t **);
void fido_cbor_info_free(fido_cbor_info_t **);
void fido_cred_free(fido_cred_t **);
void fido_dev_force_fido2(fido_dev_t *);
void fido_dev_force_u2f(fido_dev_t *);
void fido_dev_free(fido_dev_t **);
void fido_dev_info_free(fido_dev_info_t **, size_t);
void cbor_vector_free(cbor_item_t **, size_t);
/**
 * @brief Releases the memory that was allocated for @a bp.
 */
void fido_blob_free(fido_blob_t **bp);
/**
 * @brief Releases the memory that was allocated for @a pk. 
 */
void es256_pk_free(es256_pk_t **pk);

/* fido_init() flags. */
#define FIDO_DEBUG	0x01
#define FIDO_DISABLE_U2F_FALLBACK 0x02

void fido_init(int);
void fido_set_log_handler(fido_log_handler_t *);

const unsigned char *fido_assert_authdata_ptr(const fido_assert_t *, size_t);
const unsigned char *fido_assert_authdata_raw_ptr(const fido_assert_t *,
    size_t);
const unsigned char *fido_assert_clientdata_hash_ptr(const fido_assert_t *);
const unsigned char *fido_assert_hmac_secret_ptr(const fido_assert_t *, size_t);
const unsigned char *fido_assert_id_ptr(const fido_assert_t *, size_t);
const unsigned char *fido_assert_largeblob_key_ptr(const fido_assert_t *, size_t);
const unsigned char *fido_assert_sig_ptr(const fido_assert_t *, size_t);
const unsigned char *fido_assert_user_id_ptr(const fido_assert_t *, size_t);
const unsigned char *fido_assert_blob_ptr(const fido_assert_t *, size_t);

char **fido_cbor_info_certs_name_ptr(const fido_cbor_info_t *);
char **fido_cbor_info_extensions_ptr(const fido_cbor_info_t *);
char **fido_cbor_info_options_name_ptr(const fido_cbor_info_t *);
char **fido_cbor_info_transports_ptr(const fido_cbor_info_t *);
char **fido_cbor_info_versions_ptr(const fido_cbor_info_t *);
const bool *fido_cbor_info_options_value_ptr(const fido_cbor_info_t *);
const char *fido_assert_rp_id(const fido_assert_t *);
const char *fido_assert_user_display_name(const fido_assert_t *, size_t);
const char *fido_assert_user_icon(const fido_assert_t *, size_t);
const char *fido_assert_user_name(const fido_assert_t *, size_t);
const char *fido_cbor_info_algorithm_type(const fido_cbor_info_t *, size_t);
const char *fido_cred_display_name(const fido_cred_t *);
const char *fido_cred_fmt(const fido_cred_t *);
const char *fido_cred_rp_id(const fido_cred_t *);
const char *fido_cred_rp_name(const fido_cred_t *);
const char *fido_cred_user_name(const fido_cred_t *);
const char *fido_dev_info_manufacturer_string(const fido_dev_info_t *);
const char *fido_dev_info_path(const fido_dev_info_t *);
const char *fido_dev_info_product_string(const fido_dev_info_t *);
const fido_dev_info_t *fido_dev_info_ptr(const fido_dev_info_t *, size_t);
const uint8_t *fido_cbor_info_protocols_ptr(const fido_cbor_info_t *);
const uint64_t *fido_cbor_info_certs_value_ptr(const fido_cbor_info_t *);
const unsigned char *fido_cbor_info_aaguid_ptr(const fido_cbor_info_t *);
const unsigned char *fido_cred_aaguid_ptr(const fido_cred_t *);
const unsigned char *fido_cred_attstmt_ptr(const fido_cred_t *);
const unsigned char *fido_cred_authdata_ptr(const fido_cred_t *);
const unsigned char *fido_cred_authdata_raw_ptr(const fido_cred_t *);
const unsigned char *fido_cred_clientdata_hash_ptr(const fido_cred_t *);
const unsigned char *fido_cred_id_ptr(const fido_cred_t *);
const unsigned char *fido_cred_largeblob_key_ptr(const fido_cred_t *);
const unsigned char *fido_cred_pubkey_ptr(const fido_cred_t *);
const unsigned char *fido_cred_sig_ptr(const fido_cred_t *);
const unsigned char *fido_cred_user_id_ptr(const fido_cred_t *);
const unsigned char *fido_cred_x5c_ptr(const fido_cred_t *);
const unsigned char *fido_cred_x5c_list_ptr(const fido_cred_t *, size_t);

int fido_assert_allow_cred(fido_assert_t *, const unsigned char *, size_t);
int fido_assert_empty_allow_list(fido_assert_t *);
int fido_assert_set_authdata(fido_assert_t *, size_t, const unsigned char *,
    size_t);
int fido_assert_set_authdata_raw(fido_assert_t *, size_t, const unsigned char *,
    size_t);
int fido_assert_set_clientdata(fido_assert_t *, const unsigned char *, size_t);
int fido_assert_set_clientdata_hash(fido_assert_t *, const unsigned char *,
    size_t);
int fido_assert_set_count(fido_assert_t *, size_t);
int fido_assert_set_extensions(fido_assert_t *, int);
int fido_assert_set_hmac_salt(fido_assert_t *, const unsigned char *, size_t);
int fido_assert_set_hmac_secret(fido_assert_t *, size_t, const unsigned char *,
    size_t);
int fido_assert_set_options(fido_assert_t *, bool, bool);
int fido_assert_set_rp(fido_assert_t *, const char *);
int fido_assert_set_up(fido_assert_t *, fido_opt_t);
int fido_assert_set_uv(fido_assert_t *, fido_opt_t);
int fido_assert_set_sig(fido_assert_t *, size_t, const unsigned char *, size_t);
int fido_assert_set_winhello_appid(fido_assert_t *, const char *);
int fido_assert_verify(const fido_assert_t *, size_t, int, const void *);
int fido_cbor_info_algorithm_cose(const fido_cbor_info_t *, size_t);
int fido_cred_empty_exclude_list(fido_cred_t *);
bool fido_cred_entattest(const fido_cred_t *);
int fido_cred_exclude(fido_cred_t *, const unsigned char *, size_t);
int fido_cred_prot(const fido_cred_t *);
int fido_cred_set_attstmt(fido_cred_t *, const unsigned char *, size_t);
int fido_cred_set_attobj(fido_cred_t *, const unsigned char *, size_t);
int fido_cred_set_authdata(fido_cred_t *, const unsigned char *, size_t);
int fido_cred_set_authdata_raw(fido_cred_t *, const unsigned char *, size_t);
int fido_cred_set_blob(fido_cred_t *, const unsigned char *, size_t);
int fido_cred_set_clientdata(fido_cred_t *, const unsigned char *, size_t);
int fido_cred_set_clientdata_hash(fido_cred_t *, const unsigned char *, size_t);
int fido_cred_set_entattest(fido_cred_t *, int);
int fido_cred_set_extensions(fido_cred_t *, int);
int fido_cred_set_fmt(fido_cred_t *, const char *);
int fido_cred_set_id(fido_cred_t *, const unsigned char *, size_t);
int fido_cred_set_options(fido_cred_t *, bool, bool);
int fido_cred_set_pin_minlen(fido_cred_t *, size_t);
int fido_cred_set_prot(fido_cred_t *, int);
int fido_cred_set_rk(fido_cred_t *, fido_opt_t);
int fido_cred_set_rp(fido_cred_t *, const char *, const char *);
int fido_cred_set_sig(fido_cred_t *, const unsigned char *, size_t);
int fido_cred_set_type(fido_cred_t *, int);
int fido_cred_set_uv(fido_cred_t *, fido_opt_t);
int fido_cred_type(const fido_cred_t *);
int fido_cred_set_user(fido_cred_t *, const unsigned char *, size_t,
    const char *, const char *, const char *);
int fido_cred_set_x509(fido_cred_t *, const unsigned char *, size_t);
int fido_cred_verify(const fido_cred_t *);
int fido_cred_verify_self(const fido_cred_t *);
#ifdef _FIDO_SIGSET_DEFINED
int fido_dev_set_sigmask(fido_dev_t *, const fido_sigset_t *);
#endif
int fido_dev_cancel(fido_dev_t *);
int fido_dev_close(fido_dev_t *);
int fido_dev_get_assert(fido_dev_t *, fido_assert_t *, const char *);
int fido_dev_get_cbor_info(fido_dev_t *, fido_cbor_info_t *);
int fido_dev_get_retry_count(fido_dev_t *, int *);
int fido_dev_get_uv_retry_count(fido_dev_t *, int *);
int fido_dev_get_touch_begin(fido_dev_t *);
int fido_dev_get_touch_status(fido_dev_t *, int *, int);
/**
 * @brief Get the timeout in ms from the device.
 */
int fido_dev_get_timeout(fido_dev_t *dev);
/**
 * @brief Get the pin protocol of the device.
 */
uint8_t fido_dev_get_pin_protocol(const fido_dev_t *dev);
int fido_dev_info_manifest(fido_dev_info_t *, size_t, size_t *);
int fido_dev_info_set(fido_dev_info_t *, size_t, const char *, const char *,
    const char *, const fido_dev_io_t *, const fido_dev_transport_t *);
int fido_dev_make_cred(fido_dev_t *, fido_cred_t *, const char *);
int fido_dev_open_with_info(fido_dev_t *);
int fido_dev_open(fido_dev_t *, const char *);
int fido_dev_reset(fido_dev_t *);
int fido_dev_set_io_functions(fido_dev_t *, const fido_dev_io_t *);
int fido_dev_set_pin(fido_dev_t *, const char *, const char *);
int fido_dev_set_transport_functions(fido_dev_t *, const fido_dev_transport_t *);
int fido_dev_set_timeout(fido_dev_t *, int);
/**
 * @brief Directly receive a CTAP message.
 *
 * @note Can not be used with WinHello.
 * 
 * @param dev   Device handle
 * @param cmd   CTAP command identifier
 * @param buf   Buffer for the response
 * @param count Maximal count of response bytes
 */
int fido_direct_rx(fido_dev_t *dev, uint8_t cmd, void *buf, size_t count);
/**
 * @brief Directly transmits a CTAP message.
 *
 * @note Can not be used with WinHello.
 * 
 * @param dev  Device handle
 * @param cmd  CTAP command identifier
 * @param blob CTAP message and length
 */
int fido_direct_tx_blob(fido_dev_t *dev, uint8_t cmd, const fido_blob_t *blob);
/**
 * @brief Directly transmits a CTAP message.
 *
 * @note Can not be used with WinHello.
 * 
 * @param dev Device handle
 * @param cmd   CTAP command identifier
 * @param buf   Message buffer
 * @param count Count of bytes to transmit
 */
int fido_direct_tx(fido_dev_t *dev, uint8_t cmd, const void *buf, size_t count);

size_t fido_assert_authdata_len(const fido_assert_t *, size_t);
size_t fido_assert_authdata_raw_len(const fido_assert_t *, size_t);
size_t fido_assert_clientdata_hash_len(const fido_assert_t *);
size_t fido_assert_count(const fido_assert_t *);
size_t fido_assert_hmac_secret_len(const fido_assert_t *, size_t);
size_t fido_assert_id_len(const fido_assert_t *, size_t);
size_t fido_assert_largeblob_key_len(const fido_assert_t *, size_t);
size_t fido_assert_sig_len(const fido_assert_t *, size_t);
size_t fido_assert_user_id_len(const fido_assert_t *, size_t);
size_t fido_assert_blob_len(const fido_assert_t *, size_t);
size_t fido_cbor_info_aaguid_len(const fido_cbor_info_t *);
size_t fido_cbor_info_algorithm_count(const fido_cbor_info_t *);
size_t fido_cbor_info_certs_len(const fido_cbor_info_t *);
size_t fido_cbor_info_extensions_len(const fido_cbor_info_t *);
size_t fido_cbor_info_options_len(const fido_cbor_info_t *);
size_t fido_cbor_info_protocols_len(const fido_cbor_info_t *);
size_t fido_cbor_info_transports_len(const fido_cbor_info_t *);
size_t fido_cbor_info_versions_len(const fido_cbor_info_t *);
size_t fido_cred_aaguid_len(const fido_cred_t *);
size_t fido_cred_attstmt_len(const fido_cred_t *);
size_t fido_cred_authdata_len(const fido_cred_t *);
size_t fido_cred_authdata_raw_len(const fido_cred_t *);
size_t fido_cred_clientdata_hash_len(const fido_cred_t *);
size_t fido_cred_id_len(const fido_cred_t *);
size_t fido_cred_largeblob_key_len(const fido_cred_t *);
size_t fido_cred_pin_minlen(const fido_cred_t *);
size_t fido_cred_pubkey_len(const fido_cred_t *);
size_t fido_cred_sig_len(const fido_cred_t *);
size_t fido_cred_user_id_len(const fido_cred_t *);
size_t fido_cred_x5c_len(const fido_cred_t *);
size_t fido_cred_x5c_list_count(const fido_cred_t *);
size_t fido_cred_x5c_list_len(const fido_cred_t *, size_t);

uint8_t  fido_assert_flags(const fido_assert_t *, size_t);
uint32_t fido_assert_sigcount(const fido_assert_t *, size_t);
uint8_t  fido_cred_flags(const fido_cred_t *);
uint32_t fido_cred_sigcount(const fido_cred_t *);
uint8_t  fido_dev_protocol(const fido_dev_t *);
uint8_t  fido_dev_major(const fido_dev_t *);
uint8_t  fido_dev_minor(const fido_dev_t *);
uint8_t  fido_dev_build(const fido_dev_t *);
uint8_t  fido_dev_flags(const fido_dev_t *);
int16_t  fido_dev_info_vendor(const fido_dev_info_t *);
int16_t  fido_dev_info_product(const fido_dev_info_t *);
uint64_t fido_cbor_info_fwversion(const fido_cbor_info_t *);
uint64_t fido_cbor_info_maxcredbloblen(const fido_cbor_info_t *);
uint64_t fido_cbor_info_maxcredcntlst(const fido_cbor_info_t *);
uint64_t fido_cbor_info_maxcredidlen(const fido_cbor_info_t *);
uint64_t fido_cbor_info_maxlargeblob(const fido_cbor_info_t *);
uint64_t fido_cbor_info_maxmsgsiz(const fido_cbor_info_t *);
uint64_t fido_cbor_info_maxrpid_minpinlen(const fido_cbor_info_t *);
uint64_t fido_cbor_info_minpinlen(const fido_cbor_info_t *);
uint64_t fido_cbor_info_uv_attempts(const fido_cbor_info_t *);
uint64_t fido_cbor_info_uv_modality(const fido_cbor_info_t *);
int64_t  fido_cbor_info_rk_remaining(const fido_cbor_info_t *);

bool fido_dev_has_pin(const fido_dev_t *);
bool fido_dev_has_uv(const fido_dev_t *);
bool fido_dev_is_fido2(const fido_dev_t *);
bool fido_dev_is_winhello(const fido_dev_t *);
bool fido_dev_supports_credman(const fido_dev_t *);
bool fido_dev_supports_cred_prot(const fido_dev_t *);
bool fido_dev_supports_permissions(const fido_dev_t *);
bool fido_dev_supports_pin(const fido_dev_t *);
bool fido_dev_supports_uv(const fido_dev_t *);
bool fido_cbor_info_new_pin_required(const fido_cbor_info_t *);

int fido_dev_largeblob_get(fido_dev_t *, const unsigned char *, size_t,
    unsigned char **, size_t *);
int fido_dev_largeblob_set(fido_dev_t *, const unsigned char *, size_t,
    const unsigned char *, size_t, const char *);
int fido_dev_largeblob_remove(fido_dev_t *, const unsigned char *, size_t,
    const char *);
int fido_dev_largeblob_get_array(fido_dev_t *, unsigned char **, size_t *);
int fido_dev_largeblob_set_array(fido_dev_t *, const unsigned char *, size_t,
    const char *);

/**
 * @brief Converts the properties of @a assert into a list of cbor items @a argv.
 *
 * @param assert   getAssertion struct
 * @param argv     List of cbor items
 * @param argc     Number of available cbor items in @a argv, needs to be at least 5
 * @param ecdh     Shared secret
 * @param pk       Public key
 * @param pin_prot Pin protocol
 */
int fido_build_assert_cbor(const fido_assert_t *assert, cbor_item_t **argv, size_t argc,
    const fido_blob_t *ecdh, const es256_pk_t *pk, uint8_t pin_prot);
/**
 * @brief Converst a list of cbor items to a cbor byte array.
 *
 * @param cmd  CBOR command identifier
 * @param argv List of cbor items
 * @param argc Number of cbor items
 * @param f    Blob for the cbor byte array
 */
int cbor_build_frame_ext(uint8_t cmd, cbor_item_t *argv[], size_t argc, fido_blob_t **f);

/**
 * @brief Generate key-agreement pair and compute shared secret.
 *
 * @note Can not be used with WinHello.
 *
 * @param dev  Device handle
 * @param pk   Public key
 * @param ecdh Shared secret
 */
int fido_do_ecdh_ext(fido_dev_t *dev, es256_pk_t **pk, fido_blob_t **ecdh);

/**
 * @brief Request a pin-uv token and decode it into cbor items for a getAssertion command.
 *
 * @note Can not be used with WinHello.
 * 
 * @param dev    Device handle
 * @param assert getAssertion struct
 * @param pk     Host public key
 * @param ecdh   Shared secret
 * @param pin    Pin
 * @param auth   CBOR item to store the result of the authentication
 * @param opt    CBOR item to store the PIN/UV protocol version
 */
int cbor_add_uv_params_assert(fido_dev_t *dev, const fido_assert_t *assert, const es256_pk_t *pk,
    const fido_blob_t *ecdh, const char *pin, cbor_item_t **auth, cbor_item_t **opt);

/**
 * @brief Parses the content of an getAssertion response into an getAssertion struct.
 *
 * @details The getAssertion struct is reset prior to the parsing.
 *
 * @param msg    getAssertion response message
 * @param msglen Length of the message
 * @param assert getAssertion struct
 */
int fido_parse_get_assert_msg(uint8_t *msg, int msglen, fido_assert_t *assert);

/**
 * @brief Parses the content of a getNextAssertion response and adds it to an getAssertion struct.
 *
 * @param msg    getNextAssertion response message
 * @param msglen Length of the message
 * @param assert getAssertion struct
 */
int fido_parse_and_add_get_next_assert_msg(uint8_t *msg, int msglen, fido_assert_t *assert);

/**
 * @brief Decrypts the hmac secrets of a getAssertion response.
 *
 * @param pin_prot Pin protocol
 * @param assert   getAssertion struct
 * @param key      Shared secret to decrypt the hmac secrets
 */
int decrypt_hmac_secrets(uint8_t pin_prot, fido_assert_t *assert,
    const fido_blob_t *key);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* !_FIDO_H */
