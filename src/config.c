/*
 * Copyright (c) 2020-2022 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "fido.h"
#include "fido/config.h"
#include "fido/es256.h"
#include <stddef.h>
#include <stdint.h>

#define CMD_ENABLE_ENTATTEST	0x01
#define CMD_TOGGLE_ALWAYS_UV	0x02
#define CMD_SET_PIN_MINLEN	0x03
#define CMD_VENDOR_PROTOTYPE	0xFF

#define AUTH_CONFIG_SET_INTERFACE_OPTIONS_VENDOR_ID 0xb31e5238caa45176
#define AUTH_CONFIG_GET_INTERFACE_OPTIONS_VENDOR_ID 0x9b0ea7cd75180979

static int
config_prepare_hmac(uint8_t subcmd, const cbor_item_t *item, fido_blob_t *hmac)
{
	uint8_t prefix[32 + 2 * sizeof(uint8_t)], cbor[128];
	size_t cbor_len = 0;

	memset(prefix, 0xff, sizeof(prefix));
	prefix[sizeof(prefix) - 2] = CTAP_CBOR_CONFIG;
	prefix[sizeof(prefix) - 1] = subcmd;

	if (item != NULL) {
		if ((cbor_len = cbor_serialize(item, cbor, sizeof(cbor))) == 0) {
			fido_log_debug("%s: cbor_serialize", __func__);
			return -1;
		}
	}
	if ((hmac->ptr = malloc(cbor_len + sizeof(prefix))) == NULL) {
		fido_log_debug("%s: malloc", __func__);
		return -1;
	}
	memcpy(hmac->ptr, prefix, sizeof(prefix));
	memcpy(hmac->ptr + sizeof(prefix), cbor, cbor_len);
	hmac->len = cbor_len + sizeof(prefix);

	return 0;
}

static int
config_tx(fido_dev_t *dev, uint8_t subcmd, cbor_item_t **paramv, size_t paramc,
    const char *pin, int *ms)
{
	cbor_item_t *argv[4];
	es256_pk_t *pk = NULL;
	fido_blob_t *ecdh = NULL, f, hmac;
	const uint8_t cmd = CTAP_CBOR_CONFIG;
	int r = FIDO_ERR_INTERNAL;

	memset(&f, 0, sizeof(f));
	memset(&hmac, 0, sizeof(hmac));
	memset(&argv, 0, sizeof(argv));

	/* subCommand */
	if ((argv[0] = cbor_build_uint8(subcmd)) == NULL) {
		fido_log_debug("%s: cbor encode", __func__);
		goto fail;
	}

	/* subCommandParams */
	if (paramc != 0 &&
	    (argv[1] = cbor_flatten_vector(paramv, paramc)) == NULL) {
		fido_log_debug("%s: cbor_flatten_vector", __func__);
		goto fail;
	}

	/* pinProtocol, pinAuth */
	if (pin != NULL ||
	    (fido_dev_supports_permissions(dev) && fido_dev_has_uv(dev))) {
		if (config_prepare_hmac(subcmd, argv[1], &hmac) < 0) {
			fido_log_debug("%s: config_prepare_hmac", __func__);
			goto fail;
		}
		if ((r = fido_do_ecdh(dev, &pk, &ecdh, ms)) != FIDO_OK) {
			fido_log_debug("%s: fido_do_ecdh", __func__);
			goto fail;
		}
		if ((r = cbor_add_uv_params(dev, cmd, &hmac, pk, ecdh, pin,
		    NULL, &argv[3], &argv[2], ms)) != FIDO_OK) {
			fido_log_debug("%s: cbor_add_uv_params", __func__);
			goto fail;
		}
	}

	/* framing and transmission */
	if (cbor_build_frame(cmd, argv, nitems(argv), &f) < 0 ||
	    fido_tx(dev, CTAP_CMD_CBOR, f.ptr, f.len, ms) < 0) {
		fido_log_debug("%s: fido_tx", __func__);
		r = FIDO_ERR_TX;
		goto fail;
	}

	r = FIDO_OK;
fail:
	cbor_vector_free(argv, nitems(argv));
	es256_pk_free(&pk);
	fido_blob_free(&ecdh);
	free(f.ptr);
	free(hmac.ptr);

	return r;
}

static int
config_enable_entattest_wait(fido_dev_t *dev, const char *pin, int *ms)
{
	int r;

	if ((r = config_tx(dev, CMD_ENABLE_ENTATTEST, NULL, 0, pin,
	    ms)) != FIDO_OK)
		return r;

	return fido_rx_cbor_status(dev, ms);
}

int
fido_dev_enable_entattest(fido_dev_t *dev, const char *pin)
{
	int ms = dev->timeout_ms;

	return (config_enable_entattest_wait(dev, pin, &ms));
}

static int
config_toggle_always_uv_wait(fido_dev_t *dev, const char *pin, int *ms)
{
	int r;

	if ((r = config_tx(dev, CMD_TOGGLE_ALWAYS_UV, NULL, 0, pin,
	    ms)) != FIDO_OK)
		return r;

	return (fido_rx_cbor_status(dev, ms));
}

int
fido_dev_toggle_always_uv(fido_dev_t *dev, const char *pin)
{
	int ms = dev->timeout_ms;

	return config_toggle_always_uv_wait(dev, pin, &ms);
}
static int config_vendor_prototype_tx(fido_dev_t *dev, uint64_t vendor_id,
                                      cbor_item_t *item, const char *pin,
                                      int *ms)
{
  cbor_item_t *argv[2];
  int r;

  memset(argv, 0, sizeof(argv));

  if ((argv[0] = cbor_build_uint64(vendor_id)) == NULL) {
    fido_log_debug("%s: cbor_encode_uint64", __func__);
    r = FIDO_ERR_INTERNAL;
    goto fail;
  }

  size_t nitems = 1;
  if (item != NULL) {
    argv[1] = item;
    nitems = 2;
  }

  r = config_tx(dev, CMD_VENDOR_PROTOTYPE, argv, nitems, pin, ms);

fail:
  cbor_vector_free(argv, nitems(argv));

  return r;
}

/**
* This is a helper function for vendor prototype command reception, where a
* return value (other than the CTAP status) is expected.
* NOTE: currently this function only accepts a single byte return value.
*/
static int
config_vendor_prototype_rx(fido_dev_t *dev, uint8_t *out, int *ms)
{
	unsigned char *msg;
	int msglen = 0;
	int r;

	if ((msg = malloc(FIDO_MAXMSG)) == NULL) {
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if ((msglen = fido_rx(dev, CTAP_CMD_CBOR, msg, FIDO_MAXMSG, ms)) < 0 ||
	    msglen < 1) {
		fido_log_debug("%s: fido_rx", __func__);
		r = FIDO_ERR_RX;
		goto fail;
	}

	r = (int)msg[0];
	if (r == FIDO_OK && out != NULL) {
    if (msglen < 2) {
      fido_log_debug("%s: fido_rx", __func__);
      r = FIDO_ERR_RX;
      goto fail;
    }
    *out = msg[1];
  }

fail:
	freezero(msg, FIDO_MAXMSG);
	return r;
}

static int
config_get_active_interfaces_wait(fido_dev_t *dev, uint8_t *activeInterfaces, const char *pin, int *ms)
{
	int r;
	if ((r = config_vendor_prototype_tx(dev, (uint64_t) AUTH_CONFIG_GET_INTERFACE_OPTIONS_VENDOR_ID, NULL, pin, ms)) != FIDO_OK) {
		return r;
  }
	return config_vendor_prototype_rx(dev, activeInterfaces, ms);
}

int
fido_dev_get_active_interfaces(fido_dev_t *dev, uint8_t *activeInterfaces, const char *pin)
{
	int ms = dev->timeout_ms;

	return config_get_active_interfaces_wait(dev, activeInterfaces, pin, &ms);
}

static int
config_set_active_interfaces_wait(fido_dev_t *dev, const uint8_t activeInterfaces, const char *pin, int *ms)
{
  cbor_item_t *item = NULL;
	int r;

	if (activeInterfaces && (item = cbor_build_uint8(activeInterfaces)) == NULL) {
		fido_log_debug("%s: cbor_encode_uint8", __func__);
		return FIDO_ERR_INTERNAL;
	}

	if ((r = config_vendor_prototype_tx(dev, (uint64_t) AUTH_CONFIG_SET_INTERFACE_OPTIONS_VENDOR_ID, item, pin,
	    ms)) != FIDO_OK)
		return r;

	return (fido_rx_cbor_status(dev, ms));
}

int
fido_dev_set_active_interfaces(fido_dev_t *dev, const uint8_t activeInterfaces, const char *pin)
{
	int ms = dev->timeout_ms;

	return config_set_active_interfaces_wait(dev, activeInterfaces, pin, &ms);
}

static int
config_pin_minlen_tx(fido_dev_t *dev, size_t len, bool force,
    const fido_str_array_t *rpid, const char *pin, int *ms)
{
	cbor_item_t *argv[3];
	int r;

	memset(argv, 0, sizeof(argv));

	if ((rpid == NULL && len == 0 && !force) || len > UINT8_MAX) {
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto fail;
	}
	if (len && (argv[0] = cbor_build_uint8((uint8_t)len)) == NULL) {
		fido_log_debug("%s: cbor_encode_uint8", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}
	if (rpid != NULL && (argv[1] = cbor_encode_str_array(rpid)) == NULL) {
		fido_log_debug("%s: cbor_encode_str_array", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}
	if (force && (argv[2] = cbor_build_bool(true)) == NULL) {
		fido_log_debug("%s: cbor_build_bool", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}
	if ((r = config_tx(dev, CMD_SET_PIN_MINLEN, argv, nitems(argv),
	    pin, ms)) != FIDO_OK) {
		fido_log_debug("%s: config_tx", __func__);
		goto fail;
	}

fail:
	cbor_vector_free(argv, nitems(argv));

	return r;
}

static int
config_pin_minlen(fido_dev_t *dev, size_t len, bool force,
    const fido_str_array_t *rpid, const char *pin, int *ms)
{
	int r;

	if ((r = config_pin_minlen_tx(dev, len, force, rpid, pin,
	    ms)) != FIDO_OK)
		return r;

	return fido_rx_cbor_status(dev, ms);
}

int
fido_dev_set_pin_minlen(fido_dev_t *dev, size_t len, const char *pin)
{
	int ms = dev->timeout_ms;

	return config_pin_minlen(dev, len, false, NULL, pin, &ms);
}

int
fido_dev_force_pin_change(fido_dev_t *dev, const char *pin)
{
	int ms = dev->timeout_ms;

	return config_pin_minlen(dev, 0, true, NULL, pin, &ms);
}

int
fido_dev_set_pin_minlen_rpid(fido_dev_t *dev, const char * const *rpid,
    size_t n, const char *pin)
{
	fido_str_array_t sa;
	int ms = dev->timeout_ms;
	int r;

	memset(&sa, 0, sizeof(sa));
	if (fido_str_array_pack(&sa, rpid, n) < 0) {
		fido_log_debug("%s: fido_str_array_pack", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}
	r = config_pin_minlen(dev, 0, false, &sa, pin, &ms);
fail:
	fido_str_array_free(&sa);

	return r;
}
