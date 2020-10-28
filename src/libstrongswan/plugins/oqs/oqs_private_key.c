/*
 * Copyright (C) 2020 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "oqs_private_key.h"
#include "oqs_public_key.h"

#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <asn1/oid.h>

#define _GNU_SOURCE
#include <stdlib.h>

typedef struct private_oqs_private_key_t private_oqs_private_key_t;

/**
 * Private data of a oqs_private_key_t object.
 */
struct private_oqs_private_key_t {
	/**
	 * Public interface for this signer.
	 */
	oqs_private_key_t public;

	/**
	 * Key type
	 */
	key_type_t type;

	/**
	 * OID of the key type
	 */
	int oid;

	/**
	 * Key strength in bits
	 */
	int strength;

	/**
	 * Private key
	 */
	chunk_t key;

	/**
	 * Public key
	 */
	chunk_t pubkey;

	/**
	 * reference count
	 */
	refcount_t ref;
};

METHOD(private_key_t, get_type, key_type_t,
	private_oqs_private_key_t *this)
{
	return this->type;
}


METHOD(private_key_t, sign, bool,
	private_oqs_private_key_t *this, signature_scheme_t scheme, void *params,
	chunk_t data, chunk_t *signature)
{
	switch (scheme)
	{
		case SIGN_DILITHIUM_2:
			return FALSE;
		case SIGN_DILITHIUM_3:
			return FALSE;
		case SIGN_DILITHIUM_4:
			return FALSE;
		default:
			DBG1(DBG_LIB, "signature scheme %N not supported with OQS",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

METHOD(private_key_t, decrypt, bool,
	private_oqs_private_key_t *this, encryption_scheme_t scheme,
	chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "encryption scheme %N not supported",
				   encryption_scheme_names, scheme);
	return FALSE;
}

METHOD(private_key_t, get_keysize, int,
	private_oqs_private_key_t *this)
{
	return this->strength;
}

METHOD(private_key_t, get_public_key, public_key_t*,
	private_oqs_private_key_t *this)
{
	public_key_t *public;
	chunk_t pubkey;

	pubkey = oqs_public_key_info_encode(this->pubkey, this->oid);
	public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, this->type,
								BUILD_BLOB_ASN1_DER, pubkey, BUILD_END);
	free(pubkey.ptr);

	return public;
}

METHOD(private_key_t, get_encoding, bool,
	private_oqs_private_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	switch (type)
	{
		case PRIVKEY_ASN1_DER:
		case PRIVKEY_PEM:
		{
			bool success = TRUE;

			*encoding = asn1_wrap(ASN1_SEQUENCE, "cms",
							ASN1_INTEGER_0,
							asn1_algorithmIdentifier(this->oid),
							asn1_wrap(ASN1_OCTET_STRING, "s",
								asn1_simple_object(ASN1_OCTET_STRING, this->key)
							)
						);
			if (type == PRIVKEY_PEM)
			{
				chunk_t asn1_encoding = *encoding;

				success = lib->encoding->encode(lib->encoding, PRIVKEY_PEM,
								NULL, encoding, CRED_PART_PRIV_ASN1_DER,
								asn1_encoding, CRED_PART_END);
				chunk_clear(&asn1_encoding);
			}
			return success;
		}
		default:
			return FALSE;
	}
}

METHOD(private_key_t, get_fingerprint, bool,
	private_oqs_private_key_t *this, cred_encoding_type_t type,
	chunk_t *fp)
{
	bool success;

	if (lib->encoding->get_cache(lib->encoding, type, this, fp))
	{
		return TRUE;
	}
	success = oqs_public_key_fingerprint(this->pubkey, this->oid, type, fp);
	if (success)
	{
		lib->encoding->cache(lib->encoding, type, this, *fp);
	}
	return success;
}

METHOD(private_key_t, get_ref, private_key_t*,
	private_oqs_private_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(private_key_t, destroy, void,
	private_oqs_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, this);
		chunk_clear(&this->key);
		chunk_free(&this->pubkey);
		free(this);
	}
}

/**
 * Internal generic constructor
 */
static private_oqs_private_key_t *oqs_private_key_create_empty(key_type_t type)
{
	private_oqs_private_key_t *this;

	INIT(this,
		.public = {
			.key = {
				.get_type = _get_type,
				.sign = _sign,
				.decrypt = _decrypt,
				.get_keysize = _get_keysize,
				.get_public_key = _get_public_key,
				.equals = private_key_equals,
				.belongs_to = private_key_belongs_to,
				.get_fingerprint = _get_fingerprint,
				.has_fingerprint = private_key_has_fingerprint,
				.get_encoding = _get_encoding,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.type = type,
		.oid = oqs_key_type_to_oid(type),
		.ref = 1,
	);
	return this;
}

/**
 * See header.
 */
oqs_private_key_t *oqs_private_key_gen(key_type_t type, va_list args)
{
	private_oqs_private_key_t *this;

	if (!oqs_supported(type))
	{
		return NULL;
	}

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_KEY_SIZE:
				/* key_size argument is not needed */
				va_arg(args, u_int);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	this = oqs_private_key_create_empty(type);

	return this ? &this->public : NULL;
}

/**
 * See header.
 */
oqs_private_key_t *oqs_private_key_load(key_type_t type, va_list args)
{
	private_oqs_private_key_t *this;
	chunk_t key = chunk_empty;

	if (!oqs_supported(type))
	{
		return NULL;
	}

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				key = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (!asn1_parse_simple_object(&key, ASN1_OCTET_STRING, 0, "PrivateKey"))
	{
		return NULL;
	}
	this = oqs_private_key_create_empty(type);

	return this ? &this->public : NULL;
}
