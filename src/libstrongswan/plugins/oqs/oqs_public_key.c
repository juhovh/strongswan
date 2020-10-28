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

#include "oqs_public_key.h"

#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <asn1/oid.h>

typedef struct private_oqs_public_key_t private_oqs_public_key_t;

/**
 * Private data structure with signing context.
 */
struct private_oqs_public_key_t {
	/**
	 * Public interface for this signer.
	 */
	oqs_public_key_t public;

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
	 * Raw public key
	 */
	chunk_t pubkey;

	/**
	 * reference counter
	 */
	refcount_t ref;
};

METHOD(public_key_t, get_type, key_type_t,
	private_oqs_public_key_t *this)
{
	return this->type;
}

METHOD(public_key_t, verify, bool,
	private_oqs_public_key_t *this, signature_scheme_t scheme, void *params,
	chunk_t data, chunk_t signature)
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
			DBG1(DBG_LIB, "signature scheme %N not supported by OQS",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

METHOD(public_key_t, encrypt_, bool,
	private_oqs_public_key_t *this, encryption_scheme_t scheme,
	chunk_t plain, chunk_t *crypto)
{
	DBG1(DBG_LIB, "encryption scheme %N not supported",
				   encryption_scheme_names, scheme);
	return FALSE;
}

METHOD(public_key_t, get_keysize, int,
	private_oqs_public_key_t *this)
{
	return this->strength;
}

METHOD(public_key_t, get_encoding, bool,
	private_oqs_public_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	bool success = TRUE;

	*encoding = oqs_public_key_info_encode(this->pubkey, this->oid);

	if (type != PUBKEY_SPKI_ASN1_DER)
	{
		chunk_t asn1_encoding = *encoding;

		success = lib->encoding->encode(lib->encoding, type,
						NULL, encoding, CRED_PART_PUB_ASN1_DER,
						asn1_encoding, CRED_PART_END);
		chunk_clear(&asn1_encoding);
	}

	return success;
}

METHOD(public_key_t, get_fingerprint, bool,
	private_oqs_public_key_t *this, cred_encoding_type_t type, chunk_t *fp)
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

METHOD(public_key_t, get_ref, public_key_t*,
	private_oqs_public_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(public_key_t, destroy, void,
	private_oqs_public_key_t *this)
{
	if (ref_put(&this->ref))
	{
		chunk_free(&this->pubkey);
		lib->encoding->clear_cache(lib->encoding, this);
		free(this);
	}
}

/**
 * ASN.1 definition of an OQS public key
 */
static const asn1Object_t pubkeyObjects[] = {
	{ 0, "subjectPublicKeyInfo",ASN1_SEQUENCE,		ASN1_OBJ  }, /*  0 */
	{ 1,   "algorithm",			ASN1_EOC,			ASN1_RAW  }, /*  1 */
	{ 1,   "subjectPublicKey",	ASN1_BIT_STRING,	ASN1_BODY }, /*  2 */
	{ 0, "exit",				ASN1_EOC,			ASN1_EXIT }
};
#define OQS_SUBJECT_PUBLIC_KEY_ALGORITHM	1
#define OQS_SUBJECT_PUBLIC_KEY				2

/**
 * See header.
 */
oqs_public_key_t *oqs_public_key_load(key_type_t type, va_list args)
{
	private_oqs_public_key_t *this;
	chunk_t blob = chunk_empty, object, param;
	asn1_parser_t *parser;
	bool success = FALSE;
	int objectID;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (blob.len == 0)
	{
		return NULL;
	}

	INIT(this,
		.public = {
			.key = {
				.get_type = _get_type,
				.verify = _verify,
				.encrypt = _encrypt_,
				.equals = public_key_equals,
				.get_keysize = _get_keysize,
				.get_fingerprint = _get_fingerprint,
				.has_fingerprint = public_key_has_fingerprint,
				.get_encoding = _get_encoding,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.ref = 1,
	);

	parser = asn1_parser_create(pubkeyObjects, blob);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case OQS_SUBJECT_PUBLIC_KEY_ALGORITHM:
				this->oid = asn1_parse_algorithmIdentifier(object,
								parser->get_level(parser)+1, &param);
				this->type = oqs_key_type_from_oid(this->oid);
				if (this->type == KEY_ANY)
				{
					goto end;
				}
				break;
			case OQS_SUBJECT_PUBLIC_KEY:
				this->pubkey = chunk_clone(chunk_skip(object, 1));
				break;
		}
	}
	success = parser->success(parser);

end:
	parser->destroy(parser);
	if (!success)
	{
		destroy(this);
		return NULL;
	}

	return &this->public;
}

/**
 * See header.
 */
bool oqs_supported(key_type_t type)
{
	switch (type)
	{
		case KEY_DILITHIUM_2:
		case KEY_DILITHIUM_3:
		case KEY_DILITHIUM_4:
			return TRUE;
		default:
			return FALSE;
	}
}

/**
 * See header.
 */
int oqs_key_type_to_oid(key_type_t type)
{
	switch (type)
	{
		case KEY_DILITHIUM_2:
			return OID_DILITHIUM_2;
		case KEY_DILITHIUM_3:
			return OID_DILITHIUM_3;
		case KEY_DILITHIUM_4:
			return OID_DILITHIUM_4;
		default:
			return OID_UNKNOWN;
	}
}

/**
 * See header.
 */
key_type_t oqs_key_type_from_oid(int oid)
{
	switch (oid)
	{
		case OID_DILITHIUM_2:
			return KEY_DILITHIUM_2;
		case OID_DILITHIUM_3:
			return KEY_DILITHIUM_3;
		case OID_DILITHIUM_4:
			return KEY_DILITHIUM_4;
		default:
			return KEY_ANY;
	}
}

/**
 * See header.
 */
chunk_t oqs_public_key_info_encode(chunk_t pubkey, int oid)
{
	return asn1_wrap(ASN1_SEQUENCE, "mm",
					asn1_wrap(ASN1_SEQUENCE, "m",
						asn1_build_known_oid(oid)),
					asn1_bitstring("c", pubkey));
}

/**
 * See header.
 */
bool oqs_public_key_fingerprint(chunk_t pubkey, int oid,
								cred_encoding_type_t type, chunk_t *fp)
{
	hasher_t *hasher;
	chunk_t key;

	switch (type)
	{
		case KEYID_PUBKEY_SHA1:
			key = chunk_clone(pubkey);
			break;
		case KEYID_PUBKEY_INFO_SHA1:
			key = oqs_public_key_info_encode(pubkey, oid);
			break;
		default:
			return FALSE;
	}

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher || !hasher->allocate_hash(hasher, key, fp))
	{
		DBG1(DBG_LIB, "SHA1 hash algorithm not supported");
		DESTROY_IF(hasher);
		free(key.ptr);
		return FALSE;
	}
	hasher->destroy(hasher);
	free(key.ptr);

	return TRUE;
}
