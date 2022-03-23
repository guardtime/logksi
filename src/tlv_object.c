/*
 * Copyright 2013-2022 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

#include <string.h>
#include <stdlib.h>
#include <ksi/ksi.h>
#include <ksi/tlv_element.h>
#include "logksi_err.h"
#include "err_trckr.h"
#include "tlv_object.h"
#include "smart_file.h"
#include "api_wrapper.h"


typedef struct MetaRecordPair_st {
	KSI_Utf8String *key;
	KSI_Utf8String *value;
} MetaRecordPair;

struct MetaDataRecord_st {
	KSI_Integer *rec_index;
	MetaRecordPair *pair;
};

static void MetaRecordPair_free(MetaRecordPair *obj) {
	if (obj == NULL) return;
	KSI_Utf8String_free(obj->key);
	KSI_Utf8String_free(obj->value);
	free(obj);
	return;
}

int MetaDataRecord_new(KSI_CTX *ksi, uint64_t recIndex, const char *key, const char *value, MetaDataRecord **obj) {
	int res = KT_UNKNOWN_ERROR;
	MetaDataRecord *tmp = NULL;
	MetaRecordPair *tmpPair = NULL;
	KSI_Integer *tmpIndex = NULL;
	KSI_Utf8String *tmpKey = NULL;
	KSI_Utf8String *tmpValue = NULL;

	if (key == NULL || value == NULL || obj == NULL) return KT_INVALID_ARGUMENT;

	tmp = malloc(sizeof(MetaDataRecord));
	if (tmp == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmpPair = malloc(sizeof(MetaRecordPair));
	if (tmpPair == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	res = KSI_Integer_new(ksi, recIndex, &tmpIndex);
	if (res != KT_OK) goto cleanup;
	res = KSI_Utf8String_new(ksi, key, strlen(key) + 1, &tmpKey);
	if (res != KT_OK) goto cleanup;
	res = KSI_Utf8String_new(ksi, value, strlen(value) + 1, &tmpValue);
	if (res != KT_OK) goto cleanup;

	tmp->rec_index = tmpIndex;
	tmpPair->key = tmpKey;
	tmpPair->value = tmpValue;
	tmp->pair = tmpPair;

	*obj = tmp;

	tmpIndex = NULL;
	tmpKey = NULL;
	tmpValue = NULL;
	tmpPair = NULL;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_Integer_free(tmpIndex);
	KSI_Utf8String_free(tmpKey);
	KSI_Utf8String_free(tmpValue);
	free(tmpPair);
	free(tmp);

	return res;
}

void MetaDataRecord_free(MetaDataRecord *obj) {
	if (obj == NULL) return;
	KSI_Integer_free(obj->rec_index);
	MetaRecordPair_free(obj->pair);
	free(obj);
	return;
}

int MetaDataRecord_serialize(KSI_CTX *ksi, MetaDataRecord *rec, unsigned char **raw, size_t *raw_len) {
	int res = KT_UNKNOWN_ERROR;
	KSI_TlvElement *metadata = NULL;
	KSI_TlvElement *attrib_tlv = NULL;
	unsigned char buf[1024];
	size_t len = 0;

	if (ksi == NULL || rec == NULL || raw == NULL || raw_len == 0) return KT_INVALID_ARGUMENT;

	res = KSI_TlvElement_new(&metadata);
	if (res != KSI_OK) goto cleanup;
	metadata->ftlv.tag = 0x0911;

	res = KSI_TlvElement_setInteger(metadata, 0x01, rec->rec_index);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TlvElement_new(&attrib_tlv);
	if (res != KSI_OK) goto cleanup;
	attrib_tlv->ftlv.tag = 0x02;

	res = KSI_TlvElement_setUtf8String(attrib_tlv, 0x01, rec->pair->key);
	if (res != KSI_OK) goto cleanup;
	res = KSI_TlvElement_setUtf8String(attrib_tlv, 0x02, rec->pair->value);
	if (res != KSI_OK) goto cleanup;
	res = KSI_TlvElement_setElement(metadata, attrib_tlv);
	if (res != KSI_OK) goto cleanup;
	res = KSI_TlvElement_serialize(metadata, buf, sizeof(buf), &len, 0);
	if (res != KSI_OK) goto cleanup;

	*raw = malloc(len);
	if (*raw == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}
	memcpy(*raw, buf, len);
	*raw_len = len;

	res = KT_OK;

cleanup:
	KSI_TlvElement_free(metadata);
	KSI_TlvElement_free(attrib_tlv);

	return res;
}

int LOGKSI_FTLV_smartFileRead(SMART_FILE *sf, unsigned char *buf, size_t len, size_t *consumed, struct fast_tlv_s *t) {
	typedef int (*reader_t)(void *, unsigned char *, size_t, size_t *);
	int readData(void *fd, unsigned char *buf, size_t len, size_t *consumed, struct fast_tlv_s *t, reader_t read_fn);

	return readData(sf, buf, len, consumed, t, (reader_t) SMART_FILE_read);
}

int tlv_element_get_uint(KSI_TlvElement *tlv, KSI_CTX *ksi, unsigned tag, size_t *out) {
	int res;
	KSI_TlvElement *el = NULL;
	size_t len;
	size_t i;
	size_t val = 0;
	unsigned char buf[0xffff + 4];

	if (tlv == NULL || ksi == NULL || tag > 0x1fff || out == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_TlvElement_getElement(tlv, tag, &el);
	if (res != KSI_OK) goto cleanup;

	if (el != NULL) {
		if (el->ftlv.dat_len > 8 ) {
			res = KT_INVALID_INPUT_FORMAT;
			goto cleanup;
		}

		res = KSI_TlvElement_serialize(el, buf, sizeof(buf), &len, KSI_TLV_OPT_NO_HEADER);
		if (res != KSI_OK) goto cleanup;

		for (i = 0; i < len; i++) {
			val = (val << 8) | buf[i];
		}
	} else {
		res = KT_INVALID_INPUT_FORMAT;
		goto cleanup;
	}

	*out = val;
	res = KT_OK;

cleanup:

	KSI_TlvElement_free(el);
	return res;
}

int tlv_element_get_octet_string(KSI_TlvElement *tlv, KSI_CTX *ksi, unsigned tag, KSI_OctetString **out) {
	int res;
	KSI_OctetString *tmp = NULL;

	if (tlv == NULL || ksi == NULL || tag > 0x1fff || out == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_TlvElement_getOctetString(tlv, ksi, tag, &tmp);
	if (res != KSI_OK) goto cleanup;
	if (tmp == NULL) {
		res = KT_INVALID_INPUT_FORMAT;
		goto cleanup;
	}

	*out = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_OctetString_free(tmp);
	return res;
}

int tlv_element_get_hash(ERR_TRCKR *err, KSI_TlvElement *tlv, KSI_CTX *ksi, unsigned tag, KSI_DataHash **out) {
	int res;
	KSI_TlvElement *el = NULL;
	KSI_DataHash *hash = NULL;

	if (tlv == NULL || ksi == NULL || tag > 0x1fff || out == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_TlvElement_getElement(tlv, tag, &el);
	if (res != KSI_OK) goto cleanup;
	if (el == NULL) {
		res = KT_INVALID_INPUT_FORMAT;
		goto cleanup;
	}

	res = LOGKSI_DataHash_fromImprint(err, ksi, el->ptr + el->ftlv.hdr_len, el->ftlv.dat_len, &hash);
	if (res != KSI_OK) goto cleanup;

	*out = hash;
	hash = NULL;
	res = KT_OK;

cleanup:

	KSI_TlvElement_free(el);
	KSI_DataHash_free(hash);
	return res;
}

int tlv_element_set_uint(KSI_TlvElement *tlv, KSI_CTX *ksi, unsigned tag, KSI_uint64_t val) {
	int res;
	KSI_Integer *tmp = NULL;

	if (tlv == NULL || ksi == NULL || tag > 0x1fff) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_Integer_new(ksi, val, &tmp);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TlvElement_setInteger(tlv, tag, tmp);
	if (res != KSI_OK) goto cleanup;

cleanup:

	KSI_Integer_free(tmp);
	return res;
}

int tlv_element_set_hash(KSI_TlvElement *tlv, KSI_CTX *ksi, unsigned tag, KSI_DataHash *hash) {
	int res;
	KSI_OctetString *tmp = NULL;
	const unsigned char *buf = NULL;
	size_t len = 0;

	if (tlv == NULL || ksi == NULL || tag > 0x1fff || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_DataHash_getImprint(hash, &buf, &len);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OctetString_new(ksi, buf, len, &tmp);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TlvElement_setOctetString(tlv, tag, tmp);
	if (res != KSI_OK) goto cleanup;

cleanup:

	KSI_OctetString_free(tmp);
	return res;
}

int tlv_element_set_signature(KSI_TlvElement *tlv, KSI_CTX *ksi, unsigned tag, KSI_Signature *sig) {
	int res;
	KSI_OctetString *tmp = NULL;
	unsigned char *buf = NULL;
	size_t len = 0;

	if (tlv == NULL || ksi == NULL || tag > 0x1fff || sig == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_Signature_serialize(sig, &buf, &len);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OctetString_new(ksi, buf, len, &tmp);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TlvElement_setOctetString(tlv, tag, tmp);
	if (res != KSI_OK) goto cleanup;

cleanup:

	KSI_OctetString_free(tmp);
	KSI_free(buf);
	return res;
}

int tlv_element_create_hash(KSI_DataHash *hash, unsigned tag, KSI_TlvElement **tlv) {
	int res;
	KSI_TlvElement *tmp = NULL;
	unsigned char *imprint = NULL;
	size_t length = 0;

	if (hash == NULL || tag > 0x1fff || tlv == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_TlvElement_new(&tmp);
	if (res != KSI_OK) goto cleanup;

	res = KSI_DataHash_getImprint(hash, (const unsigned char **)&imprint, &length);
	if (res != KSI_OK) goto cleanup;

	tmp->ftlv.tag = tag;
	tmp->ptr = imprint;
	tmp->ftlv.dat_len = length;

	*tlv = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	KSI_TlvElement_free(tmp);
	return res;
}

int tlv_element_write_hash(KSI_DataHash *hash, unsigned tag, SMART_FILE *out) {
	int res;
	KSI_TlvElement *tlv = NULL;
	unsigned char buf[0xffff + 4];
	size_t len = 0;
	unsigned char *ptr = NULL;

	if (hash == NULL || tag > 0x1fff || out == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = tlv_element_create_hash(hash, tag, &tlv);
	if (res != KT_OK) goto cleanup;

	res = KSI_TlvElement_serialize(tlv, buf, sizeof(buf), &len, KSI_TLV_OPT_NO_MOVE);
	if (res != KSI_OK) goto cleanup;

	ptr = buf + sizeof(buf) - len;

	res = SMART_FILE_write(out, ptr, len, NULL);
	if (res != SMART_FILE_OK) goto cleanup;

	res = KT_OK;

cleanup:

	KSI_TlvElement_free(tlv);
	return res;
}

int tlv_element_parse_and_check_sub_elements(ERR_TRCKR *err, KSI_CTX *ksi, unsigned char *dat, size_t dat_len, size_t hdr_len, KSI_TlvElement **out) {
	int res;
	KSI_TlvElement *tmp = NULL;

	if (err == NULL || ksi == NULL || dat == NULL || dat_len == 0 || hdr_len == 0 || out == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = LOGKSI_FTLV_memReadN(err, ksi, dat + hdr_len, dat_len - hdr_len, NULL, 0, NULL);
	if (res != KSI_OK) goto cleanup;

	res = LOGKSI_TlvElement_parse(err, ksi, dat, dat_len, &tmp);
	if (res != KSI_OK) goto cleanup;

	*out = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_TlvElement_free(tmp);
	return res;
}

struct fold_wrapper_st {
	KSI_TlvElement *recChain;
	KSI_CTX *ksi;
};

/* Function for RECORD_INFO_foldl. */
static int foldl(void *acc, LINK_DIRECTION dir, KSI_DataHash *sibling, size_t corr) {
	int res = KT_UNKNOWN_ERROR;
	KSI_TlvElement *recChain = NULL;
	KSI_TlvElement *hashStep = NULL;
	struct fold_wrapper_st *wrap = NULL;

	if (acc == NULL || sibling == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	wrap = acc;
	recChain = wrap->recChain;


	res = KSI_TlvElement_new(&hashStep);
	if (res != KT_OK) goto cleanup;

	hashStep->ftlv.tag = dir == LEFT_LINK ? 0x02 : 0x03;

	if (corr) {
		res = tlv_element_set_uint(hashStep, wrap->ksi, 0x01, corr);
		if (res != KT_OK) goto cleanup;
	}
	res = tlv_element_set_hash(hashStep, wrap->ksi, 0x02, sibling);
	if (res != KT_OK) goto cleanup;

	res = KSI_TlvElement_appendElement(recChain, hashStep);
	if (res != KT_OK) goto cleanup;


	res = KT_OK;

cleanup:

	KSI_TlvElement_free(hashStep);

	return KT_OK;
}

int tlv_element_set_record_hash_chain(KSI_TlvElement *parentTlv, KSI_CTX *ksi, RECORD_INFO *record) {
	int res = KT_INVALID_ARGUMENT;
	struct fold_wrapper_st acc;

	if (ksi == NULL || record == NULL || parentTlv == NULL) res = KT_INVALID_ARGUMENT;

	acc.recChain = parentTlv;
	acc.ksi = ksi;

	res = RECORD_INFO_foldl(record, &acc, foldl);
	if (res != KT_OK) return res;

	return KT_OK;
}

int tlv_element_write_header(KSI_CTX *ksi, KSI_HashAlgorithm algo, KSI_OctetString *octet, KSI_DataHash *prevLeaf, SMART_FILE *out) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TlvElement *header = NULL;
	unsigned char buf[0xffff + 4];
	size_t len = 0;
	unsigned char *ptr = NULL;

	if (ksi == NULL || octet == NULL || prevLeaf == NULL || out == NULL) return KT_INVALID_ARGUMENT;

	res = KSI_TlvElement_new(&header);
	if (res != KSI_OK) goto cleanup;
	header->ftlv.tag = 0x901;

	res = tlv_element_set_uint(header, ksi, 0x01, algo);
	if (res != KSI_OK) goto cleanup;
	res = KSI_TlvElement_setOctetString(header, 0x02, octet);
	if (res != KSI_OK) goto cleanup;
	res = tlv_element_set_hash(header, ksi, 0x03, prevLeaf);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TlvElement_serialize(header, buf, sizeof(buf), &len, KSI_TLV_OPT_NO_MOVE);
	if (res != KSI_OK) goto cleanup;

	ptr = buf + sizeof(buf) - len;

	res = SMART_FILE_write(out, ptr, len, NULL);
	if (res != SMART_FILE_OK) goto cleanup;

	res = KT_OK;

cleanup:

	KSI_TlvElement_free(header);
	return res;
}

int tlv_element_write_signature_block(KSI_CTX *ksi, uint64_t recCount, KSI_Signature *sig, SMART_FILE *out) {
	int res = KT_UNKNOWN_ERROR;
	unsigned char buf[0xffff];
	size_t raw_len = 0;
	KSI_TlvElement *tlvSig = NULL;

	res = KSI_TlvElement_new(&tlvSig);
	if (res != KSI_OK) goto cleanup;
	tlvSig->ftlv.tag = 0x904;

	res = tlv_element_set_uint(tlvSig, ksi, 0x01, recCount);
	if (res != KSI_OK) goto cleanup;

	res = tlv_element_set_signature(tlvSig, ksi, 0x905, sig);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TlvElement_serialize(tlvSig, buf, sizeof(buf), &raw_len, 0);
	if (res != KSI_OK) goto cleanup;

	res = SMART_FILE_write(out, buf, raw_len, NULL);
	if (res != SMART_FILE_OK) goto cleanup;

	res = KT_OK;

cleanup:

	KSI_TlvElement_free(tlvSig);
	return res;
}
