/*
 * Copyright 2013-2016 Guardtime, Inc.
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
#include "param_set/param_set.h"
#include "err_trckr.h"
#include <ksi/ksi.h>
#include "ksitool_err.h"
#include "api_wrapper.h"
#include "debug_print.h"
#include <ksi/tlv_element.h>
#include "rsyslog.h"

#ifndef _WIN32
#include <fcntl.h>
#endif


static int calculate_new_intermediate_hash(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash *leftHash, KSI_DataHash *rightHash, unsigned char level, KSI_DataHash **nodeHash) {
	int res;
	KSI_DataHasher *hasher = NULL;
	KSI_DataHash *tmp = NULL;

	if (ksi == NULL || blocks == NULL || leftHash == NULL || rightHash == NULL || nodeHash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_DataHasher_open(ksi, blocks->hashAlgo, &hasher);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addImprint(hasher, leftHash);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addImprint(hasher, rightHash);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_add(hasher, &level, 1);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_close(hasher, &tmp);
	if (res != KSI_OK) goto cleanup;

	*nodeHash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(tmp);
	KSI_DataHasher_free(hasher);
	return res;
}

static int calculate_new_leaf_hash(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash *recordHash, int isMetaRecordHash, KSI_DataHash **leafHash) {
	int res;
	KSI_DataHasher *hasher = NULL;
	KSI_DataHash *mask = NULL;
	KSI_DataHash *tmp = NULL;

	if (ksi == NULL || blocks == NULL || recordHash == NULL || leafHash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_DataHasher_open(ksi, blocks->hashAlgo, &hasher);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addImprint(hasher, blocks->prevLeaf);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addOctetString(hasher, blocks->randomSeed);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_close(hasher, &mask);
	if (res != KSI_OK) goto cleanup;

	if (isMetaRecordHash) {
		res = calculate_new_intermediate_hash(ksi, blocks, recordHash, mask, 1, &tmp);
		if (res != KT_OK) goto cleanup;
	} else {
		res = calculate_new_intermediate_hash(ksi, blocks, mask, recordHash, 1, &tmp);
		if (res != KT_OK) goto cleanup;
	}

	*leafHash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(mask);
	KSI_DataHash_free(tmp);
	KSI_DataHasher_free(hasher);
	return res;
}

int calculate_root_hash(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash **hash) {
	int res;
	unsigned char i = 0;
	KSI_DataHash *root = NULL;
	KSI_DataHash *tmp = NULL;

	if (ksi == NULL || blocks == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (blocks->balanced) {
		root = KSI_DataHash_ref(blocks->MerkleTree[blocks->treeHeight - 1]);
	} else {
		while (i < blocks->treeHeight) {
			if (root == NULL) {
				root = KSI_DataHash_ref(blocks->MerkleTree[i]);
				i++;
				continue;
			}
			if (blocks->MerkleTree[i]) {
				res = calculate_new_intermediate_hash(ksi, blocks, blocks->MerkleTree[i], root, i + 2, &tmp);
				if (res != KT_OK) goto cleanup;
				KSI_DataHash_free(root);
				root = tmp;
			}
			i++;
		}
	}

	*hash = KSI_DataHash_ref(root);
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(root);
	KSI_DataHash_free(tmp);
	return res;
}

static int get_aggregation_level(BLOCK_INFO *blocks) {
	int level = 0;
	if (blocks != NULL) {
		if (blocks->version == LOGSIG11) {
			level = 0;
		} else {
			level = blocks->treeHeight + 1;
		}
	}
	return level;
}

int add_hash_to_merkle_tree(KSI_CTX *ksi, BLOCK_INFO *blocks, int isMetaRecordHash, KSI_DataHash *hash) {
	int res;
	unsigned char i = 0;
	KSI_DataHash *lastHash = NULL;
	KSI_DataHash *right = NULL;
	KSI_DataHash *tmp = NULL;

	if (ksi == NULL || blocks == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = calculate_new_leaf_hash(ksi, blocks, hash, isMetaRecordHash, &lastHash);
	if (res != KT_OK) goto cleanup;

	right = KSI_DataHash_ref(lastHash);

	blocks->balanced = 0;
	while (blocks->MerkleTree[i] != NULL) {
		res = calculate_new_intermediate_hash(ksi, blocks, blocks->MerkleTree[i], right, i + 2, &tmp);
		if (res != KT_OK) goto cleanup;
		KSI_DataHash_free(blocks->notVerified[i]);
		blocks->notVerified[i] = KSI_DataHash_ref(right);
		KSI_DataHash_free(right);
		right = tmp;
		KSI_DataHash_free(blocks->MerkleTree[i]);
		blocks->MerkleTree[i] = NULL;
		i++;
	}
	blocks->MerkleTree[i] = right;
	KSI_DataHash_free(blocks->notVerified[i]);
	blocks->notVerified[i] = KSI_DataHash_ref(blocks->MerkleTree[i]);

	if (i == blocks->treeHeight) {
		blocks->treeHeight++;
		blocks->balanced = 1;
	}

	KSI_DataHash_free(blocks->prevLeaf);
	blocks->prevLeaf = lastHash;
	lastHash = NULL;
	right = NULL;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(lastHash);
	KSI_DataHash_free(right);
	KSI_DataHash_free(tmp);
	return res;
}

int get_hash_of_logline(KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files, KSI_DataHash **hash) {
	int res;
	KSI_DataHash *tmp = NULL;
	char buf[1024];

	if (files == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (files->inLogFile) {
		if (fgets(buf, sizeof(buf), files->inLogFile) == NULL) {
			res = KT_IO_ERROR;
			goto cleanup;
		}
		/* Last character (newline) is not used in hash calculation. */
		res = KSI_DataHash_create(ksi, buf, strlen(buf) - 1, blocks->hashAlgo, &tmp);
		if (res != KSI_OK) goto cleanup;
	}
	*hash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(tmp);
	return res;
}

int get_hash_of_metarecord(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_TlvElement *tlv, KSI_DataHash **hash) {
	int res;
	KSI_DataHash *tmp = NULL;

	if (tlv == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* The complete metarecord TLV us used in hash calculation. */
	res = KSI_DataHash_create(ksi, tlv->ptr, tlv->ftlv.hdr_len + tlv->ftlv.dat_len, blocks->hashAlgo, &tmp);
	if (res != KSI_OK) goto cleanup;

	*hash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(tmp);
	return res;
}

static size_t max_intermediate_records(size_t nof_records) {
	size_t max = 0;
	while (nof_records) {
		max = max + nof_records;
		nof_records = nof_records / 2;
	}
	return max;
}

int tlv_element_get_uint(KSI_TlvElement *tlv, KSI_CTX *ksi, unsigned tag, KSI_uint64_t *out) {
	int res;
	KSI_Integer *tmp = NULL;

	res = KSI_TlvElement_getInteger(tlv, ksi, tag, &tmp);
	if (res != KSI_OK) goto cleanup;
	if (tmp == NULL) {
		res = KT_INVALID_INPUT_FORMAT;
		goto cleanup;
	}

	*out = KSI_Integer_getUInt64(tmp);
	res = KT_OK;

cleanup:

	KSI_Integer_free(tmp);
	return res;
}

int tlv_get_octet_string(KSI_TlvElement *tlv, KSI_CTX *ksi, unsigned tag, KSI_OctetString **out) {
	int res;
	KSI_OctetString *tmp = NULL;

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

int tlv_element_get_hash(KSI_TlvElement *tlv, KSI_CTX *ksi, unsigned tag, KSI_DataHash **out) {
	int res;
	KSI_TlvElement *el = NULL;
	KSI_DataHash *hash = NULL;

	res = KSI_TlvElement_getElement(tlv, tag, &el);
	if (res != KSI_OK) goto cleanup;
	if (el == NULL) {
		res = KT_INVALID_INPUT_FORMAT;
		goto cleanup;
	}

	res = KSI_DataHash_fromImprint(ksi, el->ptr + el->ftlv.hdr_len, el->ftlv.dat_len, &hash);
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

	res = KSI_Integer_new(ksi, val, &tmp);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TlvElement_setInteger(tlv, tag, tmp);
	if (res != KSI_OK) goto cleanup;

cleanup:

	KSI_Integer_free(tmp);
	return res;
}

int tlv_element_set_signature(KSI_TlvElement *tlv, KSI_CTX *ksi, unsigned tag, KSI_Signature *sig) {
	int res;
	KSI_OctetString *tmp = NULL;
	unsigned char *buf = NULL;
	size_t len = 0;

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

static int process_magic_number(PARAM_SET *set, ERR_TRCKR *err, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	char buf[10];
	size_t count = 0;
	size_t magicLength;
	char *magicNumbers[] = {"LOGSIG11", "LOGSIG12"};
	int d = 0;
	int i;
	FILE *in = NULL;

	if (set == NULL || err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	in = files->inBlockFile ? files->inBlockFile : files->inSigFile;
	if (in == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	d = PARAM_SET_isSetByName(set, "d");
	print_progressDesc(d, "Processing magic number... ");

	res = KT_INVALID_INPUT_FORMAT;
	for (i = 0; i < sizeof(magicNumbers) / sizeof(magicNumbers[0]); i++) {
		magicLength = strlen(magicNumbers[i]);
		count = fread(buf, 1, magicLength, in);
		if (count == magicLength && strncmp(buf, magicNumbers[i], magicLength) == 0) {
			blocks->version = i;
			res = KT_OK;
			break;
		}
		rewind(in);
	}

	if (res != KT_OK) {
		ERR_CATCH_MSG(err, res, "Error: Magic number not found at the beginning of log signature file.");
	}

	if (files->outSigFile) {
		count = fwrite(buf, 1, magicLength, files->outSigFile);
		if (count != magicLength) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Could not copy magic number to log signature file.");
		}
	}

	res = KT_OK;

cleanup:

	print_progressResult(res);
	return res;
}

static int process_block_header(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	int d = 0;
	KSI_OctetString *seed = NULL;
	KSI_DataHash *hash = NULL;
	unsigned char i = 0;
	KSI_TlvElement *tlv = NULL;
	KSI_uint64_t algo;

	if (set == NULL || err == NULL || ksi == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	d = PARAM_SET_isSetByName(set, "d");
	print_progressDesc(d, "Block no. %3d: processing block header... ", blocks->blockNo + 1);

	if (blocks->blockNo > blocks->sigNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: block signature data missing.", blocks->blockNo);
	}
	blocks->blockNo++;
	blocks->nofRecordHashes = 0;
	blocks->nofIntermediateHashes = 0;

	res = KSI_TlvElement_parse(blocks->ftlv_raw, blocks->ftlv_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse block header as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &algo);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse hash algorithm.", blocks->blockNo);

	res = tlv_get_octet_string(tlv, ksi, 0x02, &seed);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse random seed.", blocks->blockNo);

	res = tlv_element_get_hash(tlv, ksi, 0x03, &hash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse last hash of previous block.", blocks->blockNo);

	if (blocks->prevLeaf != NULL) {
		if (!KSI_DataHash_equals(blocks->prevLeaf, hash)) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: previous leaf hashes not equal.", blocks->blockNo);
		}
	}

	if (files->outSigFile) {
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->outSigFile) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to copy block header.", blocks->blockNo);
		}
	}

	blocks->hashAlgo = algo;
	KSI_OctetString_free(blocks->randomSeed);
	blocks->randomSeed = seed;
	seed = NULL;
	KSI_DataHash_free(blocks->prevLeaf);
	blocks->prevLeaf = hash;
	hash = NULL;

	while (i < blocks->treeHeight) {
		KSI_DataHash_free(blocks->MerkleTree[i]);
		blocks->MerkleTree[i] = NULL;
		KSI_DataHash_free(blocks->notVerified[i]);
		blocks->notVerified[i] = NULL;
		i++;
	}
	blocks->treeHeight = 0;
	blocks->balanced = 0;
	KSI_DataHash_free(blocks->rootHash);
	blocks->rootHash = NULL;
	KSI_DataHash_free(blocks->metarecordHash);
	blocks->metarecordHash = NULL;

	res = KT_OK;

cleanup:

	print_progressResult(res);
	KSI_OctetString_free(seed);
	KSI_DataHash_free(hash);
	KSI_TlvElement_free(tlv);
	return res;
}

static int process_record_hash(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	int d = 0;
	KSI_DataHash *recordHash = NULL;
	KSI_DataHash *hash = NULL;

	if (set == NULL || err == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	d = PARAM_SET_isSetByName(set, "d");
	print_progressDesc(d, "Block no. %3d: processing record hash... ", blocks->blockNo);

	if (blocks->blockNo == blocks->sigNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: record hash without preceding block header found.", blocks->blockNo + 1);
	}
	blocks->nofRecordHashes++;

	res = KSI_DataHash_fromImprint(ksi, blocks->ftlv_raw + blocks->ftlv.hdr_len, blocks->ftlv.dat_len, &recordHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to create hash of record no. %3d.", blocks->blockNo, blocks->nofRecordHashes);

	if (blocks->metarecordHash != NULL) {
		/* This is a metarecord hash. */
		if (!KSI_DataHash_equals(recordHash, blocks->metarecordHash)) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: metarecord hashes not equal.", blocks->blockNo);
		}

		res = add_hash_to_merkle_tree(ksi, blocks, 1, blocks->metarecordHash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to add metarecord hash to Merkle tree.", blocks->blockNo);

		KSI_DataHash_free(blocks->metarecordHash);
		blocks->metarecordHash = NULL;
	} else {
		/* This is a logline record hash. */
		if (files->inLogFile) {
			res = get_hash_of_logline(ksi, blocks, files, &hash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to calculate hash of logline no. %3d.", blocks->blockNo, blocks->nofRecordHashes);

			if (!KSI_DataHash_equals(recordHash, hash)) {
				res = KT_VERIFICATION_FAILURE;
				ERR_CATCH_MSG(err, res, "Error: Block no. %3d: record hashes not equal.", blocks->blockNo);
			}
		}

		res = add_hash_to_merkle_tree(ksi, blocks, 0, recordHash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to add hash to Merkle tree.", blocks->blockNo);
	}

	if (files->outSigFile) {
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->outSigFile) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to copy record hash.", blocks->blockNo);
		}
	}
	res = KT_OK;

cleanup:

	print_progressResult(res);
	KSI_DataHash_free(recordHash);
	KSI_DataHash_free(hash);
	return res;
}

static int process_intermediate_hash(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	int d = 0;
	KSI_DataHash *tmpHash = NULL;
	KSI_DataHash *hash = NULL;
	unsigned char i;

	if (set == NULL || err == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	d = PARAM_SET_isSetByName(set, "d");
	print_progressDesc(d, "Block no. %3d: processing intermediate hash... ", blocks->blockNo);

	if (blocks->blockNo == blocks->sigNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: intermediate hash without preceding block header found.", blocks->blockNo + 1);
	}
	blocks->nofIntermediateHashes++;

	res = KSI_DataHash_fromImprint(ksi, blocks->ftlv_raw + blocks->ftlv.hdr_len, blocks->ftlv.dat_len, &tmpHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to create intermediate hash.", blocks->blockNo);

	if (files->outSigFile) {
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->outSigFile) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to copy record hash.", blocks->blockNo);
		}
	}

	/* If the block contains intermediate hashes, but not record hashes:
	 * Calculate missing record hashes from the records in the logfile and
	 * build the Merkle tree according to the number of intermediate hashes encountered. */
	if (blocks->nofIntermediateHashes > max_intermediate_records(blocks->nofRecordHashes)) {
		if (files->inLogFile) {
			blocks->nofRecordHashes++;
			res = get_hash_of_logline(ksi, blocks, files, &hash);
			res = add_hash_to_merkle_tree(ksi, blocks, 0, hash);
			KSI_DataHash_free(hash);
			hash = NULL;
		}
	}

	if (blocks->nofRecordHashes) {
		/* Find the corresponding intermediate hash from the Merkle tree. */
		for (i = 0; i < blocks->treeHeight; i++) {
			if (blocks->notVerified[i] != NULL) break;
		}
		if (i == blocks->treeHeight) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unexpected intermediate hash.", blocks->blockNo);
		}

		if (!KSI_DataHash_equals(blocks->notVerified[i], tmpHash)) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: intermediate hashes not equal.", blocks->blockNo);
		}
		KSI_DataHash_free(blocks->notVerified[i]);
		blocks->notVerified[i] = NULL;
	}
	res = KT_OK;

cleanup:

	print_progressResult(res);
	KSI_DataHash_free(tmpHash);
	KSI_DataHash_free(hash);
	return res;
}

int process_metarecord(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	int d = 0;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlv = NULL;
	size_t metarecord_index = 0;

	if (set == NULL || err == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	d = PARAM_SET_isSetByName(set, "d");
	print_progressDesc(d, "Block no. %3d: processing metarecord... ", blocks->blockNo);

	res = KSI_TlvElement_parse(blocks->ftlv_raw, blocks->ftlv_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse metarecord as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &metarecord_index);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse metarecord index.", blocks->blockNo);

	if (files->inLogFile) {
		/* If the block contains metarecords but not the corresponding record hashes:
		 * Calculate missing metarecord hash from the last metarecord and
		 * build the Merkle tree according to the record count in the signature data. */
		if (blocks->metarecordHash != NULL) {
			/* Add the previous metarecord to Merkle tree. */
			blocks->nofRecordHashes++;
			res = add_hash_to_merkle_tree(ksi, blocks, 1, blocks->metarecordHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to add metarecord hash to Merkle tree.", blocks->blockNo);
		}

		while (blocks->nofRecordHashes < metarecord_index) {
			blocks->nofRecordHashes++;
			res = get_hash_of_logline(ksi, blocks, files, &hash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to calculate hash of logline no. %3d.", blocks->blockNo, blocks->nofRecordHashes);
			res = add_hash_to_merkle_tree(ksi, blocks, 0, hash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to add hash to Merkle tree.", blocks->blockNo);
			KSI_DataHash_free(hash);
			hash = NULL;
		}
	}

	res = get_hash_of_metarecord(ksi, blocks, tlv, &hash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to calculate hash of metarecord with index %3d.", blocks->blockNo, metarecord_index);

	if (files->outSigFile) {
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->outSigFile) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to copy record hash.", blocks->blockNo);
		}
	}

	KSI_DataHash_free(blocks->metarecordHash);
	blocks->metarecordHash = hash;
	hash = NULL;

	res = KT_OK;

cleanup:

	print_progressResult(res);
	KSI_DataHash_free(hash);
	KSI_TlvElement_free(tlv);
	return res;
}

int process_block_signature(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, SIGNATURE_PROCESSORS *processors, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	int d = 0;
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *verificationResult = NULL;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvSig = NULL;
	size_t record_count = 0;

	KSI_VerificationContext_init(&context, ksi);

	if (set == NULL || err == NULL || ksi == NULL || processors == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	d = PARAM_SET_isSetByName(set, "d");
	print_progressDesc(d, "Block no. %3d: processing block signature data... ", blocks->blockNo);

	blocks->sigNo++;
	if (blocks->sigNo > blocks->blockNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: block signature data without preceding block header found.", blocks->sigNo);
	}

	res = KSI_TlvElement_parse(blocks->ftlv_raw, blocks->ftlv_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse block signature as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &record_count);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse record count.", blocks->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x905, &tlvSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse KSI signature.", blocks->blockNo);

	if (tlvSig == NULL) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse KSI signature.", blocks->blockNo);
	}

	if (files->inLogFile) {
		/* If the block contains metarecords but not the corresponding record hashes:
		 * Calculate missing metarecord hash from the last metarecord and
		 * build the Merkle tree according to the record count in the signature data. */
		if (blocks->metarecordHash != NULL) {
			/* Add the previous metarecord to Merkle tree. */
			blocks->nofRecordHashes++;
			res = add_hash_to_merkle_tree(ksi, blocks, 1, blocks->metarecordHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to add metarecord hash to Merkle tree.", blocks->blockNo);
		}
		/* If the block contains neither record hashes nor intermediate hashes:
		 * Calculate missing record hashes from the records in the logfile and
		 * build the Merkle tree according to the record count in the signature data. */
		while (blocks->nofRecordHashes < record_count) {
			blocks->nofRecordHashes++;
			res = get_hash_of_logline(ksi, blocks, files, &hash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to calculate hash of logline no. %3d.", blocks->blockNo, blocks->nofRecordHashes);
			res = add_hash_to_merkle_tree(ksi, blocks, 0, hash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to add hash to Merkle tree.", blocks->blockNo);
			KSI_DataHash_free(hash);
			hash = NULL;
		}
	}

	if (blocks->nofRecordHashes && blocks->nofRecordHashes != record_count) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: expected %d record hashes, but found %d.", blocks->blockNo, record_count, blocks->nofRecordHashes);
	}
	print_progressResult(res);
	print_progressDesc(d, "Block no. %3d: verifying KSI signature... ", blocks->blockNo);

	res = calculate_root_hash(ksi, blocks, &context.documentHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to get root hash for verification.", blocks->blockNo);
	context.docAggrLevel = get_aggregation_level(blocks);

	if (processors->verify_signature) {
		res = KSI_Signature_parseWithPolicy(ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_EMPTY, NULL, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse KSI signature.", blocks->blockNo);

		res = processors->verify_signature(set, err, ksi, sig, context.documentHash, context.docAggrLevel , &verificationResult);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: KSI signature verification failed.", blocks->blockNo);
		/* TODO: add dumping of verification results. */
		KSI_PolicyVerificationResult_free(verificationResult);
		verificationResult = NULL;

	} else if (processors->extend_signature) {
		res = KSI_Signature_parseWithPolicy(ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_INTERNAL, &context, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse KSI signature.", blocks->blockNo);

		print_progressResult(res);
		print_progressDesc(d, "Block no. %3d: extending KSI signature... ", blocks->blockNo);

		res = processors->extend_signature(set, err, ksi, sig, &context, &ext);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to extend KSI signature.", blocks->blockNo);

		res = tlv_element_set_signature(tlv, ksi, 0x905, ext);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to serialize extended KSI signature.", blocks->blockNo);

		res = KSI_TlvElement_serialize(tlv, blocks->ftlv_raw, 0xffff + 4, &blocks->ftlv_len, 0);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to serialize extended block signature.", blocks->blockNo);

		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->outSigFile) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to write extended signature to extended log signature file.", blocks->blockNo);
		}

		KSI_DataHash_free(context.documentHash);
		context.documentHash = NULL;
		KSI_VerificationContext_clean(&context);
	}
	res = KT_OK;

cleanup:

	print_progressResult(res);
	KSI_Signature_free(sig);
	KSI_Signature_free(ext);
	KSI_DataHash_free(context.documentHash);
	KSI_DataHash_free(hash);
	KSI_VerificationContext_clean(&context);
	KSI_PolicyVerificationResult_free(verificationResult);
	KSI_TlvElement_free(tlvSig);
	KSI_TlvElement_free(tlv);
	return res;
}

static int process_partial_block(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	int d = 0;
	KSI_DataHash *hash = NULL;
	KSI_DataHash *rootHash = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvNoSig = NULL;
	size_t record_count = 0;

	if (set == NULL || err == NULL || ksi == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	d = PARAM_SET_isSetByName(set, "d");
	print_progressDesc(d, "Block no. %3d: processing partial block data... ", blocks->blockNo);

	blocks->partNo++;
	if (blocks->partNo > blocks->blockNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: partial block data without preceding block header found.", blocks->sigNo);
	}

	res = KSI_TlvElement_parse(blocks->ftlv_raw, blocks->ftlv_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse block signature as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &record_count);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse record count.", blocks->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x02, &tlvNoSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse missing KSI signature.", blocks->blockNo);

	res = tlv_element_get_hash(tlvNoSig, ksi, 0x01, &hash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse root hash of unsigned block.", blocks->blockNo);

	if (blocks->nofRecordHashes && blocks->nofRecordHashes != record_count) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: expected %d record hashes, but found %d.", blocks->blockNo, record_count, blocks->nofRecordHashes);
	}

	res = calculate_root_hash(ksi, blocks, &rootHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to calculate root hash.", blocks->blockNo);
	if (!KSI_DataHash_equals(hash, rootHash)) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: root hashes not equal.", blocks->blockNo);
	}
	blocks->rootHash = hash;
	hash = NULL;

	res = KT_OK;

cleanup:

	print_progressResult(res);
	KSI_DataHash_free(rootHash);
	KSI_TlvElement_free(tlv);
	KSI_TlvElement_free(tlvNoSig);
	return res;
}

static int process_partial_signature(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, SIGNATURE_PROCESSORS *processors, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	int d = 0;
	KSI_Signature *sig = NULL;
	KSI_DataHash *hash = NULL;
	KSI_DataHash *docHash = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvSig = NULL;
	KSI_TlvElement *tlvNoSig = NULL;
	size_t record_count = 0;

	if (set == NULL || err == NULL || ksi == NULL || processors == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	d = PARAM_SET_isSetByName(set, "d");
	print_progressDesc(d, "Block no. %3d: processing partial signature data... ", blocks->blockNo);

	blocks->sigNo++;
	if (blocks->sigNo > blocks->blockNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: block signature data without preceding block header found.", blocks->sigNo);
	}
	res = KSI_TlvElement_parse(blocks->ftlv_raw, blocks->ftlv_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse block signature as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &record_count);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse record count.", blocks->blockNo);

	if (blocks->nofRecordHashes && blocks->nofRecordHashes != record_count) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: expected %d record hashes, but found %d.", blocks->blockNo, record_count, blocks->nofRecordHashes);
	}

	res = KSI_TlvElement_getElement(tlv, 0x905, &tlvSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse KSI signature.", blocks->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x02, &tlvNoSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse missing KSI signature.", blocks->blockNo);

	if (tlvSig != NULL) {
		res = KSI_Signature_parseWithPolicy(ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_EMPTY, NULL, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse KSI signature.", blocks->blockNo);

		res = KSI_Signature_getDocumentHash(sig, &docHash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to get root hash from KSI signature.", blocks->blockNo);

		if (blocks->rootHash == NULL) {
			res = calculate_root_hash(ksi, blocks, &blocks->rootHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to calculate root hash.", blocks->blockNo);
		}

		if (!KSI_DataHash_equals(docHash, blocks->rootHash)) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: root hashes not equal.", blocks->blockNo);
		}
	} else if (tlvNoSig != NULL) {
		res = tlv_element_get_hash(tlvNoSig, ksi, 0x01, &hash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse root hash.", blocks->blockNo);

		if (blocks->rootHash == NULL) {
			res = calculate_root_hash(ksi, blocks, &blocks->rootHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to calculate root hash.", blocks->blockNo);
		}
		if (!KSI_DataHash_equals(hash, blocks->rootHash)) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: root hashes not equal.", blocks->blockNo);
		}

		if (processors->create_signature) {
			print_progressResult(res);
			print_progressDesc(d, "Block no. %3d: creating missing KSI signature... ", blocks->blockNo);

			res = processors->create_signature(err, ksi, hash, get_aggregation_level(blocks), &sig);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to sign root hash.", blocks->blockNo);

			res = KSI_TlvElement_new(&tlvSig);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to serialize KSI signature.", blocks->blockNo);
			tlvSig->ftlv.tag = 0x904;

			res = tlv_element_set_uint(tlvSig, ksi, 0x01, record_count);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to serialize KSI signature.", blocks->blockNo);

			res = tlv_element_set_signature(tlvSig, ksi, 0x905, sig);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to serialize KSI signature.", blocks->blockNo);

			res = KSI_TlvElement_serialize(tlvSig, blocks->ftlv_raw, 0xffff + 4, &blocks->ftlv_len, 0);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to serialize KSI signature.", blocks->blockNo);
		}
	} else {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse block signature data.", blocks->blockNo);
	}

	if (files->outSigFile) {
		print_progressResult(res);
		print_progressDesc(d, "Block no. %3d: writing KSI signature to file... ", blocks->blockNo);

		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->outSigFile) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to write signature data log signature file.", blocks->blockNo);
		}
	}

	res = KT_OK;

cleanup:

	print_progressResult(res);
	KSI_Signature_free(sig);
	KSI_DataHash_free(hash);
	KSI_TlvElement_free(tlvSig);
	KSI_TlvElement_free(tlvNoSig);
	KSI_TlvElement_free(tlv);
	return res;
}

static int finalize_log_signature(PARAM_SET *set, ERR_TRCKR *err, BLOCK_INFO *blocks) {
	int res;
	int d = 0;

	if (set == NULL || err == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	d = PARAM_SET_isSetByName(set, "d");
	print_progressDesc(d, "Finalizing log signature... ");

	if (blocks->blockNo == 0) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: no blocks found.");
	} else if (blocks->blockNo > blocks->sigNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: block signature data missing.", blocks->blockNo);
	}

	if (blocks->partNo > blocks->sigNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: block signature data missing.", blocks->blockNo);
	}
	res = KT_OK;

cleanup:

	print_progressResult(res);
	return res;
}

static void free_blocks(BLOCK_INFO *blocks) {
	unsigned char i = 0;

	if (blocks) {
		KSI_DataHash_free(blocks->prevLeaf);
		KSI_OctetString_free(blocks->randomSeed);
		while (i < blocks->treeHeight) {
			KSI_DataHash_free(blocks->MerkleTree[i]);
			KSI_DataHash_free(blocks->notVerified[i]);
			i++;
		}
		KSI_DataHash_free(blocks->rootHash);
		KSI_DataHash_free(blocks->metarecordHash);
	}
}

int logsignature_extend(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, EXTENDING_FUNCTION extend_signature, IO_FILES *files) {
	int res;
	BLOCK_INFO blocks;
	unsigned char ftlv_raw[0xffff + 4];
	SIGNATURE_PROCESSORS processors;

	if (set == NULL || err == NULL || ksi == NULL || extend_signature == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	memset(&blocks, 0, sizeof(blocks));
	blocks.ftlv_raw = ftlv_raw;
	processors.verify_signature = NULL;
	processors.extend_signature = extend_signature;

	res = process_magic_number(set, err, &blocks, files);
	if (res != KT_OK) goto cleanup;

	while (!feof(files->inSigFile)) {
		res = KSI_FTLV_fileRead(files->inSigFile, blocks.ftlv_raw, sizeof(ftlv_raw), &blocks.ftlv_len, &blocks.ftlv);
		if (res == KSI_OK) {
			switch (blocks.ftlv.tag) {
				case 0x901:
					res = process_block_header(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x902:
					res = process_record_hash(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x903:
					res = process_intermediate_hash(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x911:
					res = process_metarecord(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x904:
				{
					res = process_block_signature(set, err, ksi, &processors, &blocks, files);
					if (res != KT_OK) goto cleanup;
				}
				break;

				default:
					/* TODO: unknown TLV found. Either
					 * 1) Warn user and skip TLV
					 * 2) Copy TLV (maybe warn user)
					 * 3) Abort extending with an error
					 */
				break;
			}
		} else {
			if (feof(files->inSigFile)) {
				res = KT_OK;
				break;
			} else {
				/* File reading failed. */
				res = KT_IO_ERROR;
				ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to read next TLV.");
			}
		}
	}

	res = finalize_log_signature(set, err, &blocks);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	free_blocks(&blocks);

	return res;
}

int logsignature_verify(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, VERIFYING_FUNCTION verify_signature, IO_FILES *files) {
	int res;
	BLOCK_INFO blocks;
	unsigned char ftlv_raw[0xffff + 4];
	SIGNATURE_PROCESSORS processors;

	if (set == NULL || err == NULL || ksi == NULL || verify_signature == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	memset(&blocks, 0, sizeof(blocks));
	blocks.ftlv_raw = ftlv_raw;
	processors.verify_signature = verify_signature;
	processors.extend_signature = NULL;

	res = process_magic_number(set, err, &blocks, files);
	if (res != KT_OK) goto cleanup;

	while (!feof(files->inSigFile)) {
		res = KSI_FTLV_fileRead(files->inSigFile, blocks.ftlv_raw, sizeof(ftlv_raw), &blocks.ftlv_len, &blocks.ftlv);
		if (res == KSI_OK) {
			switch (blocks.ftlv.tag) {
				case 0x901:
					res = process_block_header(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x902:
					res = process_record_hash(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x903:
					res = process_intermediate_hash(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x911:
					res = process_metarecord(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x904:
				{
					res = process_block_signature(set, err, ksi, &processors, &blocks, files);
					if (res != KT_OK) goto cleanup;
				}
				break;

				default:
					/* TODO: unknown TLV found. Either
					 * 1) Warn user and skip TLV
					 * 2) Copy TLV (maybe warn user)
					 * 3) Abort extending with an error
					 */
				break;
			}
		} else {
			if (feof(files->inSigFile)) {
				res = KT_OK;
				break;
			} else {
				/* File reading failed. */
				res = KT_IO_ERROR;
				ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to read next TLV.");
			}
		}
	}

	res = finalize_log_signature(set, err, &blocks);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	free_blocks(&blocks);

	return res;
}

int logsignature_integrate(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, IO_FILES *files) {
	int res;
	BLOCK_INFO blocks;
	unsigned char ftlv_raw[0xffff + 4];
	SIGNATURE_PROCESSORS processors;

	if (set == NULL || err == NULL || ksi == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	memset(&blocks, 0, sizeof(blocks));
	blocks.ftlv_raw = ftlv_raw;
	processors.create_signature = NULL;

	res = process_magic_number(set, err, &blocks, files);
	if (res != KT_OK) goto cleanup;

	while (!feof(files->inBlockFile)) {
		res = KSI_FTLV_fileRead(files->inBlockFile, blocks.ftlv_raw, sizeof(ftlv_raw), &blocks.ftlv_len, &blocks.ftlv);
		if (res == KSI_OK) {
			switch (blocks.ftlv.tag) {
				case 0x901:
					res = process_block_header(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x902:
					res = process_record_hash(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x903:
					res = process_intermediate_hash(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x911:
					res = process_metarecord(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x904:
				{
					res = process_partial_block(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;

					res = KSI_FTLV_fileRead(files->inSigFile, blocks.ftlv_raw, sizeof(ftlv_raw), &blocks.ftlv_len, &blocks.ftlv);
					if (res != KT_OK) goto cleanup;

					if (blocks.ftlv.tag != 0x904) {
						res = KT_INVALID_INPUT_FORMAT;
						ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unexpected TLV %04X read from block-signatures file.", blocks.blockNo, blocks.ftlv.tag);
					}

					res = process_partial_signature(set, err, ksi, &processors, &blocks, files);
					if (res != KT_OK) goto cleanup;
				}
				break;

				default:
					/* TODO: unknown TLV found. Either
					 * 1) Warn user and skip TLV
					 * 2) Copy TLV (maybe warn user)
					 * 3) Abort extending with an error
					 */
				break;
			}
		} else {
			if (feof(files->inBlockFile)) {
				res = KT_OK;
				break;
			} else {
				/* File reading failed. */
				res = KT_IO_ERROR;
				ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to read next TLV.");
			}
		}
	}

	res = finalize_log_signature(set, err, &blocks);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	free_blocks(&blocks);

	return res;
}

int logsignature_sign(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, IO_FILES *files) {
	int res;
	BLOCK_INFO blocks;
	unsigned char ftlv_raw[0xffff + 4];
	SIGNATURE_PROCESSORS processors;

	if (set == NULL || err == NULL || ksi == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	memset(&blocks, 0, sizeof(blocks));
	blocks.ftlv_raw = ftlv_raw;
	processors.create_signature = KSITOOL_createSignature;

	res = process_magic_number(set, err, &blocks, files);
	if (res != KT_OK) goto cleanup;

	while (!feof(files->inSigFile)) {
		res = KSI_FTLV_fileRead(files->inSigFile, blocks.ftlv_raw, sizeof(ftlv_raw), &blocks.ftlv_len, &blocks.ftlv);
		if (res == KSI_OK) {
			switch (blocks.ftlv.tag) {
				case 0x901:
					res = process_block_header(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x902:
					res = process_record_hash(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x903:
					res = process_intermediate_hash(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x911:
					res = process_metarecord(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x904:
				{
					res = process_partial_signature(set, err, ksi, &processors, &blocks, files);
					if (res != KT_OK) goto cleanup;
				}
				break;

				default:
					/* TODO: unknown TLV found. Either
					 * 1) Warn user and skip TLV
					 * 2) Copy TLV (maybe warn user)
					 * 3) Abort extending with an error
					 */
				break;
			}
		} else {
			if (feof(files->inSigFile)) {
				res = KT_OK;
				break;
			} else {
				/* File reading failed. */
				res = KT_IO_ERROR;
				ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to read next TLV.");
			}
		}
	}

	res = finalize_log_signature(set, err, &blocks);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	free_blocks(&blocks);

	return res;
}

#ifndef _WIN32
int get_file_read_lock(FILE *in) {
	struct flock lock;
	int fres;

	if (in == NULL) return KT_INVALID_ARGUMENT;

	lock.l_type = F_RDLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;
	fres = fcntl(fileno(in), F_SETLKW, &lock);
	if (fres != 0) return KT_IO_ERROR;

	return KT_OK;
}
#else
int get_file_read_lock(FILE *in) {
	if (in == NULL)
		return KT_INVALID_ARGUMENT;
	else
		return KT_OK;
}
#endif
