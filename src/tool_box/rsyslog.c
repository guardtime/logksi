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
#include <stdlib.h>
#include <unistd.h>
#include "param_set/param_set.h"
#include "err_trckr.h"
#include <ksi/ksi.h>
#include "logksi_err.h"
#include "api_wrapper.h"
#include "printer.h"
#include "obj_printer.h"
#include "debug_print.h"
#include <ksi/tlv_element.h>
#include "rsyslog.h"
#include <fcntl.h>
#include <errno.h>

#define SOF_ARRAY(x) (sizeof(x) / sizeof((x)[0]))

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
			/* Accommodate the fixed level bug in LOGSIG11 format. */
			level = 0;
		} else {
			/* Record hashes are concatenated with level = 1 */
			level = 1;
			/* Add the height of the Merkle tree to get the aggregation level. */
			if (blocks->treeHeight != 0) {
				level += blocks->treeHeight;
			} else {
				/* If the Merkle tree was not built, calculate the tree height from the record count. */
				/* height = floor(log2(record_count)) + 1 */
				size_t c = blocks->recordCount;
				while (c) {
					level++;
					c = c / 2;
				}
			}
		}
	}
	return level;
}

int add_leaf_hash_to_merkle_tree(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash *hash) {
	int res;
	unsigned char i = 0;
	KSI_DataHash *right = NULL;
	KSI_DataHash *tmp = NULL;

	if (ksi == NULL || blocks == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	right = KSI_DataHash_ref(hash);

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
	blocks->prevLeaf = KSI_DataHash_ref(hash);
	right = NULL;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(right);
	KSI_DataHash_free(tmp);
	return res;
}

int add_record_hash_to_merkle_tree(KSI_CTX *ksi, BLOCK_INFO *blocks, int isMetaRecordHash, KSI_DataHash *hash) {
	int res;
	KSI_DataHash *lastHash = NULL;

	if (ksi == NULL || blocks == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = calculate_new_leaf_hash(ksi, blocks, hash, isMetaRecordHash, &lastHash);
	if (res != KT_OK) goto cleanup;

	res = add_leaf_hash_to_merkle_tree(ksi, blocks, lastHash);
	if (res != KT_OK) goto cleanup;

cleanup:

	KSI_DataHash_free(lastHash);
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

	if (files->files.log) {
		if (fgets(buf, sizeof(buf), files->files.log) == NULL) {
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

static size_t find_header_in_file(FILE *in, char **headers, size_t len) {
	size_t res = len;
	size_t i;
	size_t count;
	char buf[32];

	if (in == NULL || headers == NULL)
		return len;

	count = fread(buf, 1, strlen(headers[0]), in);
	if (count == strlen(headers[0])) {
		for (i = 0; i < len; i++) {
			if (strncmp(buf, headers[i], strlen(headers[i])) == 0) {
				res = i;
				break;
			}
		}
	}
	return res;
}

static int process_magic_number(ERR_TRCKR *err, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	size_t count = 0;
	char *logSignatureHeaders[] = {"LOGSIG11", "LOGSIG12"};
	char *blocksFileHeaders[] = {"LOG12BLK"};
	char *signaturesFileHeaders[] = {"LOG12SIG"};
	FILE *in = NULL;

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	in = files->files.partsBlk ? files->files.partsBlk : files->files.inSig;
	if (in == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDesc(0, "Processing magic number... ");

	res = KT_INVALID_INPUT_FORMAT;

	if (files->files.partsBlk) {
		if (find_header_in_file(files->files.partsBlk, blocksFileHeaders, SOF_ARRAY(blocksFileHeaders)) == SOF_ARRAY(blocksFileHeaders)) {
			ERR_CATCH_MSG(err, res, "Error: Magic number not found at the beginning of blocks file %s.", files->internal.partsBlk);
		}
		if (find_header_in_file(files->files.partsSig, signaturesFileHeaders, SOF_ARRAY(signaturesFileHeaders)) == SOF_ARRAY(signaturesFileHeaders)) {
			ERR_CATCH_MSG(err, res, "Error: Magic number not found at the beginning of signatures file %s.", files->internal.partsSig);
		}
		blocks->version = LOGSIG12;
	} else {
		blocks->version = find_header_in_file(files->files.inSig, logSignatureHeaders, SOF_ARRAY(logSignatureHeaders));
		if (blocks->version == SOF_ARRAY(logSignatureHeaders)) {
			ERR_CATCH_MSG(err, res, "Error: Magic number not found at the beginning of signature file %s.", files->internal.inSig);
		}
	}

	if (files->files.outSig) {
		count = fwrite(logSignatureHeaders[blocks->version], 1, strlen(logSignatureHeaders[blocks->version]), files->files.outSig);
		if (count != strlen(logSignatureHeaders[blocks->version])) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Could not copy magic number to log signature file.");
		}
	}

	res = KT_OK;

cleanup:

	print_progressResult(res);
	return res;
}

static int process_block_header(ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_OctetString *seed = NULL;
	KSI_DataHash *hash = NULL;
	unsigned char i = 0;
	KSI_TlvElement *tlv = NULL;
	KSI_uint64_t algo;

	if (err == NULL || ksi == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDesc(0, "Block no. %3lu: processing block header... ", blocks->blockNo + 1);

	if (blocks->blockNo > blocks->sigNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: block signature data missing.", blocks->blockNo);
	}
	blocks->blockNo++;
	blocks->recordCount = 0;
	blocks->nofRecordHashes = 0;
	blocks->nofIntermediateHashes = 0;

	res = KSI_TlvElement_parse(blocks->ftlv_raw, blocks->ftlv_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to parse block header as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &algo);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: missing hash algorithm in block header.", blocks->blockNo);

	res = tlv_get_octet_string(tlv, ksi, 0x02, &seed);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: missing random seed in block header.", blocks->blockNo);

	res = tlv_element_get_hash(tlv, ksi, 0x03, &hash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: missing hash of previous leaf in block header.", blocks->blockNo);

	if (blocks->prevLeaf != NULL) {
		if (!KSI_DataHash_equals(blocks->prevLeaf, hash)) {
			OBJPRINT_Hash(blocks->prevLeaf, "Expected hash of previous leaf: ", print_debug);
			OBJPRINT_Hash(hash            , "Received hash of previous leaf: ", print_debug);
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: previous leaf hashes not equal.", blocks->blockNo);
		}
	}

	if (files->files.outSig) {
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->files.outSig) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to copy block header.", blocks->blockNo);
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

static int process_record_hash(ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_DataHash *recordHash = NULL;
	KSI_DataHash *hash = NULL;

	if (err == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDesc(0, "Block no. %3lu: processing record hash... ", blocks->blockNo);

	if (blocks->blockNo == blocks->sigNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: record hash without preceding block header found.", blocks->blockNo + 1);
	}
	blocks->nofRecordHashes++;

	res = KSI_DataHash_fromImprint(ksi, blocks->ftlv_raw + blocks->ftlv.hdr_len, blocks->ftlv.dat_len, &recordHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to create hash of record no. %3lu.", blocks->blockNo, blocks->nofRecordHashes);

	if (blocks->metarecordHash != NULL) {
		/* This is a metarecord hash. */
		if (!KSI_DataHash_equals(blocks->metarecordHash, recordHash)) {
			OBJPRINT_Hash(blocks->metarecordHash, "Expected metarecord hash: ", print_debug);
			OBJPRINT_Hash(recordHash            , "Received metarecord hash: ", print_debug);
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: metarecord hashes not equal.", blocks->blockNo);
		}

		res = add_record_hash_to_merkle_tree(ksi, blocks, 1, blocks->metarecordHash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);

		KSI_DataHash_free(blocks->metarecordHash);
		blocks->metarecordHash = NULL;
	} else {
		/* This is a logline record hash. */
		if (files->files.log) {
			res = get_hash_of_logline(ksi, blocks, files, &hash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to calculate hash of logline no. %3lu.", blocks->blockNo, blocks->nofRecordHashes);

			if (!KSI_DataHash_equals(hash, recordHash)) {
				OBJPRINT_Hash(hash,       "Expected record hash: ", print_debug);
				OBJPRINT_Hash(recordHash, "Received record hash: ", print_debug);
				res = KT_VERIFICATION_FAILURE;
				ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: record hashes not equal.", blocks->blockNo);
			}
		}

		res = add_record_hash_to_merkle_tree(ksi, blocks, 0, recordHash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to add hash to Merkle tree.", blocks->blockNo);
	}

	if (files->files.outSig) {
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->files.outSig) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to copy record hash.", blocks->blockNo);
		}
	}
	res = KT_OK;

cleanup:

	print_progressResult(res);
	KSI_DataHash_free(recordHash);
	KSI_DataHash_free(hash);
	return res;
}

static int process_intermediate_hash(ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_DataHash *tmpHash = NULL;
	KSI_DataHash *hash = NULL;
	unsigned char i;

	if (err == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDesc(0, "Block no. %3lu: processing intermediate hash... ", blocks->blockNo);

	if (blocks->blockNo == blocks->sigNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: intermediate hash without preceding block header found.", blocks->blockNo + 1);
	}
	blocks->nofIntermediateHashes++;

	res = KSI_DataHash_fromImprint(ksi, blocks->ftlv_raw + blocks->ftlv.hdr_len, blocks->ftlv.dat_len, &tmpHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to create intermediate hash.", blocks->blockNo);

	if (files->files.outSig) {
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->files.outSig) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to copy record hash.", blocks->blockNo);
		}
	}

	/* If the block contains intermediate hashes, but not record hashes:
	 * Calculate missing record hashes from the records in the logfile and
	 * build the Merkle tree according to the number of intermediate hashes encountered. */
	if (blocks->nofIntermediateHashes > max_intermediate_records(blocks->nofRecordHashes)) {
		if (files->files.log) {
			blocks->nofRecordHashes++;
			if (blocks->metarecordHash) {
				res = add_record_hash_to_merkle_tree(ksi, blocks, 1, blocks->metarecordHash);
				ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);

				KSI_DataHash_free(blocks->metarecordHash);
				blocks->metarecordHash = NULL;
			} else {
				res = get_hash_of_logline(ksi, blocks, files, &hash);
				ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to calculate hash of logline no. %3lu.", blocks->blockNo, blocks->nofRecordHashes);
				res = add_record_hash_to_merkle_tree(ksi, blocks, 0, hash);
				ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to add record hash to Merkle tree.", blocks->blockNo);
				KSI_DataHash_free(hash);
				hash = NULL;
			}
		} else {
			blocks->nofRecordHashes++;
			res = add_leaf_hash_to_merkle_tree(ksi, blocks, tmpHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to add leaf hash to Merkle tree.", blocks->blockNo);
		}
	}

	if (blocks->nofRecordHashes) {
		/* Find the corresponding intermediate hash from the Merkle tree. */
		for (i = 0; i < blocks->treeHeight; i++) {
			if (blocks->notVerified[i] != NULL) break;
		}
		if (i == blocks->treeHeight) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unexpected intermediate hash.", blocks->blockNo);
		}

		if (!KSI_DataHash_equals(blocks->notVerified[i], tmpHash)) {
			OBJPRINT_Hash(blocks->notVerified[i], "Expected intermediate hash: ", print_debug);
			OBJPRINT_Hash(tmpHash               , "Received intermediate hash: ", print_debug);
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: intermediate hashes not equal.", blocks->blockNo);
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

int process_metarecord(ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_uint64_t metarecord_index = 0;

	if (err == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDesc(0, "Block no. %3lu: processing metarecord... ", blocks->blockNo);

	res = KSI_TlvElement_parse(blocks->ftlv_raw, blocks->ftlv_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to parse metarecord as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &metarecord_index);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: missing metarecord index.", blocks->blockNo);

	if (files->files.log) {
		/* If the block contains metarecords but not the corresponding record hashes:
		 * Calculate missing metarecord hash from the last metarecord and
		 * build the Merkle tree according to the record count in the signature data. */
		if (blocks->metarecordHash != NULL) {
			/* Add the previous metarecord to Merkle tree. */
			blocks->nofRecordHashes++;
			res = add_record_hash_to_merkle_tree(ksi, blocks, 1, blocks->metarecordHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);
		}

		while (blocks->nofRecordHashes < metarecord_index) {
			blocks->nofRecordHashes++;
			res = get_hash_of_logline(ksi, blocks, files, &hash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: missing logline no. %3lu up to metarecord index %3lu.", blocks->blockNo, blocks->nofRecordHashes, metarecord_index);
			res = add_record_hash_to_merkle_tree(ksi, blocks, 0, hash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);
			KSI_DataHash_free(hash);
			hash = NULL;
		}
	}

	res = get_hash_of_metarecord(ksi, blocks, tlv, &hash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to calculate metarecord hash with index %3lu.", blocks->blockNo, metarecord_index);

	if (files->files.outSig) {
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->files.outSig) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to copy metarecord hash.", blocks->blockNo);
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
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *verificationResult = NULL;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvSig = NULL;

	KSI_VerificationContext_init(&context, ksi);

	if (set == NULL || err == NULL || ksi == NULL || processors == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDesc(0, "Block no. %3lu: processing block signature data... ", blocks->blockNo);

	blocks->sigNo++;
	if (blocks->sigNo > blocks->blockNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: block signature data without preceding block header found.", blocks->sigNo);
	}

	res = KSI_TlvElement_parse(blocks->ftlv_raw, blocks->ftlv_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to parse block signature as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &blocks->recordCount);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: missing record count in block signature.", blocks->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x905, &tlvSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to extract KSI signature element in block signature.", blocks->blockNo);

	if (tlvSig == NULL) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: missing KSI signature in block signature.", blocks->blockNo);
	}

	if (files->files.log) {
		/* If the block contains metarecords but not the corresponding record hashes:
		 * Calculate missing metarecord hash from the last metarecord and
		 * build the Merkle tree according to the record count in the signature data. */
		if (blocks->metarecordHash != NULL) {
			/* Add the previous metarecord to Merkle tree. */
			blocks->nofRecordHashes++;
			res = add_record_hash_to_merkle_tree(ksi, blocks, 1, blocks->metarecordHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);
		}
		/* If the block contains neither record hashes nor intermediate hashes:
		 * Calculate missing record hashes from the records in the logfile and
		 * build the Merkle tree according to the record count in the signature data. */
		while (blocks->nofRecordHashes < blocks->recordCount) {
			blocks->nofRecordHashes++;
			res = get_hash_of_logline(ksi, blocks, files, &hash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to calculate hash of logline no. %3lu.", blocks->blockNo, blocks->nofRecordHashes);
			res = add_record_hash_to_merkle_tree(ksi, blocks, 0, hash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to add hash to Merkle tree.", blocks->blockNo);
			KSI_DataHash_free(hash);
			hash = NULL;
		}
	}

	if (blocks->nofRecordHashes && blocks->nofRecordHashes != blocks->recordCount) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: expected %lu record hashes, but found %lu.", blocks->blockNo, blocks->recordCount, blocks->nofRecordHashes);
	}
	print_progressResult(res);
	print_progressDesc(1, "Block no. %3lu: verifying KSI signature... ", blocks->blockNo);

	res = calculate_root_hash(ksi, blocks, (KSI_DataHash**)&context.documentHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to get root hash for verification.", blocks->blockNo);

	if (processors->verify_signature) {
		res = KSI_Signature_parseWithPolicy(ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_EMPTY, NULL, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to parse KSI signature.", blocks->blockNo);

		res = processors->verify_signature(set, err, ksi, sig, (KSI_DataHash*)context.documentHash, &verificationResult);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: KSI signature verification failed.", blocks->blockNo);
		/* TODO: add dumping of verification results. */
		KSI_PolicyVerificationResult_free(verificationResult);
		verificationResult = NULL;

	} else if (processors->extend_signature) {
		res = KSI_Signature_parseWithPolicy(ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_INTERNAL, &context, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to parse KSI signature.", blocks->blockNo);

		print_progressResult(res);
		print_progressDesc(1, "Block no. %3lu: extending KSI signature... ", blocks->blockNo);

		res = processors->extend_signature(set, err, ksi, sig, &context, &ext);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to extend KSI signature.", blocks->blockNo);

		res = tlv_element_set_signature(tlv, ksi, 0x905, ext);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to serialize extended KSI signature.", blocks->blockNo);

		res = KSI_TlvElement_serialize(tlv, blocks->ftlv_raw, SOF_FTLV_BUFFER, &blocks->ftlv_len, 0);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to serialize extended block signature.", blocks->blockNo);

		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->files.outSig) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to write extended signature to extended log signature file.", blocks->blockNo);
		}

		KSI_DataHash_free((KSI_DataHash*)context.documentHash);
		context.documentHash = NULL;
		KSI_VerificationContext_clean(&context);
	}
	res = KT_OK;

cleanup:

	print_progressResult(res);
	KSI_Signature_free(sig);
	KSI_Signature_free(ext);
	KSI_DataHash_free((KSI_DataHash*)context.documentHash);
	KSI_DataHash_free(hash);
	KSI_VerificationContext_clean(&context);
	KSI_PolicyVerificationResult_free(verificationResult);
	KSI_TlvElement_free(tlvSig);
	KSI_TlvElement_free(tlv);
	return res;
}

static int process_partial_block(ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_DataHash *hash = NULL;
	KSI_DataHash *rootHash = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvNoSig = NULL;

	if (err == NULL || ksi == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDesc(0, "Block no. %3lu: processing partial block data... ", blocks->blockNo);

	blocks->partNo++;
	if (blocks->partNo > blocks->blockNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: partial block data without preceding block header found.", blocks->sigNo);
	}

	res = KSI_TlvElement_parse(blocks->ftlv_raw, blocks->ftlv_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to parse block signature as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &blocks->recordCount);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: missing record count in blocks file.", blocks->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x02, &tlvNoSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to extract 'no-sig' element in blocks file.", blocks->blockNo);

	res = tlv_element_get_hash(tlvNoSig, ksi, 0x01, &hash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: missing root hash in blocks file.", blocks->blockNo);

	if (blocks->nofRecordHashes && blocks->nofRecordHashes != blocks->recordCount) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: expected %lu records in blocks file, but found %lu records.", blocks->blockNo, blocks->recordCount, blocks->nofRecordHashes);
	}

	/* If the blocks file contains hashes, re-compute and compare the root hash against the provided root hash. */
	if (blocks->nofRecordHashes) {
		res = calculate_root_hash(ksi, blocks, &rootHash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to calculate root hash.", blocks->blockNo);
		if (!KSI_DataHash_equals(rootHash, hash)) {
			OBJPRINT_Hash(rootHash, "Expected root hash: ", print_debug);
			OBJPRINT_Hash(hash,     "Received root hash: ", print_debug);
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: root hashes not equal.", blocks->blockNo);
		}
		blocks->rootHash = hash;
		hash = NULL;
	}

	res = KT_OK;

cleanup:

	print_progressResult(res);
	KSI_DataHash_free(rootHash);
	KSI_DataHash_free(hash);
	KSI_TlvElement_free(tlv);
	KSI_TlvElement_free(tlvNoSig);
	return res;
}

static int process_partial_signature(ERR_TRCKR *err, KSI_CTX *ksi, SIGNATURE_PROCESSORS *processors, BLOCK_INFO *blocks, IO_FILES *files, int progress) {
	int res;
	KSI_Signature *sig = NULL;
	KSI_DataHash *hash = NULL;
	KSI_DataHash *docHash = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvSig = NULL;
	KSI_TlvElement *tlvNoSig = NULL;

	if (err == NULL || ksi == NULL || processors == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDesc(0, "Block no. %3lu: processing partial signature data... ", blocks->blockNo);

	blocks->sigNo++;
	if (blocks->sigNo > blocks->blockNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: block signature data without preceding block header found.", blocks->sigNo);
	}
	res = KSI_TlvElement_parse(blocks->ftlv_raw, blocks->ftlv_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to parse block signature as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &blocks->recordCount);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: missing record count in signatures file.", blocks->blockNo);

	if (blocks->nofRecordHashes && blocks->nofRecordHashes != blocks->recordCount) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: expected %lu records in signatures file, but found %lu records in blocks file.", blocks->blockNo, blocks->recordCount, blocks->nofRecordHashes);
	}

	res = KSI_TlvElement_getElement(tlv, 0x905, &tlvSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to extract KSI signature element in signatures file.", blocks->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x02, &tlvNoSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to extract 'no-sig' element in signatures file.", blocks->blockNo);

	if (tlvSig != NULL) {
		res = KSI_Signature_parseWithPolicy(ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_EMPTY, NULL, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to parse KSI signature in signatures file.", blocks->blockNo);

		res = KSI_Signature_getDocumentHash(sig, &docHash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to get root hash from KSI signature.", blocks->blockNo);

		/* If the blocks file contains hashes, re-compute and compare the root hash against the provided root hash. */
		if (blocks->nofRecordHashes) {
			if (blocks->rootHash == NULL) {
				res = calculate_root_hash(ksi, blocks, &blocks->rootHash);
				ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to calculate root hash.", blocks->blockNo);
			}

			if (!KSI_DataHash_equals(blocks->rootHash, docHash)) {
				OBJPRINT_Hash(blocks->rootHash, "Expected root hash: ", print_debug);
				OBJPRINT_Hash(docHash,          "Received root hash: ", print_debug);
				res = KT_VERIFICATION_FAILURE;
				ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: root hashes not equal.", blocks->blockNo);
			}
		} else {
			KSI_DataHash_free(blocks->prevLeaf);
			blocks->prevLeaf = NULL;
		}
	} else if (tlvNoSig != NULL) {
		blocks->noSigNo++;
		res = tlv_element_get_hash(tlvNoSig, ksi, 0x01, &hash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to parse root hash.", blocks->blockNo);

		if (blocks->rootHash == NULL) {
			res = calculate_root_hash(ksi, blocks, &blocks->rootHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to calculate root hash.", blocks->blockNo);
		}
		if (!KSI_DataHash_equals(hash, blocks->rootHash)) {
			OBJPRINT_Hash(blocks->rootHash, "Expected root hash: ", print_debug);
			OBJPRINT_Hash(hash,             "Received root hash: ", print_debug);
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: root hashes not equal.", blocks->blockNo);
		}

		if (processors->create_signature) {
			print_progressResult(res);
			if (progress) {
				print_debug("Progress: signing block %3lu of %3lu unsigned blocks. Estimated time remaining: %3lu seconds.\n", blocks->noSigNo, blocks->noSigCount, blocks->noSigCount - blocks->noSigNo + 1);
			}
			print_progressDesc(1, "Block no. %3lu: creating missing KSI signature... ", blocks->blockNo);

			res = processors->create_signature(err, ksi, hash, get_aggregation_level(blocks), &sig);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to sign root hash.", blocks->blockNo);

			res = KSI_TlvElement_new(&tlvSig);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to serialize KSI signature.", blocks->blockNo);
			tlvSig->ftlv.tag = 0x904;

			res = tlv_element_set_uint(tlvSig, ksi, 0x01, blocks->recordCount);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to serialize KSI signature.", blocks->blockNo);

			res = tlv_element_set_signature(tlvSig, ksi, 0x905, sig);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to serialize KSI signature.", blocks->blockNo);

			res = KSI_TlvElement_serialize(tlvSig, blocks->ftlv_raw, SOF_FTLV_BUFFER, &blocks->ftlv_len, 0);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to serialize KSI signature.", blocks->blockNo);
		}
	} else {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: block signature missing in signatures file.", blocks->blockNo);
	}

	if (files->files.outSig) {
		print_progressResult(res);
		print_progressDesc(0, "Block no. %3lu: writing KSI signature to file... ", blocks->blockNo);

		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->files.outSig) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to write signature data log signature file.", blocks->blockNo);
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

static int finalize_log_signature(ERR_TRCKR *err, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	char buf[2];

	if (err == NULL || blocks == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDesc(0, "Finalizing log signature... ");

	if (blocks->blockNo == 0) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: no blocks found.");
	} else if (blocks->blockNo > blocks->sigNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: block signature data missing.", blocks->blockNo);
	}

	if (blocks->partNo > blocks->sigNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: block signature data missing.", blocks->blockNo);
	}

	/* Log file must not contain more records than log signature file. */
	if (files->files.log) {
		if (fread(buf, 1, 1, files->files.log) > 0) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: end of log file contains unexpected records.", blocks->blockNo);
		}
	}

	/* Signatures file must not contain more blocks than blocks file. */
	if (files->files.partsSig) {
		if (fread(buf, 1, 1, files->files.partsSig) > 0) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: end of signatures file contains unexpected data.", blocks->blockNo);
		}
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

int count_blocks(ERR_TRCKR *err, BLOCK_INFO *blocks, FILE *in) {
	int res;
	long int pos = -1;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvNoSig = NULL;

	if (err == NULL || in == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Do not count records, if input comes from stdin. */
	if (in == stdin) {
		res = KT_OK;
		goto cleanup;
	}

	blocks->blockCount = 0;
	blocks->noSigCount = 0;
	blocks->noSigNo = 0;
	pos = ftell(in);
	if (pos == -1) {
		res = KT_IO_ERROR;
		ERR_CATCH_MSG(err, res, "Error: unable to get file handle position.");
	}

	while (!feof(in)) {
		res = KSI_FTLV_fileRead(in, blocks->ftlv_raw, SOF_FTLV_BUFFER, &blocks->ftlv_len, &blocks->ftlv);
		if (res == KSI_OK) {
			switch (blocks->ftlv.tag) {
				case 0x901:
					blocks->blockCount++;
				break;

				case 0x904:
					res = KSI_TlvElement_parse(blocks->ftlv_raw, blocks->ftlv_len, &tlv);
					ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to parse block signature as TLV element.", blocks->blockNo);
					res = KSI_TlvElement_getElement(tlv, 0x02, &tlvNoSig);
					ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unable to extract 'no-sig' element in signatures file.", blocks->blockNo);

					if (tlvNoSig) blocks->noSigCount++;

					KSI_TlvElement_free(tlvNoSig);
					tlvNoSig = NULL;
					KSI_TlvElement_free(tlv);
					tlv = NULL;
				break;

				default:
				/* Ignore hashes and other TLVs as we are just counting blocks. */
				break;
			}
		} else {
			if (blocks->ftlv_len > 0) {
				res = KT_INVALID_INPUT_FORMAT;
				ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: incomplete data found in log signature file.", blocks->blockNo);
			} else {
				break;
			}
		}
	}

	res = KT_OK;

cleanup:

	/* Rewind input stream. */
	if (pos != -1) {
		if (fseek(in, pos, SEEK_SET) != 0) {
			if (res == KT_OK) {
				res = KT_IO_ERROR;
				if (err) ERR_TRCKR_ADD(err, res, "Error: could not rewind input stream.");
			}
		}
	}
	KSI_TlvElement_free(tlvNoSig);
	KSI_TlvElement_free(tlv);

	return res;
}

int logsignature_extend(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, EXTENDING_FUNCTION extend_signature, IO_FILES *files) {
	int res;
	BLOCK_INFO blocks;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;

	if (set == NULL || err == NULL || ksi == NULL || extend_signature == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	memset(&blocks, 0, sizeof(blocks));
	blocks.ftlv_raw = ftlv_raw;
	processors.verify_signature = NULL;
	processors.extend_signature = extend_signature;

	res = process_magic_number(err, &blocks, files);
	if (res != KT_OK) goto cleanup;

	while (!feof(files->files.inSig)) {
		res = KSI_FTLV_fileRead(files->files.inSig, blocks.ftlv_raw, SOF_FTLV_BUFFER, &blocks.ftlv_len, &blocks.ftlv);
		if (res == KSI_OK) {
			switch (blocks.ftlv.tag) {
				case 0x901:
					res = process_block_header(err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x902:
					res = process_record_hash(err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x903:
					res = process_intermediate_hash(err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x911:
					res = process_metarecord(err, ksi, &blocks, files);
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
			if (blocks.ftlv_len > 0) {
				res = KT_INVALID_INPUT_FORMAT;
				ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: incomplete data found in log signature file.", blocks.blockNo);
			} else {
				break;
			}
		}
	}

	res = finalize_log_signature(err, &blocks, files);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	free_blocks(&blocks);

	return res;
}

int logsignature_verify(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, VERIFYING_FUNCTION verify_signature, IO_FILES *files) {
	int res;
	BLOCK_INFO blocks;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;

	if (set == NULL || err == NULL || ksi == NULL || verify_signature == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	memset(&blocks, 0, sizeof(blocks));
	blocks.ftlv_raw = ftlv_raw;
	processors.verify_signature = verify_signature;
	processors.extend_signature = NULL;

	res = process_magic_number(err, &blocks, files);
	if (res != KT_OK) goto cleanup;

	while (!feof(files->files.inSig)) {
		res = KSI_FTLV_fileRead(files->files.inSig, blocks.ftlv_raw, SOF_FTLV_BUFFER, &blocks.ftlv_len, &blocks.ftlv);
		if (res == KSI_OK) {
			switch (blocks.ftlv.tag) {
				case 0x901:
					res = process_block_header(err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x902:
					res = process_record_hash(err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x903:
					res = process_intermediate_hash(err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x911:
					res = process_metarecord(err, ksi, &blocks, files);
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
			if (blocks.ftlv_len > 0) {
				res = KT_INVALID_INPUT_FORMAT;
				ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: incomplete data found in log signature file.", blocks.blockNo);
			} else {
				break;
			}
		}
	}

	res = finalize_log_signature(err, &blocks, files);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	free_blocks(&blocks);

	return res;
}

int logsignature_integrate(ERR_TRCKR *err, KSI_CTX *ksi, IO_FILES *files) {
	int res;
	BLOCK_INFO blocks;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;

	if (err == NULL || ksi == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	memset(&blocks, 0, sizeof(blocks));
	blocks.ftlv_raw = ftlv_raw;
	processors.create_signature = NULL;

	res = process_magic_number(err, &blocks, files);
	if (res != KT_OK) goto cleanup;

	while (!feof(files->files.partsBlk)) {
		res = KSI_FTLV_fileRead(files->files.partsBlk, blocks.ftlv_raw, SOF_FTLV_BUFFER, &blocks.ftlv_len, &blocks.ftlv);
		if (res == KSI_OK) {
			switch (blocks.ftlv.tag) {
				case 0x901:
					res = process_block_header(err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x902:
					res = process_record_hash(err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x903:
					res = process_intermediate_hash(err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x911:
					res = process_metarecord(err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x904:
				{
					res = process_partial_block(err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;

					res = KSI_FTLV_fileRead(files->files.partsSig, blocks.ftlv_raw, SOF_FTLV_BUFFER, &blocks.ftlv_len, &blocks.ftlv);
					if (res != KT_OK) {
						if (blocks.ftlv_len > 0) {
							res = KT_INVALID_INPUT_FORMAT;
							ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: incomplete data found in signatures file.", blocks.blockNo);
						} else {
							res = KT_VERIFICATION_FAILURE;
							ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unexpected end of signatures file.", blocks.blockNo);
						}
					}
					if (blocks.ftlv.tag != 0x904) {
						res = KT_INVALID_INPUT_FORMAT;
						ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: unexpected TLV %04X read from block-signatures file.", blocks.blockNo, blocks.ftlv.tag);
					}

					res = process_partial_signature(err, ksi, &processors, &blocks, files, 0);
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
			if (blocks.ftlv_len > 0) {
				res = KT_INVALID_INPUT_FORMAT;
				ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: incomplete data found in blocks file.", blocks.blockNo);
			} else {
				break;
			}
		}
	}

	res = finalize_log_signature(err, &blocks, files);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	free_blocks(&blocks);

	return res;
}

int logsignature_sign(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, IO_FILES *files) {
	int res;
	int progress;
	BLOCK_INFO blocks;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;

	if (set == NULL || err == NULL || ksi == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	memset(&blocks, 0, sizeof(blocks));
	blocks.ftlv_raw = ftlv_raw;
	processors.create_signature = LOGKSI_createSignature;

	res = process_magic_number(err, &blocks, files);
	if (res != KT_OK) goto cleanup;

	if (files->files.inSig != stdin) {
		progress = (PARAM_SET_isSetByName(set, "d")&& PARAM_SET_isSetByName(set, "show-progress"));
	} else {
		/* Impossible to estimate signing progress if input is from stdin. */
		progress = 0;
	}

	if (progress) {
		res = count_blocks(err, &blocks, files->files.inSig);
		if (res != KT_OK) goto cleanup;
		print_debug("Progress: %3lu of %3lu blocks need signing. Estimated signing time: %3lu seconds.\n", blocks.noSigCount, blocks.blockCount, blocks.noSigCount);
	}

	while (!feof(files->files.inSig)) {
		res = KSI_FTLV_fileRead(files->files.inSig, blocks.ftlv_raw, SOF_FTLV_BUFFER, &blocks.ftlv_len, &blocks.ftlv);
		if (res == KSI_OK) {
			switch (blocks.ftlv.tag) {
				case 0x901:
					res = process_block_header(err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x902:
					res = process_record_hash(err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x903:
					res = process_intermediate_hash(err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x911:
					res = process_metarecord(err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x904:
				{
					res = process_partial_signature(err, ksi, &processors, &blocks, files, progress);
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
			if (blocks.ftlv_len > 0) {
				res = KT_INVALID_INPUT_FORMAT;
				ERR_CATCH_MSG(err, res, "Error: Block no. %3lu: incomplete data found in log signature file.", blocks.blockNo);
			} else {
				break;
			}
		}
	}

	res = finalize_log_signature(err, &blocks, files);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	free_blocks(&blocks);

	return res;
}

int get_file_read_lock(FILE *in) {
	struct flock lock;
	int fres;

	if (in == NULL) return KT_INVALID_ARGUMENT;

	lock.l_type = F_RDLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;
	fres = fcntl(fileno(in), F_SETLK, &lock);
	if (fres != 0) {
		if (errno == EAGAIN || errno == EACCES) {
			print_progressDesc(1, "Waiting to acquire read lock... ");
			fres = fcntl(fileno(in), F_SETLKW, &lock);
			print_progressResult(fres);
		}
	}

	if (fres != 0) {
		return KT_IO_ERROR;
	} else {
		return KT_OK;
	}
}

int concat_names(char *org, const char *extension, char **derived) {
	int res;
	char *buf = NULL;

	if (org == NULL || extension == NULL || derived == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}
	buf = (char*)KSI_malloc(strlen(org) + strlen(extension) + 1);
	if (buf == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}
	sprintf(buf, "%s%s", org, extension);
	*derived = buf;
	res = KT_OK;

cleanup:

	return res;
}

int temp_name(char *org, char **derived) {
	int res;
	int fd = -1;
	char *tmp = NULL;

	if (org == NULL || derived == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = concat_names(org, "XXXXXX", &tmp);
	if (res != KT_OK) goto cleanup;

	fd = mkstemp(tmp);
	if (fd == -1) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	*derived = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	close(fd);
	KSI_free(tmp);
	return res;
}

void logksi_filename_free(char **ptr) {
	if (ptr != NULL && *ptr != NULL) {
		KSI_free(*ptr);
		*ptr = NULL;
	}
}

void logksi_internal_filenames_free(INTERNAL_FILE_NAMES *internal) {
	if (internal != NULL) {
		logksi_filename_free(&internal->log);
		logksi_filename_free(&internal->inSig);
		logksi_filename_free(&internal->outSig);
		logksi_filename_free(&internal->tempSig);
		logksi_filename_free(&internal->backupSig);
		logksi_filename_free(&internal->partsBlk);
		logksi_filename_free(&internal->partsSig);
	}
}

void logksi_file_close(FILE **ptr) {
	if (ptr != NULL && *ptr != NULL) {
		fclose(*ptr);
		*ptr = NULL;
	}
}

void logksi_files_close(INTERNAL_FILE_HANDLES *files) {
	if (files != NULL) {
		logksi_file_close(&files->log);
		if (files->inSig == stdin) files->inSig = NULL;
		logksi_file_close(&files->inSig);
		if (files->outSig == stdout) files->outSig = NULL;
		logksi_file_close(&files->outSig);
		logksi_file_close(&files->partsBlk);
		logksi_file_close(&files->partsSig);
	}
}

int logksi_remove_file(char *name) {
	int res;
	if (name == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (unlink(name) != 0) {
		if (errno != ENOENT) {
			res = KT_IO_ERROR;
			goto cleanup;
		}
	}

	res = KT_OK;

cleanup:

	return res;
}
