/*
 * Copyright 2013-2017 Guardtime, Inc.
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
#include "tool_box/param_control.h"
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
#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>

#define SOF_ARRAY(x) (sizeof(x) / sizeof((x)[0]))

int calculate_new_tree_hash(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash *leftHash, KSI_DataHash *rightHash, unsigned char level, KSI_DataHash **nodeHash) {
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

int calculate_new_leaf_hash(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash *recordHash, int isMetaRecordHash, KSI_DataHash **leafHash) {
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

	KSI_DataHash_free(blocks->extractMask);
	blocks->extractMask = KSI_DataHash_ref(mask);

	if (isMetaRecordHash) {
		res = calculate_new_tree_hash(ksi, blocks, recordHash, mask, 1, &tmp);
		if (res != KT_OK) goto cleanup;
	} else {
		res = calculate_new_tree_hash(ksi, blocks, mask, recordHash, 1, &tmp);
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

int add_hash_to_record_chain(EXTRACT_INFO *extracts, LINK_DIRECTION dir, KSI_DataHash *hash, int corr) {
	int res;

	if (extracts == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	extracts->extractChain[extracts->extractLevel].dir = dir;
	extracts->extractChain[extracts->extractLevel].corr = corr;
	extracts->extractChain[extracts->extractLevel].sibling = KSI_DataHash_ref(hash);
	extracts->extractLevel = extracts->extractLevel + corr + 1;

	res = KT_OK;

cleanup:

	return res;
}

int update_record_chain(BLOCK_INFO *blocks, unsigned char level, int finalize, KSI_DataHash *leftLink) {
	int res;
	size_t j;
	int condition;

	if (blocks == NULL || leftLink == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	for (j = 0; j < blocks->nofExtractPositionsInBlock; j++) {
		if (blocks->extractInfo[j].extractOffset <= blocks->nofRecordHashes) {
			if (finalize) {
				condition = (level + 1 >= blocks->extractInfo[j].extractLevel);
			} else {
				condition = (level + 1 == blocks->extractInfo[j].extractLevel);
			}
			if (condition) {
				if (((blocks->extractInfo[j].extractOffset - 1) >> level) & 1L) {
					res = add_hash_to_record_chain(blocks->extractInfo + j, RIGHT_LINK, blocks->MerkleTree[level], level + 1 - blocks->extractInfo[j].extractLevel);
				} else {
					res = add_hash_to_record_chain(blocks->extractInfo + j, LEFT_LINK, leftLink, level + 1 - blocks->extractInfo[j].extractLevel);
				}
				if (res != KT_OK) goto cleanup;
			}
		}
	}

	res = KT_OK;

cleanup:

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
				res = calculate_new_tree_hash(ksi, blocks, blocks->MerkleTree[i], root, i + 2, &tmp);
				if (res != KT_OK) goto cleanup;

				res = update_record_chain(blocks, i, 1, root);
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
			/* To be backward compatible with a bug in LOGSIG11 implementation of rsyslog-ksi,
			 * we must sign tree hashes with level 0 regardless of the tree height. */
			level = 0;
		} else if (blocks->recordCount){
			/* LOGSIG12 implementation:
			 * Calculate the aggregation level from the number of records in the block (tree).
			 * Level is log2 dependent on the number of records,
			 * and is the same for all perfect and smaller trees.
			 * E.g. level = 4 for 5.. 8 records
			 *      level = 5 for 9..16 records etc.
			 * Level for the single node tree that uses blinding masks is 1. */
			level = 1;
			size_t c = blocks->recordCount - 1;
			while (c) {
				level++;
				c = c / 2;
			}
		}
		/* If there are no records in the block, the aggregation level is 0,
		 * as if we are signing a record hash directly. */
	}
	return level;
}

int expand_extract_info(BLOCK_INFO *blocks) {
	int res;
	EXTRACT_INFO *tmp = NULL;

	if (blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}
	if (blocks->extractInfo == NULL) {
		tmp = (EXTRACT_INFO*)malloc(sizeof(EXTRACT_INFO));
	} else {
		tmp = (EXTRACT_INFO*)realloc(blocks->extractInfo, sizeof(EXTRACT_INFO) * (blocks->nofExtractPositionsInBlock + 1));
	}

	if (tmp == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	blocks->extractInfo = tmp;
	tmp = NULL;
	memset(blocks->extractInfo + blocks->nofExtractPositionsInBlock, 0, sizeof(EXTRACT_INFO));
	blocks->nofExtractPositionsInBlock++;
	res = KT_OK;

cleanup:

	free(tmp);
	return res;
}

int update_extract_info(BLOCK_INFO *blocks, int isMetaRecordHash, KSI_DataHash *hash) {
	int res;
	EXTRACT_INFO *extractInfo = NULL;

	if (blocks == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (blocks->nofExtractPositionsFound < blocks->nofExtractPositions && blocks->extractPositions[blocks->nofExtractPositionsFound] - blocks->nofTotalRecordHashes == blocks->nofRecordHashes) {
		/* make room in extractInfo */
		res = expand_extract_info(blocks);
		if (res != KT_OK) goto cleanup;

		extractInfo = &blocks->extractInfo[blocks->nofExtractPositionsInBlock - 1];

		extractInfo->extractPos = blocks->extractPositions[blocks->nofExtractPositionsFound];
		extractInfo->extractOffset = blocks->extractPositions[blocks->nofExtractPositionsFound] - blocks->nofTotalRecordHashes;
		extractInfo->extractRecord = KSI_DataHash_ref(hash);
		if (!isMetaRecordHash) {
			extractInfo->metaRecord = NULL;
			extractInfo->logLine = strdup(blocks->logLine);
			if (extractInfo->logLine == NULL) {
				res = KT_OUT_OF_MEMORY;
				goto cleanup;
			}
		} else {
			extractInfo->logLine = NULL;
			res = KSI_TlvElement_parse(blocks->metaRecord, 0xffff, &extractInfo->metaRecord);
			if (res != KT_OK) goto cleanup;
		}
		blocks->nofExtractPositionsFound++;

		if (isMetaRecordHash) {
			res = add_hash_to_record_chain(extractInfo, LEFT_LINK, blocks->extractMask, 0);
		} else {
			res = add_hash_to_record_chain(extractInfo, RIGHT_LINK, blocks->extractMask, 0);
		}
		if (res != KT_OK) goto cleanup;

	}

	res = KT_OK;

cleanup:

	return res;
}


int add_leaf_hash_to_merkle_tree(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash *hash, int isMetaRecordHash) {
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
		res = calculate_new_tree_hash(ksi, blocks, blocks->MerkleTree[i], right, i + 2, &tmp);
		if (res != KT_OK) goto cleanup;

		res = update_record_chain(blocks, i, 0, right);
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

	res = update_extract_info(blocks, isMetaRecordHash, hash);
	if (res != KT_OK) goto cleanup;

	res = add_leaf_hash_to_merkle_tree(ksi, blocks, lastHash, isMetaRecordHash);
	if (res != KT_OK) goto cleanup;

cleanup:

	KSI_DataHash_free(lastHash);
	return res;
}

int store_logline(BLOCK_INFO *blocks, char *buf) {
	int res;
	char *tmp = NULL;

	if (blocks == NULL || buf == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = (char*)malloc(strlen(buf) + 1);
	if (tmp == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	strncpy(tmp, buf, strlen(buf) + 1);
	free(blocks->logLine);
	blocks->logLine = tmp;
	tmp = NULL;

	res = KT_OK;

cleanup:

	free(tmp);
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

	if (files->files.inLog) {
		if (fgets(buf, sizeof(buf), files->files.inLog) == NULL) {
			res = KT_IO_ERROR;
			goto cleanup;
		}
		/* Last character (newline) is not used in hash calculation. */
		res = KSI_DataHash_create(ksi, buf, strlen(buf) - 1, blocks->hashAlgo, &tmp);
		if (res != KSI_OK) goto cleanup;

		/* Store logline for extraction. */
		res = store_logline(blocks, buf);
		if (res != KT_OK) goto cleanup;
	}
	*hash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(tmp);
	return res;
}

int store_metarecord(BLOCK_INFO *blocks, KSI_TlvElement *tlv) {
	int res;
	size_t len = 0;
	unsigned char *buf = NULL;

	if (blocks == NULL || tlv == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_TlvElement_serialize(tlv, NULL, 0, &len, 0);
	if (res != KSI_OK) goto cleanup;

	buf = (unsigned char*)malloc(len);
	if (buf == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	res = KSI_TlvElement_serialize(tlv, buf, len, &len, 0);
	if (res != KSI_OK) goto cleanup;

	free(blocks->metaRecord);
	blocks->metaRecord = buf;
	buf = NULL;

	res = KT_OK;

cleanup:

	free(buf);
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

	/* Store metarecord for extraction. */
	res = store_metarecord(blocks, tlv);
	if (res != KT_OK) goto cleanup;

	*hash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(tmp);
	return res;
}

static size_t max_tree_hashes(size_t nof_records) {
	size_t max = 0;
	while (nof_records) {
		max = max + nof_records;
		nof_records = nof_records / 2;
	}
	return max;
}

int tlv_element_get_uint(KSI_TlvElement *tlv, KSI_CTX *ksi, unsigned tag, size_t *out) {
	int res;
	KSI_Integer *tmp = NULL;

	res = KSI_TlvElement_getInteger(tlv, ksi, tag, &tmp);
	if (res != KSI_OK) goto cleanup;
	if (tmp == NULL) {
		res = KT_INVALID_INPUT_FORMAT;
		goto cleanup;
	}

	*out = (size_t)KSI_Integer_getUInt64(tmp);
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

int tlv_element_set_hash(KSI_TlvElement *tlv, KSI_CTX *ksi, unsigned tag, KSI_DataHash *hash) {
	int res;
	KSI_OctetString *tmp = NULL;
	const unsigned char *buf = NULL;
	size_t len = 0;

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
	char *logSignatureHeaders[] = {"LOGSIG11", "LOGSIG12", "RECSIG11", "RECSIG12"};
	char *blocksFileHeaders[] = {"LOG12BLK"};
	char *signaturesFileHeaders[] = {"LOG12SIG"};
	char *proofFileHeaders[] = {"RECSIG11", "RECSIG12"};
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
	} else if (files->files.outProof) {
		count = fwrite(proofFileHeaders[blocks->version], 1, strlen(proofFileHeaders[blocks->version]), files->files.outProof);
		if (count != strlen(proofFileHeaders[blocks->version])) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Could not write magic number to integrity proof file.");
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
	size_t algo;
	size_t j;

	if (err == NULL || ksi == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDesc(0, "Block no. %3zu: processing block header... ", blocks->blockNo + 1);

	if (blocks->blockNo > blocks->sigNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: block signature data missing.", blocks->blockNo);
	}
	blocks->blockNo++;
	blocks->recordCount = 0;
	blocks->nofRecordHashes = 0;
	blocks->nofTreeHashes = 0;
	blocks->finalTreeHashesSome = 0;
	blocks->finalTreeHashesNone = 0;
	blocks->finalTreeHashesAll = 0;

	res = KSI_TlvElement_parse(blocks->ftlv_raw, blocks->ftlv_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to parse block header as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &algo);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: missing hash algorithm in block header.", blocks->blockNo);

	res = tlv_get_octet_string(tlv, ksi, 0x02, &seed);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: missing random seed in block header.", blocks->blockNo);

	res = tlv_element_get_hash(tlv, ksi, 0x03, &hash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: missing hash of previous leaf in block header.", blocks->blockNo);

	if (blocks->prevLeaf != NULL) {
		if (!KSI_DataHash_equals(blocks->prevLeaf, hash)) {
			res = KT_VERIFICATION_FAILURE;
			print_progressResult(res);
			OBJPRINT_Hash(blocks->prevLeaf, "Expected hash of previous leaf: ", print_debug);
			OBJPRINT_Hash(hash            , "Received hash of previous leaf: ", print_debug);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: previous leaf hashes not equal.", blocks->blockNo);
		}
	}

	if (files->files.outSig) {
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->files.outSig) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to copy block header.", blocks->blockNo);
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

	KSI_DataHash_free(blocks->extractMask);
	blocks->extractMask = NULL;
	for (j = 0; j < blocks->nofExtractPositionsInBlock; j++) {
		for (i = 0; i < blocks->extractInfo[j].extractLevel; i++) {
			KSI_DataHash_free(blocks->extractInfo[j].extractChain[i].sibling);
			blocks->extractInfo[j].extractChain[i].sibling = NULL;
		}
		blocks->extractInfo[j].extractLevel = 0;
		KSI_DataHash_free(blocks->extractInfo[j].extractRecord);
		blocks->extractInfo[j].extractRecord = NULL;
		free(blocks->extractInfo[j].logLine);
		blocks->extractInfo[j].logLine = NULL;
		KSI_TlvElement_free(blocks->extractInfo[j].metaRecord);
		blocks->extractInfo[j].metaRecord = NULL;
	}
	free(blocks->extractInfo);
	blocks->extractInfo = NULL;
	blocks->nofExtractPositionsInBlock = 0;

	res = KT_OK;

cleanup:

	print_progressResult(res);
	KSI_OctetString_free(seed);
	KSI_DataHash_free(hash);
	KSI_TlvElement_free(tlv);
	return res;
}

static int is_record_hash_expected(ERR_TRCKR *err, BLOCK_INFO *blocks) {
	int res;

	if (err == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Check if record hash is received between block header and block signature. */
	if (blocks->blockNo == blocks->sigNo) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: record hash without preceding block header found.", blocks->blockNo + 1);
	}
	/* Check if record hashes are present for previous records. */
	if (blocks->nofRecordHashes > 0 && blocks->keepRecordHashes == 0) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: missing record hash for record no. %3zu.", blocks->blockNo, blocks->nofRecordHashes);
	}
	/* Check if all tree hashes are present for previous records. */
	if (blocks->keepTreeHashes && blocks->nofTreeHashes != max_tree_hashes(blocks->nofRecordHashes)) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: missing tree hash(es) for record no. %3zu.", blocks->blockNo, blocks->nofRecordHashes);
	}
	/* Check if record hashes are present in previous blocks. */
	if (blocks->blockNo > 1 && blocks->keepRecordHashes == 0) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: all record hashes missing.", blocks->blockNo - 1);
	}

	res = KT_OK;

cleanup:

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

	print_progressDesc(0, "Block no. %3zu: processing record hash... ", blocks->blockNo);

	res = is_record_hash_expected(err, blocks);
	if (res != KT_OK) goto cleanup;

	blocks->keepRecordHashes = 1;
	blocks->nofRecordHashes++;

	res = KSI_DataHash_fromImprint(ksi, blocks->ftlv_raw + blocks->ftlv.hdr_len, blocks->ftlv.dat_len, &recordHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to create hash of record no. %3zu.", blocks->blockNo, blocks->nofRecordHashes);

	if (blocks->metarecordHash != NULL) {
		/* This is a metarecord hash. */
		if (!KSI_DataHash_equals(blocks->metarecordHash, recordHash)) {
			res = KT_VERIFICATION_FAILURE;
			print_progressResult(res);
			OBJPRINT_Hash(blocks->metarecordHash, "Expected metarecord hash: ", print_debug);
			OBJPRINT_Hash(recordHash            , "Received metarecord hash: ", print_debug);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: metarecord hashes not equal.", blocks->blockNo);
		}

		res = add_record_hash_to_merkle_tree(ksi, blocks, 1, blocks->metarecordHash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);

		KSI_DataHash_free(blocks->metarecordHash);
		blocks->metarecordHash = NULL;
	} else {
		/* This is a logline record hash. */
		if (files->files.inLog) {
			res = get_hash_of_logline(ksi, blocks, files, &hash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to calculate hash of logline no. %3zu.", blocks->blockNo, blocks->nofRecordHashes);

			if (!KSI_DataHash_equals(hash, recordHash)) {
				res = KT_VERIFICATION_FAILURE;
				print_progressResult(res);
				OBJPRINT_Hash(hash,       "Expected record hash: ", print_debug);
				OBJPRINT_Hash(recordHash, "Received record hash: ", print_debug);
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: record hashes not equal for record no. %3zu.", blocks->blockNo, blocks->nofRecordHashes);
			}
		}

		res = add_record_hash_to_merkle_tree(ksi, blocks, 0, recordHash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to add hash to Merkle tree.", blocks->blockNo);
	}

	if (files->files.outSig) {
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->files.outSig) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to copy record hash.", blocks->blockNo);
		}
	}
	res = KT_OK;

cleanup:

	print_progressResult(res);
	KSI_DataHash_free(recordHash);
	KSI_DataHash_free(hash);
	return res;
}

static int max_final_hashes(BLOCK_INFO *blocks) {
	int finalHashes = 0;
	int i;
	if (blocks) {
		for (i = 0; i < blocks->treeHeight; i++) {
			if (blocks->MerkleTree[i]) {
				finalHashes++;
			}
		}
		finalHashes--;
	}
	return finalHashes;
}

static int is_tree_hash_expected(ERR_TRCKR *err, BLOCK_INFO *blocks) {
	int res;
	int i;

	if (err == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	/* Check if tree hash is received between block header and block signature. */
	if (blocks->blockNo == blocks->sigNo) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: tree hash without preceding block header found.", blocks->blockNo + 1);
	}
	/* Check if tree hashes are present for previous records. */
	if (blocks->nofRecordHashes > 1 && blocks->keepTreeHashes == 0) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: missing tree hash for record no. %3zu.", blocks->blockNo, blocks->nofRecordHashes - 1);
	}
	/* Check if all record hashes are present for previous records. */
	if (blocks->keepRecordHashes && blocks->nofTreeHashes == max_tree_hashes(blocks->nofRecordHashes)) {
		/* Either a record hash is missing or the tree hash is used in finalizing the unbalanced tree. */
		if (blocks->balanced) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: missing record hash for record no. %3zu.", blocks->blockNo, blocks->nofRecordHashes + 1);
		} else {
			blocks->finalTreeHashesSome = 1;
			/* Prepare tree hashes for verification of finalizing. */
			for (i = 0; i < blocks->treeHeight; i++) {
				blocks->notVerified[i] = KSI_DataHash_ref(blocks->MerkleTree[i]);
			}
		}
	}
	/* Check if all final tree hashes are present. */
	if (blocks->finalTreeHashesSome && blocks->nofTreeHashes == max_tree_hashes(blocks->nofRecordHashes) + max_final_hashes(blocks)) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unexpected final tree hash no. %3zu.", blocks->blockNo, blocks->nofTreeHashes + 1);
	}

	/* Check if tree hashes are present in previous blocks. */
	if (blocks->blockNo > 1 && blocks->keepTreeHashes == 0) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: all tree hashes missing.", blocks->blockNo - 1);
	}
	res = KT_OK;

cleanup:

	return res;
}

static int process_tree_hash(ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_DataHash *treeHash = NULL;
	KSI_DataHash *recordHash = NULL;
	KSI_DataHash *tmpRoot = NULL;
	KSI_DataHash *root = NULL;
	unsigned char i;

	if (err == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDesc(0, "Block no. %3zu: processing tree hash... ", blocks->blockNo);

	res = is_tree_hash_expected(err, blocks);
	if (res != KT_OK) goto cleanup;

	blocks->keepTreeHashes = 1;
	blocks->nofTreeHashes++;

	res = KSI_DataHash_fromImprint(ksi, blocks->ftlv_raw + blocks->ftlv.hdr_len, blocks->ftlv.dat_len, &treeHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to create tree hash.", blocks->blockNo);

	if (files->files.outSig) {
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->files.outSig) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to copy record hash.", blocks->blockNo);
		}
	}

	/* If the block contains tree hashes, but not record hashes:
	 * Calculate missing record hashes from the records in the logfile and
	 * build the Merkle tree according to the number of tree hashes encountered. */
	if (blocks->keepRecordHashes == 0 && blocks->nofTreeHashes > max_tree_hashes(blocks->nofRecordHashes)) {
		blocks->nofRecordHashes++;
		if (files->files.inLog) {
			if (blocks->metarecordHash) {
				res = add_record_hash_to_merkle_tree(ksi, blocks, 1, blocks->metarecordHash);
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);

				KSI_DataHash_free(blocks->metarecordHash);
				blocks->metarecordHash = NULL;
			} else {
				res = get_hash_of_logline(ksi, blocks, files, &recordHash);
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to calculate hash of logline no. %3zu.", blocks->blockNo, blocks->nofRecordHashes);
				res = add_record_hash_to_merkle_tree(ksi, blocks, 0, recordHash);
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to add record hash to Merkle tree.", blocks->blockNo);
				KSI_DataHash_free(recordHash);
				recordHash = NULL;
			}
		} else {
			/* No log file available so build the Merkle tree from tree hashes alone. */
			res = add_leaf_hash_to_merkle_tree(ksi, blocks, treeHash, 0);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to add leaf hash to Merkle tree.", blocks->blockNo);
		}
	}

	if (!blocks->finalTreeHashesSome) {
		if (blocks->nofRecordHashes) {
			/* Find the corresponding tree hash from the Merkle tree. */
			for (i = 0; i < blocks->treeHeight; i++) {
				if (blocks->notVerified[i] != NULL) break;
			}
			if (i == blocks->treeHeight) {
				res = KT_VERIFICATION_FAILURE;
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unexpected tree hash for record no. %3zu.", blocks->blockNo, blocks->nofRecordHashes);
			}

			if (!KSI_DataHash_equals(blocks->notVerified[i], treeHash)) {
				res = KT_VERIFICATION_FAILURE;
				print_progressResult(res);
				OBJPRINT_Hash(blocks->notVerified[i], "Expected tree hash: ", print_debug);
				OBJPRINT_Hash(treeHash               , "Received tree hash: ", print_debug);
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: tree hashes not equal for record no. %3zu.", blocks->blockNo, blocks->nofRecordHashes);
			}
			KSI_DataHash_free(blocks->notVerified[i]);
			blocks->notVerified[i] = NULL;
		}
	} else {
		if (blocks->nofRecordHashes) {
			/* Find the corresponding tree hash from the Merkle tree. */
			if (blocks && blocks->finalTreeHashesSome) {
				print_progressResult(res);
				print_progressDesc(0, "Block no. %3zu: interpreting tree hash no. %3zu as a final hash... ", blocks->blockNo, blocks->nofTreeHashes);
			}
			i = 0;
			while (i < blocks->treeHeight) {
				if (root == NULL) {
					root = KSI_DataHash_ref(blocks->notVerified[i]);
					KSI_DataHash_free(blocks->notVerified[i]);
					blocks->notVerified[i] = NULL;
					i++;
					continue;
				}
				if (blocks->notVerified[i]) {
					res = calculate_new_tree_hash(ksi, blocks, blocks->notVerified[i], root, i + 2, &tmpRoot);
					if (res != KT_OK) goto cleanup;

					KSI_DataHash_free(blocks->notVerified[i]);
					blocks->notVerified[i] = KSI_DataHash_ref(tmpRoot);
					break;
				}
				i++;
			}
			if (i == blocks->treeHeight) {
				res = KT_VERIFICATION_FAILURE;
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unexpected tree hash for record no. %3zu.", blocks->blockNo, blocks->nofRecordHashes);
			}

			if (!KSI_DataHash_equals(blocks->notVerified[i], treeHash)) {
				res = KT_VERIFICATION_FAILURE;
				print_progressResult(res);
				OBJPRINT_Hash(blocks->notVerified[i], "Expected tree hash: ", print_debug);
				OBJPRINT_Hash(treeHash              , "Received tree hash: ", print_debug);
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: tree hashes not equal for record no. %3zu.", blocks->blockNo, blocks->nofRecordHashes);
			}
		}
	}
	res = KT_OK;

cleanup:

	print_progressResult(res);
	KSI_DataHash_free(treeHash);
	KSI_DataHash_free(recordHash);
	KSI_DataHash_free(tmpRoot);
	KSI_DataHash_free(root);
	return res;
}

static int process_metarecord(ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlv = NULL;
	size_t metarecord_index = 0;

	if (err == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDesc(0, "Block no. %3zu: processing metarecord... ", blocks->blockNo);

	res = KSI_TlvElement_parse(blocks->ftlv_raw, blocks->ftlv_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to parse metarecord as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &metarecord_index);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: missing metarecord index.", blocks->blockNo);

	if (files->files.inLog) {
		/* If the block contains metarecords but not the corresponding record hashes:
		 * Calculate missing metarecord hash from the last metarecord and
		 * build the Merkle tree according to the record count in the signature data. */
		if (blocks->metarecordHash != NULL) {
			/* Add the previous metarecord to Merkle tree. */
			blocks->nofRecordHashes++;
			res = add_record_hash_to_merkle_tree(ksi, blocks, 1, blocks->metarecordHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);
		}

		while (blocks->nofRecordHashes < metarecord_index) {
			blocks->nofRecordHashes++;
			res = get_hash_of_logline(ksi, blocks, files, &hash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: missing logline no. %3zu up to metarecord index %3zu.", blocks->blockNo, blocks->nofRecordHashes, metarecord_index);
			res = add_record_hash_to_merkle_tree(ksi, blocks, 0, hash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);
			KSI_DataHash_free(hash);
			hash = NULL;
		}
	}

	res = get_hash_of_metarecord(ksi, blocks, tlv, &hash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to calculate metarecord hash with index %3zu.", blocks->blockNo, metarecord_index);

	if (files->files.outSig) {
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->files.outSig) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to copy metarecord hash.", blocks->blockNo);
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

int is_block_signature_expected(ERR_TRCKR *err, BLOCK_INFO *blocks) {
	int res;
	size_t maxTreeHashes;
	size_t maxFinalHashes;

	if (err == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	maxTreeHashes = max_tree_hashes(blocks->recordCount);
	maxFinalHashes = max_final_hashes(blocks);

	if (blocks->keepRecordHashes) {
		/* Check if record hash is present for the most recent metarecord (if any). */
		if (blocks->metarecordHash) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: missing record hash for metarecord with index %3zu.", blocks->blockNo, blocks->nofRecordHashes);
		}
		/* Check if all record hashes are present in the current block. */
		if (blocks->nofRecordHashes < blocks->recordCount) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: missing record hash for record no. %3zu.", blocks->blockNo, blocks->nofRecordHashes + 1);
		}
	}

	if (blocks->keepTreeHashes) {
		/* Check if all mandatory tree hashes are present in the current block. */
		if (blocks->nofTreeHashes < maxTreeHashes) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: missing tree hash(es) for record no. %3zu.", blocks->blockNo, blocks->recordCount);
		}
		/* Check if the block contains too few optional tree hashes. */
		if (blocks->nofTreeHashes < maxTreeHashes + maxFinalHashes) {
			if (blocks->nofTreeHashes == maxTreeHashes) {
				/* Special case: if all optional tree hashes are missing, we issue just a warning. */
				blocks->finalTreeHashesNone = 1;
			} else {
				/* If however some optional tree hashes are present, they must all be present. */
				res = KT_VERIFICATION_FAILURE;
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: found %3zu final tree hashes instead of %3zu.", blocks->blockNo, blocks->nofTreeHashes - maxTreeHashes, maxFinalHashes);
			}
		}
		/* Check if the block contains too many optional tree hashes. */
		if (blocks->nofTreeHashes > maxTreeHashes + maxFinalHashes) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: found %3zu final tree hashes instead of %3zu.", blocks->blockNo, blocks->nofTreeHashes - maxTreeHashes, maxFinalHashes);
		}
		if (blocks->nofTreeHashes == maxTreeHashes + maxFinalHashes) {
			blocks->finalTreeHashesAll = 1;
		}
	}

	res = KT_OK;

cleanup:

	return res;
}

static int process_block_signature(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, SIGNATURE_PROCESSORS *processors, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *verificationResult = NULL;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvSig = NULL;
	KSI_TlvElement *recChain = NULL;
	KSI_TlvElement *hashStep = NULL;
	size_t j;

	KSI_VerificationContext_init(&context, ksi);

	if (set == NULL || err == NULL || ksi == NULL || processors == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	blocks->sigNo++;
	if (blocks->sigNo > blocks->blockNo) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: block signature data without preceding block header found.", blocks->sigNo);
	}

	print_progressDesc(0, "Block no. %3zu: processing block signature data... ", blocks->blockNo);

	res = KSI_TlvElement_parse(blocks->ftlv_raw, blocks->ftlv_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to parse block signature as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &blocks->recordCount);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: missing record count in block signature.", blocks->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x905, &tlvSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to extract KSI signature element in block signature.", blocks->blockNo);

	if (tlvSig == NULL) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: missing KSI signature in block signature.", blocks->blockNo);
	}

	res = is_block_signature_expected(err, blocks);
	if (res != KT_OK) goto cleanup;

	if (files->files.inLog) {
		/* If the block contains metarecords but not the corresponding record hashes:
		 * Calculate missing metarecord hash from the last metarecord and
		 * build the Merkle tree with the metarecord hash. */
		if (blocks->metarecordHash) {
			/* Add the previous metarecord to Merkle tree. */
			blocks->nofRecordHashes++;
			res = add_record_hash_to_merkle_tree(ksi, blocks, 1, blocks->metarecordHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);
		}

		/* If the block contains neither record hashes nor tree hashes:
		 * Calculate missing record hashes from the records in the logfile and
		 * build the Merkle tree according to the record count in the signature data. */
		if (blocks->keepRecordHashes == 0 && blocks->keepTreeHashes == 0) {
			while (blocks->nofRecordHashes < blocks->recordCount) {
				blocks->nofRecordHashes++;
				res = get_hash_of_logline(ksi, blocks, files, &hash);
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to calculate hash of logline no. %3zu.", blocks->blockNo, blocks->nofRecordHashes);
				res = add_record_hash_to_merkle_tree(ksi, blocks, 0, hash);
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to add hash to Merkle tree.", blocks->blockNo);
				KSI_DataHash_free(hash);
				hash = NULL;
			}
		}
	}

	/* If we have any record hashes directly from log signature file or indirectly from log file,
	 * their count must match the record count in block signature. */
	if (blocks->nofRecordHashes && blocks->nofRecordHashes != blocks->recordCount) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: expected %zu record hashes, but found %zu.", blocks->blockNo, blocks->recordCount, blocks->nofRecordHashes);
	}
	print_progressResult(res);
	print_progressDesc(1, "Block no. %3zu: verifying KSI signature... ", blocks->blockNo);

	blocks->nofTotalRecordHashes += blocks->nofRecordHashes;
	res = calculate_root_hash(ksi, blocks, (KSI_DataHash**)&context.documentHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to get root hash for verification.", blocks->blockNo);

	if (processors->verify_signature) {
		res = KSI_Signature_parseWithPolicy(ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_EMPTY, NULL, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to parse KSI signature.", blocks->blockNo);

		res = processors->verify_signature(set, err, ksi, sig, (KSI_DataHash*)context.documentHash, &verificationResult);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: KSI signature verification failed.", blocks->blockNo);
		/* TODO: add dumping of verification results. */
		KSI_PolicyVerificationResult_free(verificationResult);
		verificationResult = NULL;

	} else if (processors->extend_signature) {
		res = KSI_Signature_parseWithPolicy(ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_INTERNAL, &context, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to parse KSI signature.", blocks->blockNo);

		print_progressResult(res);
		print_progressDesc(1, "Block no. %3zu: extending KSI signature... ", blocks->blockNo);

		res = processors->extend_signature(set, err, ksi, sig, &context, &ext);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to extend KSI signature.", blocks->blockNo);

		res = tlv_element_set_signature(tlv, ksi, 0x905, ext);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to serialize extended KSI signature.", blocks->blockNo);

		res = KSI_TlvElement_serialize(tlv, blocks->ftlv_raw, SOF_FTLV_BUFFER, &blocks->ftlv_len, 0);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to serialize extended block signature.", blocks->blockNo);

		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->files.outSig) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to write extended signature to extended log signature file.", blocks->blockNo);
		}

		KSI_DataHash_free((KSI_DataHash*)context.documentHash);
		context.documentHash = NULL;
		KSI_VerificationContext_clean(&context);
	} else if (processors->extract_signature) {
		res = KSI_Signature_parseWithPolicy(ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_INTERNAL, &context, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to parse KSI signature.", blocks->blockNo);

		if (blocks->nofExtractPositionsInBlock) {
			if (fwrite(tlvSig->ptr, 1, tlvSig->ftlv.dat_len + tlvSig->ftlv.hdr_len, files->files.outProof) != tlvSig->ftlv.dat_len + tlvSig->ftlv.hdr_len) {
				res = KT_IO_ERROR;
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to write KSI signature to integrity proof file.", blocks->blockNo);
			}
		}

		print_progressResult(res);
		print_progressDesc(0, "Block no. %3zu: extracting log records... ", blocks->blockNo);

		for (j = 0; j < blocks->nofExtractPositionsInBlock; j++) {
			unsigned char buf[0xFFFF + 4];
			size_t len = 0;
			size_t i;

			if (blocks->extractInfo[j].extractOffset && blocks->extractInfo[j].extractOffset <= blocks->nofRecordHashes) {
				res = KSI_TlvElement_new(&recChain);
				ERR_CATCH_MSG(err, res, "Error: Record no. %4zu: unable to create record chain.", blocks->extractInfo[j].extractPos);
				recChain->ftlv.tag = 0x0907;

				if (blocks->extractInfo[j].logLine) {
					if (fwrite(blocks->extractInfo[j].logLine, 1, strlen(blocks->extractInfo[j].logLine), files->files.outLog) != strlen(blocks->extractInfo[j].logLine)) {
						res = KT_IO_ERROR;
						ERR_CATCH_MSG(err, res, "Error: Record no. %4zu: unable to write log record to log records file.", blocks->extractInfo[j].extractPos);
					}
				} else if (blocks->extractInfo[j].metaRecord){
					res = KSI_TlvElement_setElement(recChain, blocks->extractInfo[j].metaRecord);
					ERR_CATCH_MSG(err, res, "Error: Record no. %4zu: unable to add metarecord to record chain.", blocks->extractInfo[j].extractPos);
				}
				res = tlv_element_set_hash(recChain, ksi, 0x01, blocks->extractInfo[j].extractRecord);
				ERR_CATCH_MSG(err, res, "Error: Record no. %4zu: unable to add record hash to record chain.", blocks->extractInfo[j].extractPos);

				for (i = 0; i < blocks->extractInfo[j].extractLevel; i++) {
					if (blocks->extractInfo[j].extractChain[i].sibling) {
						res = KSI_TlvElement_new(&hashStep);
						ERR_CATCH_MSG(err, res, "Error: Record no. %4zu: unable to create hash step no. %2zu.", blocks->extractInfo[j].extractPos, i + 1);

						if (blocks->extractInfo[j].extractChain[i].dir == LEFT_LINK) {
							hashStep->ftlv.tag = 0x02;
						}
						else {
							hashStep->ftlv.tag = 0x03;
						}
						if (blocks->extractInfo[j].extractChain[i].corr) {
							res = tlv_element_set_uint(hashStep, ksi, 0x01, blocks->extractInfo[j].extractChain[i].corr);
							ERR_CATCH_MSG(err, res, "Error: Record no. %4zu: unable to add level correction to hash step no. %2zu.", blocks->extractInfo[j].extractPos, i + 1);
						}
						res = tlv_element_set_hash(hashStep, ksi, 0x02, blocks->extractInfo[j].extractChain[i].sibling);
						ERR_CATCH_MSG(err, res, "Error: Record no. %4zu: unable to add sibling hash to hash step no. %2zu.", blocks->extractInfo[j].extractPos, i + 1);
						res = KSI_TlvElement_appendElement(recChain, hashStep);
						ERR_CATCH_MSG(err, res, "Error: Record no. %4zu: unable to add hash step no. %2zu.", blocks->extractInfo[j].extractPos, i + 1);

						KSI_TlvElement_free(hashStep);
						hashStep = NULL;
					}
				}
				res = KSI_TlvElement_serialize(recChain, buf, sizeof(buf), &len, 0);
				ERR_CATCH_MSG(err, res, "Error: Record no. %4zu: unable to serialize record chain.", blocks->extractInfo[j].extractPos);

				if (fwrite(buf, 1, len, files->files.outProof) != len) {
					res = KT_IO_ERROR;
					ERR_CATCH_MSG(err, res, "Error: Record no. %4zu: unable to write record chain to integrity proof file.", blocks->extractInfo[j].extractPos);
				}
				KSI_TlvElement_free(recChain);
				recChain = NULL;
			}
		}
	}
	res = KT_OK;

cleanup:

	print_progressResult(res);
	if (blocks) {
		if (blocks->finalTreeHashesNone) {
			print_debug("Warning: Block no. %3zu: all final tree hashes are missing.\n", blocks->blockNo);
			blocks->warningTreeHashes = 1;
		} else if (blocks->finalTreeHashesAll) {
			print_debug("Block no. %3zu: all final tree hashes are present.\n", blocks->blockNo);
		}
	}
	KSI_Signature_free(sig);
	KSI_Signature_free(ext);
	KSI_DataHash_free((KSI_DataHash*)context.documentHash);
	KSI_DataHash_free(hash);
	KSI_VerificationContext_clean(&context);
	KSI_PolicyVerificationResult_free(verificationResult);
	KSI_TlvElement_free(tlvSig);
	KSI_TlvElement_free(tlv);
	KSI_TlvElement_free(hashStep);
	KSI_TlvElement_free(recChain);
	return res;
}

static int process_ksi_signature(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, SIGNATURE_PROCESSORS *processors, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_Signature *sig = NULL;
	KSI_PolicyVerificationResult *verificationResult = NULL;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlvSig = NULL;

	if (set == NULL || err == NULL || ksi == NULL || processors == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	blocks->blockNo++;
	blocks->sigNo++;
	print_progressDesc(0, "Block no. %3zu: processing KSI signature ... ", blocks->blockNo);

	res = KSI_TlvElement_parse(blocks->ftlv_raw, blocks->ftlv_len, &tlvSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to parse KSI signature as TLV element.", blocks->blockNo);

	print_progressResult(res);
	print_progressDesc(1, "Block no. %3zu: verifying KSI signature... ", blocks->blockNo);

	if (processors->verify_signature) {
		res = KSI_Signature_parseWithPolicy(ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_EMPTY, NULL, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to parse KSI signature.", blocks->blockNo);

		res = processors->verify_signature(set, err, ksi, sig, NULL, &verificationResult);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: KSI signature verification failed.", blocks->blockNo);
		/* TODO: add dumping of verification results. */
		KSI_PolicyVerificationResult_free(verificationResult);
		verificationResult = NULL;

		res = KSI_Signature_getDocumentHash(sig, &hash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to get root hash from KSI signature.", blocks->blockNo);

		res = KSI_DataHash_getHashAlg(hash, &blocks->hashAlgo);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to get algorithm ID from root hash.", blocks->blockNo);

		KSI_DataHash_free(blocks->rootHash);
		blocks->rootHash = KSI_DataHash_ref(hash);
	}
	res = KT_OK;

cleanup:

	print_progressResult(res);
	KSI_Signature_free(sig);
	KSI_PolicyVerificationResult_free(verificationResult);
	KSI_TlvElement_free(tlvSig);
	return res;
}

static int process_hash_step(KSI_CTX *ksi, KSI_TlvElement *tlv, BLOCK_INFO *blocks, KSI_DataHash *inputHash, KSI_DataHash **outputHash) {
	int res;
	size_t correction = 0;
	KSI_DataHash *siblingHash = NULL;
	KSI_DataHash *tmp = NULL;

	if (tlv == NULL || blocks == NULL || inputHash == NULL || outputHash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = tlv_element_get_uint(tlv, ksi, 0x01, &correction);
	if (res == KT_INVALID_INPUT_FORMAT) {
		correction = 0;
		res = KT_OK;
	}
	if (res != KT_OK) goto cleanup;
	res = tlv_element_get_hash(tlv, ksi, 0x02, &siblingHash);
	if (res != KT_OK) goto cleanup;

	blocks->treeHeight += correction + 1;
	if (tlv->ftlv.tag == 0x02) {
		res = calculate_new_tree_hash(ksi, blocks, inputHash, siblingHash, blocks->treeHeight, &tmp);
	} else if (tlv->ftlv.tag == 0x03){
		res = calculate_new_tree_hash(ksi, blocks, siblingHash, inputHash, blocks->treeHeight, &tmp);
	} else {
		res = KT_INVALID_INPUT_FORMAT;
	}
	if (res != KT_OK) goto cleanup;

	*outputHash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(siblingHash);
	KSI_DataHash_free(tmp);
	return res;
}

static int process_record_chain(ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_DataHash *recordHash = NULL;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvMetaRecord = NULL;
	KSI_DataHash *tmpHash = NULL;
	KSI_DataHash *root = NULL;

	if (err == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDesc(0, "Block no. %3zu: processing record hash... ", blocks->blockNo);

	blocks->nofRecordHashes++;

	res = KSI_TlvElement_parse(blocks->ftlv_raw, blocks->ftlv_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to parse record chain as TLV element.", blocks->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x911, &tlvMetaRecord);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to extract metarecord in record chain.", blocks->blockNo);

	KSI_DataHash_free(blocks->metarecordHash);
	blocks->metarecordHash = NULL;
	if (tlvMetaRecord != NULL) {
		res = get_hash_of_metarecord(ksi, blocks, tlvMetaRecord, &hash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to calculate metarecord hash.", blocks->blockNo);

		blocks->metarecordHash = KSI_DataHash_ref(hash);
	}

	res = tlv_element_get_hash(tlv, ksi, 0x01, &recordHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to parse hash of record no. %3zu.", blocks->blockNo, blocks->nofRecordHashes);

	if (blocks->metarecordHash != NULL) {
		/* This is a metarecord hash. */
		if (!KSI_DataHash_equals(blocks->metarecordHash, recordHash)) {
			res = KT_VERIFICATION_FAILURE;
			print_progressResult(res);
			OBJPRINT_Hash(blocks->metarecordHash, "Expected metarecord hash: ", print_debug);
			OBJPRINT_Hash(recordHash            , "Received metarecord hash: ", print_debug);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: metarecord hashes not equal.", blocks->blockNo);
		}

	} else {
		/* This is a logline record hash. */
		if (files->files.inLog) {
			res = get_hash_of_logline(ksi, blocks, files, &hash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to calculate hash of logline no. %3zu.", blocks->blockNo, blocks->nofRecordHashes);

			if (!KSI_DataHash_equals(hash, recordHash)) {
				res = KT_VERIFICATION_FAILURE;
				print_progressResult(res);
				OBJPRINT_Hash(hash,       "Expected record hash: ", print_debug);
				OBJPRINT_Hash(recordHash, "Received record hash: ", print_debug);
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: record hashes not equal.", blocks->blockNo);
			}
		}
	}

	if (tlv->subList) {
		int i;
		blocks->treeHeight = 0;
		root = KSI_DataHash_ref(recordHash);

		print_progressResult(res);
		print_progressDesc(0, "Block no. %3zu: processing hash chain... ", blocks->blockNo);
		for (i = 0; i < KSI_TlvElementList_length(tlv->subList); i++) {
			KSI_TlvElement *tmpTlv = NULL;

			res = KSI_TlvElementList_elementAt(tlv->subList, i, &tmpTlv);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to get element %d from TLV.", blocks->blockNo, i);
			if (tmpTlv && (tmpTlv->ftlv.tag == 0x02 || tmpTlv->ftlv.tag == 0x03)) {
				res = process_hash_step(ksi, tmpTlv, blocks, root, &tmpHash);
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to process hash step.", blocks->blockNo);

				KSI_DataHash_free(root);
				root = tmpHash;
				tmpHash = NULL;
			}
		}

		if (!KSI_DataHash_equals(blocks->rootHash, root)) {
			res = KT_VERIFICATION_FAILURE;
			print_progressResult(res);
			OBJPRINT_Hash(blocks->rootHash, "Expected KSI signature root hash: ", print_debug);
			OBJPRINT_Hash(root,             "            Calculated root hash: ", print_debug);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: root hashes not equal.", blocks->blockNo);
		}

	} else {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to get sub TLVs from record chain.", blocks->blockNo);
	}
	res = KT_OK;

cleanup:

	print_progressResult(res);
	KSI_DataHash_free(recordHash);
	KSI_DataHash_free(hash);
	KSI_DataHash_free(root);
	KSI_DataHash_free(tmpHash);
	KSI_TlvElement_free(tlv);
	KSI_TlvElement_free(tlvMetaRecord);
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

	print_progressDesc(0, "Block no. %3zu: processing partial block data... ", blocks->blockNo);

	blocks->partNo++;
	if (blocks->partNo > blocks->blockNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: partial block data without preceding block header found.", blocks->sigNo);
	}

	res = KSI_TlvElement_parse(blocks->ftlv_raw, blocks->ftlv_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to parse block signature as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &blocks->recordCount);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: missing record count in blocks file.", blocks->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x02, &tlvNoSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to extract 'no-sig' element in blocks file.", blocks->blockNo);

	res = tlv_element_get_hash(tlvNoSig, ksi, 0x01, &hash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: missing root hash in blocks file.", blocks->blockNo);

	if (blocks->nofRecordHashes && blocks->nofRecordHashes != blocks->recordCount) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: expected %zu records in blocks file, but found %zu records.", blocks->blockNo, blocks->recordCount, blocks->nofRecordHashes);
	}

	/* If the blocks file contains hashes, re-compute and compare the root hash against the provided root hash. */
	if (blocks->nofRecordHashes) {
		res = calculate_root_hash(ksi, blocks, &rootHash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to calculate root hash.", blocks->blockNo);
		if (!KSI_DataHash_equals(rootHash, hash)) {
			res = KT_VERIFICATION_FAILURE;
			print_progressResult(res);
			OBJPRINT_Hash(rootHash, "Expected root hash: ", print_debug);
			OBJPRINT_Hash(hash,     "Received root hash: ", print_debug);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: root hashes not equal.", blocks->blockNo);
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

	print_progressDesc(0, "Block no. %3zu: processing partial signature data... ", blocks->blockNo);

	blocks->sigNo++;
	if (blocks->sigNo > blocks->blockNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: block signature data without preceding block header found.", blocks->sigNo);
	}
	res = KSI_TlvElement_parse(blocks->ftlv_raw, blocks->ftlv_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to parse block signature as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &blocks->recordCount);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: missing record count in signatures file.", blocks->blockNo);

	res = is_block_signature_expected(err, blocks);
	if (res != KT_OK) goto cleanup;

	if (blocks->nofRecordHashes && blocks->nofRecordHashes != blocks->recordCount) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: expected %zu records in signatures file, but found %zu records in blocks file.", blocks->blockNo, blocks->recordCount, blocks->nofRecordHashes);
	}

	res = KSI_TlvElement_getElement(tlv, 0x905, &tlvSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to extract KSI signature element in signatures file.", blocks->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x02, &tlvNoSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to extract 'no-sig' element in signatures file.", blocks->blockNo);

	if (tlvSig != NULL) {
		res = KSI_Signature_parseWithPolicy(ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_EMPTY, NULL, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to parse KSI signature in signatures file.", blocks->blockNo);

		res = KSI_Signature_getDocumentHash(sig, &docHash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to get root hash from KSI signature.", blocks->blockNo);

		/* If the blocks file contains hashes, re-compute and compare the root hash against the provided root hash. */
		if (blocks->nofRecordHashes) {
			if (blocks->rootHash == NULL) {
				res = calculate_root_hash(ksi, blocks, &blocks->rootHash);
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to calculate root hash.", blocks->blockNo);
			}

			if (!KSI_DataHash_equals(blocks->rootHash, docHash)) {
				res = KT_VERIFICATION_FAILURE;
				print_progressResult(res);
				OBJPRINT_Hash(blocks->rootHash, "Expected root hash: ", print_debug);
				OBJPRINT_Hash(docHash,          "Received root hash: ", print_debug);
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: root hashes not equal.", blocks->blockNo);
			}
		} else {
			KSI_DataHash_free(blocks->prevLeaf);
			blocks->prevLeaf = NULL;
		}
	} else if (tlvNoSig != NULL) {
		blocks->noSigNo++;
		res = tlv_element_get_hash(tlvNoSig, ksi, 0x01, &hash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to parse root hash.", blocks->blockNo);

		if (blocks->rootHash == NULL) {
			res = calculate_root_hash(ksi, blocks, &blocks->rootHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to calculate root hash.", blocks->blockNo);
		}
		if (!KSI_DataHash_equals(hash, blocks->rootHash)) {
			res = KT_VERIFICATION_FAILURE;
			print_progressResult(res);
			OBJPRINT_Hash(blocks->rootHash, "Expected root hash: ", print_debug);
			OBJPRINT_Hash(hash,             "Received root hash: ", print_debug);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: root hashes not equal.", blocks->blockNo);
		}

		if (processors->create_signature) {
			print_progressResult(res);

			if (progress) {
				print_debug("Progress: signing block %3zu of %3zu unsigned blocks. Estimated time remaining: %3zu seconds.\n", blocks->noSigNo, blocks->noSigCount, blocks->noSigCount - blocks->noSigNo + 1);
			}
			print_progressDesc(1, "Block no. %3zu: creating missing KSI signature... ", blocks->blockNo);

			res = processors->create_signature(err, ksi, hash, get_aggregation_level(blocks), &sig);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to sign root hash.", blocks->blockNo);

			res = KSI_TlvElement_new(&tlvSig);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to serialize KSI signature.", blocks->blockNo);
			tlvSig->ftlv.tag = 0x904;

			res = tlv_element_set_uint(tlvSig, ksi, 0x01, blocks->recordCount);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to serialize KSI signature.", blocks->blockNo);

			res = tlv_element_set_signature(tlvSig, ksi, 0x905, sig);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to serialize KSI signature.", blocks->blockNo);

			res = KSI_TlvElement_serialize(tlvSig, blocks->ftlv_raw, SOF_FTLV_BUFFER, &blocks->ftlv_len, 0);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to serialize KSI signature.", blocks->blockNo);
		}
	} else {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: block signature missing in signatures file.", blocks->blockNo);
	}

	if (files->files.outSig) {
		print_progressResult(res);
		print_progressDesc(0, "Block no. %3zu: writing KSI signature to file... ", blocks->blockNo);

		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->files.outSig) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to write signature data log signature file.", blocks->blockNo);
		}
	}

	res = KT_OK;

cleanup:

	print_progressResult(res);
	if (blocks) {
		if (blocks->finalTreeHashesNone) {
			print_debug("Warning: Block no. %3zu: all final tree hashes are missing.\n", blocks->blockNo);
			blocks->warningTreeHashes = 1;
		} else if (blocks->finalTreeHashesAll) {
			print_debug("Block no. %3zu: all final tree hashes are present.\n", blocks->blockNo);
		}
	}
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
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: block signature data missing.", blocks->blockNo);
	}

	if (blocks->partNo > blocks->sigNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: block signature data missing.", blocks->blockNo);
	}

	/* Log file must not contain more records than log signature file. */
	if (files->files.inLog) {
		if (fread(buf, 1, 1, files->files.inLog) > 0) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: end of log file contains unexpected records.", blocks->blockNo);
		}
	}

	/* Signatures file must not contain more blocks than blocks file. */
	if (files->files.partsSig) {
		if (fread(buf, 1, 1, files->files.partsSig) > 0) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: end of signatures file contains unexpected data.", blocks->blockNo);
		}
	}

	res = KT_OK;

cleanup:

	print_progressResult(res);

	if (blocks && blocks->warningTreeHashes) {
		print_warnings("Warning: Some tree hashes are missing from the log signature file.\n");
	}

	return res;
}

static void free_blocks(BLOCK_INFO *blocks) {
	unsigned char i = 0;
	size_t j;

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
		KSI_DataHash_free(blocks->extractMask);
		for (j = 0; j < blocks->nofExtractPositionsInBlock; j++) {
			KSI_DataHash_free(blocks->extractInfo[j].extractRecord);
			free(blocks->extractInfo[j].logLine);
			KSI_TlvElement_free(blocks->extractInfo[j].metaRecord);
			for (i = 0; i < blocks->extractInfo[j].extractLevel; i++) {
				KSI_DataHash_free(blocks->extractInfo[j].extractChain[i].sibling);
			}
		}
		free(blocks->extractPositions);
		free(blocks->extractInfo);
		free(blocks->logLine);
		free(blocks->metaRecord);
	}
}

static int count_blocks(ERR_TRCKR *err, BLOCK_INFO *blocks, FILE *in) {
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
					ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to parse block signature as TLV element.", blocks->blockNo);
					res = KSI_TlvElement_getElement(tlv, 0x02, &tlvNoSig);
					ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unable to extract 'no-sig' element in signatures file.", blocks->blockNo);

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
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: incomplete data found in log signature file.", blocks->blockNo);
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
	memset(&processors, 0, sizeof(processors));
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
					res = process_tree_hash(err, ksi, &blocks, files);
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
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: incomplete data found in log signature file.", blocks.blockNo);
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
	memset(&processors, 0, sizeof(processors));
	processors.verify_signature = verify_signature;

	res = process_magic_number(err, &blocks, files);
	if (res != KT_OK) goto cleanup;

	while (!feof(files->files.inSig)) {
		res = KSI_FTLV_fileRead(files->files.inSig, blocks.ftlv_raw, SOF_FTLV_BUFFER, &blocks.ftlv_len, &blocks.ftlv);
		if (res == KSI_OK) {
			switch (blocks.version) {
				case LOGSIG11:
				case LOGSIG12:
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
							res = process_tree_hash(err, ksi, &blocks, files);
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
				break;

				case RECSIG11:
				case RECSIG12:
					switch (blocks.ftlv.tag) {
						case 0x905:
						{
							res = process_ksi_signature(set, err, ksi, &processors, &blocks, files);
							if (res != KT_OK) goto cleanup;
						}
						break;

						case 0x907:
						{
							res = process_record_chain(err, ksi, &blocks, files);
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
				break;

				default:
					/* TODO: unknown file header found. */
				break;
			}
		} else {
			if (blocks.ftlv_len > 0) {
				res = KT_INVALID_INPUT_FORMAT;
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: incomplete data found in log signature file.", blocks.blockNo);
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

int add_position(ERR_TRCKR *err, long int n, BLOCK_INFO *blocks) {
	int res;
	size_t *tmp = NULL;

	if (n == 0 || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (blocks->nofExtractPositions) {
		if (n <= blocks->extractPositions[blocks->nofExtractPositions - 1]) {
			res = KT_INVALID_CMD_PARAM;
			ERR_CATCH_MSG(err, res, "Error: List of positions must be given in strictly ascending order.");
		}
	}

	if (blocks->extractPositions == NULL) {
		tmp = (size_t*)malloc(sizeof(size_t));
	} else {
		tmp = (size_t*)realloc(blocks->extractPositions, sizeof(size_t) * (blocks->nofExtractPositions + 1));
	}

	if (tmp == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	blocks->extractPositions = tmp;
	tmp = NULL;
	blocks->extractPositions[blocks->nofExtractPositions] = n;
	blocks->nofExtractPositions++;
	res = KT_OK;


cleanup:

	return res;
}

int extract_positions(ERR_TRCKR *err, char *records, BLOCK_INFO *blocks) {
	int res;
	long int n = 0;
	long int from = 0;
	char *endp = NULL;
	char digit_expected = 1;
	char dash_allowed = 1;

	if (records == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	while (*records) {
		if(!digit_expected) {
			digit_expected = 1;
			if (*records == ',') {
				dash_allowed = 1;
				records++;
				from = 0;
				continue;
			}
			if (*records == '-') {
				if (dash_allowed) {
					dash_allowed = 0;
					records++;
					from = n;
					continue;
				} else {
					res = KT_INVALID_CMD_PARAM;
					ERR_CATCH_MSG(err, res, "Error: Positions must be represented by positive decimal integers, using a list of comma-separated ranges.");
				}
			}
		} else {
			digit_expected = 0;
			n = strtol(records, &endp, 10);
			if (endp == records) {
				res = KT_INVALID_CMD_PARAM;
				ERR_CATCH_MSG(err, res, "Error: Positions must be represented by positive decimal integers, using a list of comma-separated ranges.");
			} else {
				if (n <= 0) {
					res = KT_INVALID_CMD_PARAM;
					ERR_CATCH_MSG(err, res, "Error: Positions must be represented by positive decimal integers, using a list of comma-separated ranges.");
				} else if (from == 0) {
					res = add_position(err, n, blocks);
					if (res != KT_OK) goto cleanup;
				} else if (n <= from) {
					res = KT_INVALID_CMD_PARAM;
					ERR_CATCH_MSG(err, res, "Error: List of positions must be given in strictly ascending order.");
				} else {
					while (from++ < n) {
						res = add_position(err, from, blocks);
						if (res != KT_OK) goto cleanup;
					}
				}
				from = 0;
				records = endp;
			}
		}
	}

	if(digit_expected) {
		res = KT_INVALID_CMD_PARAM;
		ERR_CATCH_MSG(err, res, "Error: Positions must be represented by positive decimal integers, using a list of comma-separated ranges.");
	}
	res = KT_OK;

cleanup:

	return res;
}

int logsignature_extract(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, IO_FILES *files) {
	int res;
	BLOCK_INFO blocks;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;
	char *records = NULL;

	if (set == NULL || err == NULL || ksi == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	memset(&blocks, 0, sizeof(blocks));
	blocks.ftlv_raw = ftlv_raw;
	memset(&processors, 0, sizeof(processors));
	processors.extract_signature = 1;

	res = PARAM_SET_getStr(set, "r", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &records);
	if (res != KT_OK) goto cleanup;

	res = extract_positions(err, records, &blocks);
	if (res != KT_OK) goto cleanup;

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
					res = process_tree_hash(err, ksi, &blocks, files);
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
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: incomplete data found in log signature file.", blocks.blockNo);
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
	memset(&processors, 0, sizeof(processors));

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
					res = process_tree_hash(err, ksi, &blocks, files);
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
							ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: incomplete data found in signatures file.", blocks.blockNo);
						} else {
							res = KT_VERIFICATION_FAILURE;
							ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unexpected end of signatures file.", blocks.blockNo);
						}
					}
					if (blocks.ftlv.tag != 0x904) {
						res = KT_INVALID_INPUT_FORMAT;
						ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: unexpected TLV %04X read from block-signatures file.", blocks.blockNo, blocks.ftlv.tag);
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
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: incomplete data found in blocks file.", blocks.blockNo);
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
	memset(&processors, 0, sizeof(processors));
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
		print_debug("Progress: %3zu of %3zu blocks need signing. Estimated signing time: %3zu seconds.\n", blocks.noSigCount, blocks.blockCount, blocks.noSigCount);
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
					res = process_tree_hash(err, ksi, &blocks, files);
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
				ERR_CATCH_MSG(err, res, "Error: Block no. %3zu: incomplete data found in log signature file.", blocks.blockNo);
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

int duplicate_name(char *in, char **out) {
	int res;
	char *tmp = NULL;

	if (in == NULL || out == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = strdup(in);
	if (tmp == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	*out = tmp;
	res = KT_OK;

cleanup:

	return res;
}

int temp_name(char *org, char **derived) {
	int res;
	int fd = -1;
	char *tmp = NULL;
	mode_t prev;

	if (org == NULL || derived == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = concat_names(org, "XXXXXX", &tmp);
	if (res != KT_OK) goto cleanup;

	prev = umask(077);
	fd = mkstemp(tmp);
	umask(prev);

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

int logksi_file_check_and_open(ERR_TRCKR *err, char *name, FILE **out) {
	int res;
	FILE *tmp = NULL;

	if (name == NULL || out == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = fopen(name, "rb");
	if (tmp == NULL) {
		if (errno == ENOENT) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: could not find file %s.", name);
		} else {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: could not open file %s.", name);
		}
	}

	*out = tmp;
	res = KT_OK;

cleanup:
	return res;
}

int logksi_file_create(char *name, FILE **out) {
	int res;
	FILE *tmp = NULL;

	if (name == NULL  || out == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = fopen(name, "wb");
	if (tmp == NULL) {
		res = KT_IO_ERROR;
		goto cleanup;
	}
	*out = tmp;
	res = KT_OK;

cleanup:
	return res;
}

int logksi_file_create_temporary(char *name, FILE **out, char bStdout) {
	int res;
	FILE *tmp = NULL;

	if ((name == NULL && bStdout == 0) || out == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Output goes either to a named or nameless temporary file. */
	if (bStdout) {
		tmp = tmpfile();
	} else {
		tmp = fopen(name, "wb");
	}
	if (tmp == NULL) {
		res = KT_IO_ERROR;
		goto cleanup;
	}
	*out = tmp;
	res = KT_OK;

cleanup:
	return res;
}

int logksi_file_redirect_to_stdout(FILE *in) {
	int res;
	char buf[1024];
	size_t count = 0;

	if (in == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (fseek(in, 0, SEEK_SET) != 0) {
		res = KT_IO_ERROR;
		goto cleanup;
	}

	while(!feof(in)) {
		count = fread(buf, 1, sizeof(buf), in);
		if (fwrite(buf, 1, count, stdout) != count) {
			res = KT_IO_ERROR;
			goto cleanup;
		}
	}
	res = KT_OK;

cleanup:

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
		logksi_filename_free(&internal->inLog);
		logksi_filename_free(&internal->inSig);
		logksi_filename_free(&internal->outSig);
		logksi_filename_free(&internal->outProof);
		logksi_filename_free(&internal->outLog);
		logksi_filename_free(&internal->tempSig);
		logksi_filename_free(&internal->tempProof);
		logksi_filename_free(&internal->tempLog);
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
		if (files->inLog == stdin) files->inLog = NULL;
		logksi_file_close(&files->inLog);
		if (files->inSig == stdin) files->inSig = NULL;
		logksi_file_close(&files->inSig);
		if (files->outSig == stdout) files->outSig = NULL;
		logksi_file_close(&files->outSig);
		logksi_file_close(&files->outProof);
		logksi_file_close(&files->outLog);
		logksi_file_close(&files->partsBlk);
		logksi_file_close(&files->partsSig);
	}
}

int logksi_file_remove(char *name) {
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

int logksi_file_rename(char *from, char *to) {
	int res;

	if (from == NULL || to == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (rename(from, to) != 0) {
		res = KT_IO_ERROR;
		goto cleanup;
	}
	res = KT_OK;

cleanup:

	return res;
}
