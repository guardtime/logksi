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
#include <ctype.h>
#include "param_set/param_set.h"
#include "tool_box/param_control.h"
#include "err_trckr.h"
#include <ksi/ksi.h>
#include <ksi/compatibility.h>
#include "logksi_err.h"
#include "api_wrapper.h"
#include "printer.h"
#include "obj_printer.h"
#include "debug_print.h"
#include <ksi/tlv_element.h>
#include "rsyslog.h"
#include "param_set/strn.h"
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <gtrfc3161/tsconvert.h>

#define SOF_ARRAY(x) (sizeof(x) / sizeof((x)[0]))

const char *IO_FILES_getCurrentLogFilePrintRepresentation(IO_FILES *files);

static char* ksi_signature_sigTimeToString(const KSI_Signature* sig, char *buf, size_t buf_len) {
	int res = KT_UNKNOWN_ERROR;
	KSI_Integer *sigTime = NULL;

	if (sig == NULL || buf == NULL || buf_len == 0) return NULL;

	res = KSI_Signature_getSigningTime(sig, &sigTime);
	if (res != KSI_OK) return NULL;


	return KSI_Integer_toDateString(sigTime, buf, buf_len);;
}

static char* uint64_toDateString(uint64_t time, char *buf, size_t buf_len) {
	int res = KT_UNKNOWN_ERROR;
	KSI_Integer *t = NULL;
	char tmp[256];

	if (buf == NULL || buf_len == 0) return NULL;

	res = KSI_Integer_new(NULL, time, &t);
	if (res != KSI_OK) return NULL;

	PST_snprintf(buf, buf_len, "(%llu) %s+00:00", (unsigned long long)time, KSI_Integer_toDateString(t, tmp, sizeof(tmp)));

	KSI_Integer_free(t);
	return buf;
}

enum {
	TASK_NONE = 0x00,
	TASK_VERIFY,
	TASK_EXTEND,
	TASK_EXTRACT,
	TASK_SIGN,
	TASK_INTEGRATE,
};

int calculate_new_tree_hash(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash *leftHash, KSI_DataHash *rightHash, unsigned char level, KSI_DataHash **nodeHash) {
	int res;
	KSI_DataHash *tmp = NULL;

	if (ksi == NULL || blocks == NULL || leftHash == NULL || rightHash == NULL || nodeHash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_DataHasher_reset(blocks->hasher);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addImprint(blocks->hasher, leftHash);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addImprint(blocks->hasher, rightHash);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_add(blocks->hasher, &level, 1);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_close(blocks->hasher, &tmp);
	if (res != KSI_OK) goto cleanup;

	*nodeHash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(tmp);
	return res;
}

int calculate_new_leaf_hash(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash *recordHash, int isMetaRecordHash, KSI_DataHash **leafHash) {
	int res;
	KSI_DataHash *mask = NULL;
	KSI_DataHash *tmp = NULL;

	if (ksi == NULL || blocks == NULL || recordHash == NULL || leafHash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_DataHasher_reset(blocks->hasher);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addImprint(blocks->hasher, blocks->prevLeaf);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addOctetString(blocks->hasher, blocks->randomSeed);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_close(blocks->hasher, &mask);
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

int merge_one_level(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash **hash) {
	int res;
	unsigned char i = 0;
	KSI_DataHash *root = NULL;
	KSI_DataHash *tmp = NULL;

	if (ksi == NULL || blocks == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	while (i < blocks->treeHeight) {
		if (blocks->MerkleTree[i]) {
			if (root == NULL) {
				/* Initialize root hash only if there is at least one more hash afterwards. */
				if (i < blocks->treeHeight - 1) {
					root = KSI_DataHash_ref(blocks->MerkleTree[i]);
					KSI_DataHash_free(blocks->MerkleTree[i]);
					blocks->MerkleTree[i] = NULL;
				}
			} else {
				res = calculate_new_tree_hash(ksi, blocks, blocks->MerkleTree[i], root, i + 2, &tmp);
				if (res != KT_OK) goto cleanup;

				KSI_DataHash_free(root);
				root = tmp;

				KSI_DataHash_free(blocks->MerkleTree[i]);
				blocks->MerkleTree[i] = KSI_DataHash_ref(root);
				break;
			}
		}
		i++;
	}

	*hash = KSI_DataHash_ref(root);
	tmp = NULL;

	res = KT_OK;

cleanup:

	KSI_DataHash_free(root);
	KSI_DataHash_free(tmp);
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

static size_t get_nof_lines(BLOCK_INFO *blocks) {
	if (blocks) {
		return blocks->nofRecordHashes + blocks->nofTotalRecordHashes;
	} else {
		return 0;
	}
}

int add_position(ERR_TRCKR *err, long int n, BLOCK_INFO *blocks) {
	int res;
	size_t *tmp = NULL;

	if (n <= 0 || blocks == NULL) {
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

int extract_next_position(ERR_TRCKR *err, char *range, BLOCK_INFO *blocks) {
	int res;
	static long int n = 0;
	static long int from = 0;
	static char *endp = NULL;
	static char digit_expected = 1;
	static char dash_allowed = 1;
	static char get_next_n = 1;
	static char *records = NULL;

	if (range == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (records == NULL) {
		records = range;
	}
	while (*records) {
		if (isspace(*records)) {
			res = KT_INVALID_CMD_PARAM;
			ERR_CATCH_MSG(err, res, "Error: List of positions must not contain whitespace. Use ',' and '-' as separators.");
		}
		if(!digit_expected) {
			/* Process either ',' or '-' as a separator. */
			digit_expected = 1;
			if (*records == ',') {
				dash_allowed = 1;
				records++;
				from = 0;
				get_next_n = 1;
				continue;
			} else if (*records == '-') {
				if (dash_allowed) {
					dash_allowed = 0;
					records++;
					from = n;
					get_next_n = 1;
					continue;
				} else {
					res = KT_INVALID_CMD_PARAM;
					ERR_CATCH_MSG(err, res, "Error: Positions must be represented by positive decimal integers, using a list of comma-separated ranges.");
				}
			} else {
				res = KT_INVALID_CMD_PARAM;
				ERR_CATCH_MSG(err, res, "Error: List of positions must be separated with ',' or '-'.");
			}
		} else {
			/* Get the next integer and interpret it as a single position or range of positions. */
			if (get_next_n) {
				n = strtol(records, &endp, 10);
				get_next_n = 0;
				if (endp == records) {
					res = KT_INVALID_CMD_PARAM;
					ERR_CATCH_MSG(err, res, "Error: Positions must be represented by positive decimal integers, using a list of comma-separated ranges.");
				}
			}
			if (n <= 0) {
				res = KT_INVALID_CMD_PARAM;
				ERR_CATCH_MSG(err, res, "Error: Positions must be represented by positive decimal integers, using a list of comma-separated ranges.");
			} else if (from == 0) {
				/* Add a single position. */
				res = add_position(err, n, blocks);
				if (res != KT_OK) goto cleanup;
				records = endp;
				digit_expected = 0;
				goto cleanup;
			} else if (from < n) {
				/* Add the next position in the range. */
				from++;
				res = add_position(err, from, blocks);
				if (res != KT_OK) goto cleanup;
				if (from < n) {
					goto cleanup;
				} else {
					records = endp;
					digit_expected = 0;
				}
			} else {
				res = KT_INVALID_CMD_PARAM;
				ERR_CATCH_MSG(err, res, "Error: List of positions must be given in strictly ascending order.");
			}
		}
	}

	/* Make sure the last processed character was a digit. */
	if(digit_expected) {
		res = KT_INVALID_CMD_PARAM;
		ERR_CATCH_MSG(err, res, "Error: Positions must be represented by positive decimal integers, using a list of comma-separated ranges.");
	}
	res = KT_OK;

cleanup:

	return res;
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

int update_extract_info(ERR_TRCKR *err, BLOCK_INFO *blocks, int isMetaRecordHash, KSI_DataHash *hash) {
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

	if (blocks->records && blocks->nofExtractPositionsFound == blocks->nofExtractPositions) {
		res = extract_next_position(err, blocks->records, blocks);
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

int add_record_hash_to_merkle_tree(KSI_CTX *ksi, ERR_TRCKR *err, BLOCK_INFO *blocks, int isMetaRecordHash, KSI_DataHash *hash) {
	int res;
	KSI_DataHash *lastHash = NULL;

	if (ksi == NULL || blocks == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Do not allow meta records to be extracted. */
	if (isMetaRecordHash) {
		blocks->nofTotalMetarecors++;
		blocks->nofMetaRecords++;
		blocks->nofTotalRecordHashes--;
	}

	res = calculate_new_leaf_hash(ksi, blocks, hash, isMetaRecordHash, &lastHash);
	if (res != KT_OK) goto cleanup;

	res = update_extract_info(err, blocks, isMetaRecordHash, hash);
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

int get_hash_of_logline(BLOCK_INFO *blocks, IO_FILES *files, KSI_DataHash **hash) {
	int res;
	KSI_DataHash *tmp = NULL;
	/* Maximum line size is 64K characters, without newline character. */
	char buf[0x10000 + 2];

	if (files == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (files->files.inLog) {
		if (fgets(buf, sizeof(buf), files->files.inLog) == NULL) {
			res = KT_IO_ERROR;
			goto cleanup;
		}
		res = KSI_DataHasher_reset(blocks->hasher);
		if (res != KSI_OK) goto cleanup;

		/* Last character (newline) is not used in hash calculation. */
		res = KSI_DataHasher_add(blocks->hasher, buf, strlen(buf) - 1);
		if (res != KSI_OK) goto cleanup;

		res = KSI_DataHasher_close(blocks->hasher, &tmp);
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

int get_hash_of_metarecord(BLOCK_INFO *blocks, KSI_TlvElement *tlv, KSI_DataHash **hash) {
	int res;
	KSI_DataHash *tmp = NULL;

	if (tlv == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_DataHasher_reset(blocks->hasher);
	if (res != KSI_OK) goto cleanup;

	/* The complete metarecord TLV us used in hash calculation. */
	res = KSI_DataHasher_add(blocks->hasher, tlv->ptr, tlv->ftlv.hdr_len + tlv->ftlv.dat_len);
	if (res != KSI_OK) goto cleanup;

	res = KSI_DataHasher_close(blocks->hasher, &tmp);
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
	KSI_TlvElement *el = NULL;
	size_t len;
	size_t i;
	size_t val = 0;
	unsigned char buf[0xffff + 4];


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

int tlv_element_get_hash(ERR_TRCKR *err, KSI_TlvElement *tlv, KSI_CTX *ksi, unsigned tag, KSI_DataHash **out) {
	int res;
	KSI_TlvElement *el = NULL;
	KSI_DataHash *hash = NULL;

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

int tlv_element_create_hash(KSI_DataHash *hash, unsigned tag, KSI_TlvElement **tlv) {
	int res;
	KSI_TlvElement *tmp = NULL;
	unsigned char *imprint = NULL;
	size_t length = 0;

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

int tlv_element_write_hash(KSI_DataHash *hash, unsigned tag, FILE *out) {
	int res;
	KSI_TlvElement *tlv = NULL;
	unsigned char buf[0xffff + 4];
	size_t len = 0;
	unsigned char *ptr = NULL;

	if (hash == NULL || out == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = tlv_element_create_hash(hash, tag, &tlv);
	if (res != KT_OK) goto cleanup;

	res = KSI_TlvElement_serialize(tlv, buf, sizeof(buf), &len, KSI_TLV_OPT_NO_MOVE);
	if (res != KSI_OK) goto cleanup;

	ptr = buf + sizeof(buf) - len;

	if (fwrite(ptr, 1, len, out) != len) {
		res = KT_IO_ERROR;
		goto cleanup;
	}

	res = KT_OK;

cleanup:

	KSI_TlvElement_free(tlv);
	return res;
}

static int format_hash_help(const char *helpLeft, const char *helpRight, char *bufLeft, char *bufRight, size_t bufLen) {
	int res;
	int len = 0;

	if (bufLeft == NULL || bufRight == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (helpLeft == NULL) helpLeft = "Computed hash: ";
	if (helpRight == NULL) helpRight = "Stored hash: ";

	len = strlen(helpLeft) > strlen(helpRight) ? strlen(helpLeft) : strlen(helpRight);

	if (len > bufLen - 1) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	sprintf(bufLeft, "%*s", len, helpLeft);
	sprintf(bufRight, "%*s", len, helpRight);
	res = KT_OK;

cleanup:

	return res;
}

int logksi_datahash_compare(ERR_TRCKR *err, KSI_DataHash *left, KSI_DataHash *right, const char *helpLeft, const char *helpRight) {
	int res;
	KSI_HashAlgorithm leftId;
	KSI_HashAlgorithm rightId;
	char bufLeft[256];
	char bufRight[256];

	if (left == NULL || right == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (!KSI_DataHash_equals(left, right)) {
		res = KT_VERIFICATION_FAILURE;
		print_progressResult(res);
		if (KSI_DataHash_getHashAlg(left, &leftId) == KSI_OK &&
			KSI_DataHash_getHashAlg(right, &rightId) == KSI_OK &&
			leftId != rightId) {
			ERR_TRCKR_ADD(err, res, "Error: Hash algorithm in block header does not match the hash algorithm that was used for building the tree.");
		}

		if(format_hash_help(helpLeft, helpRight, bufLeft, bufRight, 256) != KT_OK) goto cleanup;

		OBJPRINT_Hash(left, bufLeft, print_debug);
		OBJPRINT_Hash(right, bufRight, print_debug);
		goto cleanup;
	}

	res = KT_OK;

cleanup:

	return res;
}

int tlv_element_parse_and_check_sub_elements(ERR_TRCKR *err, KSI_CTX *ksi, unsigned char *dat, size_t dat_len, size_t hdr_len, KSI_TlvElement **out) {
	int res;
	KSI_TlvElement *tmp = NULL;

	if (dat == NULL || out == NULL) {
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

static int process_magic_number(PARAM_SET* set, ERR_TRCKR *err, BLOCK_INFO *blocks, IO_FILES *files) {
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

	print_progressDescExtended(set, 0, DEBUG_LEVEL_3, "Processing magic number... ");

	res = KT_INVALID_INPUT_FORMAT;

	if (files->files.partsBlk) {
		if (find_header_in_file(files->files.partsBlk, blocksFileHeaders, SOF_ARRAY(blocksFileHeaders)) == SOF_ARRAY(blocksFileHeaders)) {
			ERR_CATCH_MSG(err, res, "Error: Unable to parse blocks file %s, magic number not found.", files->internal.partsBlk);
		}
		if (find_header_in_file(files->files.partsSig, signaturesFileHeaders, SOF_ARRAY(signaturesFileHeaders)) == SOF_ARRAY(signaturesFileHeaders)) {
			ERR_CATCH_MSG(err, res, "Error: Unable to parse signature file %s, magic number not found.", files->internal.partsSig);
		}
		blocks->version = LOGSIG12;
	} else {
		blocks->version = find_header_in_file(files->files.inSig, logSignatureHeaders, SOF_ARRAY(logSignatureHeaders));
		if (blocks->version == SOF_ARRAY(logSignatureHeaders)) {
			ERR_CATCH_MSG(err, res, "Error: Unable to parse signature file %s, magic number not found.", files->internal.inSig);
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

	print_progressResultExtended(set, DEBUG_LEVEL_3, res);
	return res;
}

int continue_on_hash_fail(int result, PARAM_SET *set, BLOCK_INFO *blocks, KSI_DataHash *computed, KSI_DataHash *stored, KSI_DataHash **replacement) {
	int res = result;

	if (set == NULL || blocks == NULL || computed == NULL || stored == NULL || replacement == NULL) {
		goto cleanup;
	}

	if (res == KT_OK) {
		*replacement = KSI_DataHash_ref(computed);
	} else {
		blocks->nofHashFails++;
		if (PARAM_SET_isSetByName(set, "use-computed-hash-on-fail")) {
			print_debug("Using computed hash to continue.\n");
			*replacement = KSI_DataHash_ref(computed);
			res = KT_OK;
		} else if (PARAM_SET_isSetByName(set, "use-stored-hash-on-fail")) {
			*replacement = KSI_DataHash_ref(stored);
			print_debug("Using stored hash to continue.\n");
			res = KT_OK;
		} else {
			*replacement = KSI_DataHash_ref(computed);
		}
	}

cleanup:

	return res;
}

static int finalize_block(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	char *dummy = NULL;
	int checkSigkTime = 0;
	int warnSameSigTime = 0;

	if (set == NULL || err == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (blocks->blockNo > blocks->sigNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: block signature data missing.", blocks->blockNo);
	}

	res = PARAM_SET_getStr(set, "ignore-desc-block-time", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &dummy);
	checkSigkTime = !(res == PST_PARAMETER_NOT_FOUND || res == PST_OK);

	res = PARAM_SET_getStr(set, "warn-same-block-time", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &dummy);
	warnSameSigTime = res == PST_OK;

	/* Check if previous signature is older than the current one. If not, rise the error. */
	if (checkSigkTime || warnSameSigTime) {
		char buf[256];
		char strT0[256];
		char strT1[256];
		int logStdin = files->internal.inLog == NULL;
		char *currentLogFile = logStdin ? "stdin" : files->internal.inLog;
		char *previousLogFile = files->previousLogFile;


		/* When sigTime is 0 it is the first signature and there is nothing to check. */
		if (blocks->sigTime_0 > 0) {

			uint64_toDateString(blocks->sigTime_0, strT0, sizeof(strT0));
			uint64_toDateString(blocks->sigTime_1, strT1, sizeof(strT1));

			print_progressDescExtended(set, 0, DEBUG_LEVEL_3, "Block no. %3zu: checking signing time with previous block... ", blocks->blockNo);

			if (blocks->sigTime_0 > blocks->sigTime_1 && !PARAM_SET_isSetByName(set, "ignore-desc-block-time")) {
				print_progressResultExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, 1);
				print_progressResultExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_1, 1);
				blocks->errSignTime = 1;

				if (blocks->blockNo == 1) {
					PST_snprintf(blocks->errorBuf, sizeof(blocks->errorBuf), "Error: Last block  %s from file '%s' is more recent than\n"
						                                                     "       first block %s from file '%s'\n", strT0, previousLogFile, strT1, currentLogFile);
				} else {
					PST_snprintf(blocks->errorBuf, sizeof(blocks->errorBuf), "Error: Block no. %3zu %s in %s '%s' is more recent than\n"
						                                                     "       block no. %3zu %s\n", blocks->blockNo - 1, strT0, (logStdin ? "log from" : "file"), currentLogFile, blocks->blockNo, strT1);
				}

				blocks->nofTotalFailedBlocks++;
				print_progressResultExtended(set, DEBUG_LEVEL_3, res);
			}

			if (blocks->sigTime_0 == blocks->sigTime_1 && PARAM_SET_isSetByName(set, "warn-same-block-time")) {
				blocks->warningSignatureSameTime = 1;

				if (blocks->blockNo == 1) {
					PST_snprintf(blocks->warnBuf, sizeof(blocks->warnBuf), "Warning: Last block from file      '%s'\n"
						                                                   "         and first block from file '%s'\n"
																		   "         has same signing time %s.\n", previousLogFile, currentLogFile, uint64_toDateString(blocks->sigTime_1, buf, sizeof(buf)));
				} else {
					PST_snprintf(blocks->warnBuf, sizeof(blocks->warnBuf), "Warning: Block no. %3zu and %3zu in %s '%s' has same signing time %s.\n" , blocks->blockNo - 1, blocks->blockNo, (logStdin ? "log from" : "file"), currentLogFile, strT1);
				}
			}
		}

		print_progressResultExtended(set, DEBUG_LEVEL_2, 0);


		if (blocks->errSignTime && blocks->errorBuf[0] != '\0') {
			print_errors("\n%s\n", blocks->errorBuf);
			blocks->errorBuf[0] = '\0';
		}

		/* As this type of warning is explictly enabled it must be seen without -d flag and it is printed with error printer. */
		if (blocks->warningSignatureSameTime) {
			print_errors("%s", blocks->warnBuf);
			blocks->warningSignatureSameTime = 0;
		}
	}

	print_progressResultExtended(set, DEBUG_LEVEL_3, 0);
	print_progressResultExtended(set, DEBUG_LEVEL_2, 0);

	if (blocks->blockNo > 0) {
		char strT1[256] = "<not signed>";
		char strExtTo[256] = "<null>";
		char inHash[256] = "<null>";
		char outHash[256] = "<null>";
		int isSignTask = 0;
		int isExtractTask = 0;
		int isExtendTask = 0;
		int shortIndentation = 13;
		int longIndentation = 29;

		if (blocks->sigTime_1 > 0) {
			uint64_toDateString(blocks->sigTime_1, strT1, sizeof(strT1));
		}

		if (blocks->extendedToTime > 0) {
			uint64_toDateString(blocks->extendedToTime, strExtTo, sizeof(strExtTo));
		}

		LOGKSI_DataHash_toString(blocks->inputHash, inHash, sizeof(inHash));
		LOGKSI_DataHash_toString(blocks->prevLeaf, outHash, sizeof(outHash));

		isSignTask = blocks->taskId == TASK_SIGN;
		isExtractTask = blocks->taskId == TASK_EXTRACT;
		isExtendTask = blocks->taskId == TASK_EXTEND;

		if ((isSignTask && blocks->curBlockJustReSigned) || (isExtractTask && blocks->nofExtractPositionsInBlock) || (!isSignTask && !isExtractTask)) {
			print_debugExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, "Summary of block %zu:\n", blocks->blockNo);

			if (isSignTask || isExtractTask || isExtendTask) {
				shortIndentation = longIndentation;
			}

			if (!blocks->curBlockNotSigned) {
				print_debugExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", shortIndentation, "Sig time:", strT1);
				if (blocks->extendedToTime > 0) print_debugExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", shortIndentation, "Extended to:", strExtTo);
			} else {
				print_debugExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", shortIndentation, "Sig time:", "<unsigned>");
			}

			if (!isSignTask && !isExtractTask && !isExtendTask) {
				print_debugExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", shortIndentation, "Input hash:", inHash);
				print_debugExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", shortIndentation, "Output hash:", outHash);
			}

			/* Print line numbers. */
			if (blocks->firstLineInBlock < blocks->nofTotalRecordHashes) {
				print_debugExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%zu - %zu (%zu)\n", longIndentation, "Lines:", blocks->firstLineInBlock, blocks->nofTotalRecordHashes, blocks->recordCount - blocks->nofMetaRecords);
			} else if (blocks->recordCount == 1 && blocks->nofMetaRecords == 1) {
				print_debugExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*sn/a\n", longIndentation, "Line:");
			} else if (blocks->firstLineInBlock == blocks->nofTotalRecordHashes) {
				print_debugExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%zu\n", longIndentation, "Line:", blocks->firstLineInBlock);
			} else {
				print_debugExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s<unknown>\n", longIndentation, "Line:");
			}

			if (blocks->nofMetaRecords > 0) print_debugExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%zu\n", longIndentation, "Count of meta-records:", blocks->nofMetaRecords);
			if (blocks->nofHashFails > 0) print_debugExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%zu\n", longIndentation, "Count of hash failures:", blocks->nofHashFails);
			if (blocks->nofExtractPositionsInBlock > 0) print_debugExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%zu\n", longIndentation, "Records extracted:", blocks->nofExtractPositionsInBlock);

			print_debugExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, "\n", outHash); /* Meta records not included. */
		}
	}

	/* Print Output hash of previous block. */
	if (blocks->prevLeaf != NULL && blocks->taskId == TASK_VERIFY) {
		char buf[256];
		LOGKSI_DataHash_toString(blocks->prevLeaf, buf, sizeof(buf));
		print_debugExtended(set, DEBUG_LEVEL_3, "Block no. %3zu: output hash: %s.\n", blocks->blockNo, buf);
	}

	if (blocks->unsignedRootHash) {
		print_debugExtended(set, DEBUG_LEVEL_3, "Warning: Block no. %3zu: unsigned root hash found.\n", blocks->blockNo);
	}

	if (blocks->finalTreeHashesNone) {
		print_debugExtended(set, DEBUG_LEVEL_3, "Block no. %3zu: Warning: all final tree hashes are missing.\n", blocks->blockNo);
		blocks->warningTreeHashes = 1;
	} else if (blocks->finalTreeHashesAll) {
		print_debugExtended(set, DEBUG_LEVEL_3, "Block no. %3zu: all final tree hashes are present.\n", blocks->blockNo);
	}

	res = KT_OK;

cleanup:

	return res;
}

static int init_next_block(BLOCK_INFO *blocks) {
	if (blocks == NULL) return KT_INVALID_ARGUMENT;

	blocks->blockNo++;
	blocks->recordCount = 0;
	blocks->nofRecordHashes = 0;
	blocks->nofTreeHashes = 0;
	blocks->finalTreeHashesSome = 0;
	blocks->finalTreeHashesNone = 0;
	blocks->finalTreeHashesAll = 0;
	blocks->finalTreeHashesLeaf = 0;
	blocks->unsignedRootHash = 0;
	blocks->keepRecordHashes = 0;
	blocks->keepTreeHashes = 0;
	blocks->firstLineInBlock = blocks->nofTotalRecordHashes + 1;
	blocks->nofMetaRecords = 0;
	blocks->curBlockNotSigned = 0;
	blocks->curBlockJustReSigned = 0;

	/* Previous and current (next) signature time. Note that 0 indicates not set. */
	blocks->sigTime_0 = blocks->sigTime_1;
	blocks->sigTime_1 = 0;
	blocks->extendedToTime = 0;
	return KT_OK;
}


static int process_block_header(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_DataHash *hash = NULL;
	KSI_DataHash *replacement = NULL;
	unsigned char i = 0;
	KSI_TlvElement *tlv = NULL;
	size_t algo;
	size_t j;
	KSI_DataHasher *hasher = NULL;

	if (err == NULL || ksi == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDescExtended(set, 0, DEBUG_LEVEL_3, "Block no. %3zu: processing block header... ", blocks->blockNo);



	res = tlv_element_parse_and_check_sub_elements(err, ksi, blocks->ftlv_raw, blocks->ftlv_len, blocks->ftlv.hdr_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse block header as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &algo);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing hash algorithm in block header.", blocks->blockNo);

	if (blocks->hasher == NULL || blocks->hashAlgo != algo) {
		res = KSI_DataHasher_open(ksi, algo, &hasher);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: could not open datahasher.", blocks->blockNo);
	}

	KSI_OctetString_free(blocks->randomSeed);
	blocks->randomSeed = NULL;
	res = tlv_get_octet_string(tlv, ksi, 0x02, &blocks->randomSeed);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing random seed in block header.", blocks->blockNo);

	res = tlv_element_get_hash(err, tlv, ksi, 0x03, &hash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse last hash of previous block.", blocks->blockNo);

	KSI_DataHash_free(blocks->inputHash);
	blocks->inputHash = KSI_DataHash_ref(hash);

	if (blocks->prevLeaf != NULL) {
		res = logksi_datahash_compare(err, blocks->prevLeaf, hash, "Last hash computed from previous block data: ", "Last hash stored in current block header: ");
		res = continue_on_hash_fail(res, set, blocks, blocks->prevLeaf, hash, &replacement);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: last hashes of previous block not equal.", blocks->blockNo);
	} else {
		replacement = KSI_DataHash_ref(hash);
	}

	if (files->files.outSig) {
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->files.outSig) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to copy block header.", blocks->blockNo);
		}
	}

	blocks->hashAlgo = algo;
	if (hasher) {
		KSI_DataHasher_free(blocks->hasher);
		blocks->hasher = hasher;
		hasher = NULL;
	}
	KSI_DataHash_free(blocks->prevLeaf);
	blocks->prevLeaf = replacement;

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
	free(blocks->metaRecord);
	blocks->metaRecord = NULL;

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

	print_progressResultExtended(set, DEBUG_LEVEL_3, res);
	KSI_DataHash_free(hash);
	KSI_TlvElement_free(tlv);
	KSI_DataHasher_free(hasher);
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
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: record hash without preceding block header found.", blocks->blockNo + 1);
	}
	/* Check if record hashes are present for previous records. */
	if (blocks->keepRecordHashes == 0 && blocks->nofRecordHashes > 0) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record hash for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));
	}
	/* Check if all tree hashes are present for previous records. */
	if (blocks->keepTreeHashes && blocks->nofTreeHashes != max_tree_hashes(blocks->nofRecordHashes)) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing tree hash(es) for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));
	}

	res = KT_OK;

cleanup:

	return res;
}

static int process_record_hash(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_DataHash *recordHash = NULL;
	KSI_DataHash *hash = NULL;
	KSI_DataHash *replacement = NULL;

	if (err == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	res = is_record_hash_expected(err, blocks);
	if (res != KT_OK) goto cleanup;

	blocks->keepRecordHashes = 1;
	blocks->nofRecordHashes++;

	res = LOGKSI_DataHash_fromImprint(err, ksi, blocks->ftlv_raw + blocks->ftlv.hdr_len, blocks->ftlv.dat_len, &recordHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse hash of logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));

	if (blocks->metarecordHash != NULL) {
		/* This is a metarecord hash. */
		res = logksi_datahash_compare(err, blocks->metarecordHash, recordHash, "Metarecord hash computed from metarecord: ", "Metarecord hash stored in log signature file: ");
		res = continue_on_hash_fail(res, set, blocks, blocks->metarecordHash, recordHash, &replacement);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: metarecord hashes not equal.", blocks->blockNo);

		res = add_record_hash_to_merkle_tree(ksi, err, blocks, 1, replacement);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);

		KSI_DataHash_free(blocks->metarecordHash);
		blocks->metarecordHash = NULL;
	} else {
		/* This is a logline record hash. */
		if (files->files.inLog) {
			res = get_hash_of_logline(blocks, files, &hash);
			if (res == KT_IO_ERROR) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: record hash no. %zu does not have a matching logline, end of logfile reached.", blocks->blockNo, get_nof_lines(blocks));
			} else {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate hash of logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));
			}

			res = logksi_datahash_compare(err, hash, recordHash, "Record hash computed from logline: ", "Record hash stored in log signature file: ");
			if (res != KT_OK) {
				print_debug("Failed to verify logline no. %zu: %s", get_nof_lines(blocks), blocks->logLine);
			}
			res = continue_on_hash_fail(res, set, blocks, hash, recordHash, &replacement);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: record hashes not equal for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));
		} else {
			replacement = KSI_DataHash_ref(recordHash);
		}

		res = add_record_hash_to_merkle_tree(ksi, err, blocks, 0, replacement);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add hash to Merkle tree.", blocks->blockNo);
	}

	if (files->files.outSig) {
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->files.outSig) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to copy record hash.", blocks->blockNo);
		}
	}
	res = KT_OK;

cleanup:

	KSI_DataHash_free(replacement);
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

static size_t nof_unverified_hashes(BLOCK_INFO *blocks) {
	size_t count = 0;
	size_t i;

	for (i = 0; i < blocks->treeHeight; i++) {
		if (blocks->notVerified[i]) {
			count++;
		}
	}

	return count;
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
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: tree hash without preceding block header found.", blocks->blockNo + 1);
	}
	/* Check if tree hashes are present for previous records. */
	if (blocks->keepTreeHashes == 0 && blocks->nofRecordHashes > 1) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing tree hash for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks) - 1);
	}
	/* Check if all record hashes are present for previous records. */
	if (blocks->keepRecordHashes && blocks->nofTreeHashes == max_tree_hashes(blocks->nofRecordHashes)) {
		/* All the tree hashes that can be computed from the received record hashes have been received.
		 * However, another tree hash was just received, so either the preceding record hash is missing or
		 * the tree hash is used in finalizing the unbalanced tree. */
		if (blocks->balanced) {
			/* The tree is balanced, so no finalizing is needed. Thus the tree hash is unexpected, probably due to a missing record hash. */
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record hash for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks) + 1);
		} else if (blocks->metarecordHash) {
			/* A metarecord hash is missing while the tree hash for the metarecord is present. */
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record hash for metarecord with index %zu.", blocks->blockNo, blocks->nofRecordHashes);
		} else {
			/* Assuming that no record hashes are missing, let's start the finalizing process. */
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
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unexpected final tree hash no. %zu.", blocks->blockNo, blocks->nofTreeHashes + 1);
	}

	res = KT_OK;

cleanup:

	return res;
}

static int process_tree_hash(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_DataHash *treeHash = NULL;
	KSI_DataHash *recordHash = NULL;
	KSI_DataHash *tmpRoot = NULL;
	KSI_DataHash *root = NULL;
	KSI_DataHash *replacement = NULL;
	unsigned char i;

	if (err == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	res = is_tree_hash_expected(err, blocks);
	if (res != KT_OK) goto cleanup;

	blocks->keepTreeHashes = 1;
	blocks->nofTreeHashes++;

	res = LOGKSI_DataHash_fromImprint(err, ksi, blocks->ftlv_raw + blocks->ftlv.hdr_len, blocks->ftlv.dat_len, &treeHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse tree hash.", blocks->blockNo);

	if (files->files.outSig) {
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->files.outSig) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to copy tree hash.", blocks->blockNo);
		}
	}

	if (!blocks->finalTreeHashesSome) {
		/* If the block contains tree hashes, but not record hashes:
		 * Calculate missing record hashes from the records in the logfile and
		 * build the Merkle tree according to the number of tree hashes encountered. */
		if (blocks->keepRecordHashes == 0 && blocks->nofTreeHashes > max_tree_hashes(blocks->nofRecordHashes)) {
			/* If the block is closed prematurely with a metarecord, process the current tree hash as a mandatory leaf hash.
			 * Subsequent tree hashes are either mandatory tree hashes corresponding to the metarecord hash or optional final tree hashes. */
			if (blocks->metarecordHash) {
				blocks->finalTreeHashesLeaf = 1;
			}
			blocks->nofRecordHashes++;
			if (files->files.inLog) {
				if (blocks->metarecordHash) {
					res = add_record_hash_to_merkle_tree(ksi, err, blocks, 1, blocks->metarecordHash);
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);

					KSI_DataHash_free(blocks->metarecordHash);
					blocks->metarecordHash = NULL;
				} else {
					res = get_hash_of_logline(blocks, files, &recordHash);
					if (res == KT_IO_ERROR) {
						ERR_CATCH_MSG(err, res, "Error: Block no. %zu: tree hash does not have a matching logline no. %zu, end of logfile reached.", blocks->blockNo, get_nof_lines(blocks));
					} else {
						ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate hash of logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));
					}
					res = add_record_hash_to_merkle_tree(ksi, err, blocks, 0, recordHash);
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add record hash to Merkle tree.", blocks->blockNo);
					KSI_DataHash_free(recordHash);
					recordHash = NULL;
				}
			} else {
				/* No log file available so build the Merkle tree from tree hashes alone. */
				res = add_leaf_hash_to_merkle_tree(ksi, blocks, treeHash, 0);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add leaf hash to Merkle tree.", blocks->blockNo);
			}
		}
		if (blocks->nofRecordHashes) {
			/* Find the corresponding tree hash from the Merkle tree. */
			for (i = 0; i < blocks->treeHeight; i++) {
				if (blocks->notVerified[i] != NULL) break;
			}
			if (i == blocks->treeHeight) {
				res = KT_VERIFICATION_FAILURE;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unexpected tree hash for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));
			}

			res = logksi_datahash_compare(err, blocks->notVerified[i], treeHash, "Tree hash computed from record hashes: ", "Tree hash stored in log signature file: ");
			res = continue_on_hash_fail(res, set, blocks, blocks->notVerified[i], treeHash, &replacement);
			if (blocks->keepRecordHashes) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: tree hashes not equal for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));
			} else {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: tree hashes not equal.", blocks->blockNo);
			}

			KSI_DataHash_free(blocks->notVerified[i]);
			blocks->notVerified[i] = NULL;
		}
		if (blocks->finalTreeHashesLeaf && !nof_unverified_hashes(blocks)) {
			/* This was the last mandatory tree hash. From this point forward all tree hashes must be interpreted as optional final tree hashes. */
			blocks->finalTreeHashesSome = 1;
			for (i = 0; i < blocks->treeHeight; i++) {
				blocks->notVerified[i] = KSI_DataHash_ref(blocks->MerkleTree[i]);
			}
		}
	} else {
		if (blocks->nofRecordHashes) {
			print_progressResultExtended(set, DEBUG_LEVEL_3, res);
			print_progressDescExtended(set, 0, DEBUG_LEVEL_3, "Block no. %3zu: interpreting tree hash no. %3zu as a final hash... ", blocks->blockNo, blocks->nofTreeHashes);
			/* Find the corresponding tree hash from the Merkle tree. */
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
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unexpected tree hash for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));
			}

			res = logksi_datahash_compare(err, blocks->notVerified[i], treeHash, "Tree hash computed from record hashes: ", "Tree hash stored in log signature file: ");
			res = continue_on_hash_fail(res, set, blocks, blocks->notVerified[i], treeHash, &replacement);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: tree hashes not equal for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));
		}
	}

	res = KT_OK;

cleanup:

	print_progressResultExtended(set, DEBUG_LEVEL_3, res);
	KSI_DataHash_free(treeHash);
	KSI_DataHash_free(recordHash);
	KSI_DataHash_free(tmpRoot);
	KSI_DataHash_free(root);
	KSI_DataHash_free(replacement);
	return res;
}

static int process_metarecord(PARAM_SET* set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlv = NULL;
	size_t metarecord_index = 0;

	if (err == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	res = tlv_element_parse_and_check_sub_elements(err, ksi, blocks->ftlv_raw, blocks->ftlv_len, blocks->ftlv.hdr_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse metarecord as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &metarecord_index);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing metarecord index.", blocks->blockNo);

	if (files->files.inLog) {
		/* If the block contains metarecords but not the corresponding record hashes:
		 * Calculate missing metarecord hash from the last metarecord and
		 * build the Merkle tree according to the record count in the signature data. */
		if (blocks->metarecordHash != NULL) {
			/* Add the previous metarecord to Merkle tree. */
			blocks->nofRecordHashes++;
			res = add_record_hash_to_merkle_tree(ksi, err, blocks, 1, blocks->metarecordHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);
		}

		while (blocks->nofRecordHashes < metarecord_index) {
			blocks->nofRecordHashes++;
			res = get_hash_of_logline(blocks, files, &hash);
			if (res == KT_IO_ERROR) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: at least %zu loglines expected up to metarecord index %zu, end of logfile reached.", blocks->blockNo, get_nof_lines(blocks), metarecord_index);
			} else {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate hash of logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));
			}
			res = add_record_hash_to_merkle_tree(ksi, err, blocks, 0, hash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);
			KSI_DataHash_free(hash);
			hash = NULL;
		}
	}

	KSI_DataHash_free(blocks->metarecordHash);
	blocks->metarecordHash = NULL;
	res = get_hash_of_metarecord(blocks, tlv, &blocks->metarecordHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate metarecord hash with index %zu.", blocks->blockNo, metarecord_index);

	if (files->files.outSig) {
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->files.outSig) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to copy metarecord hash.", blocks->blockNo);
		}
	}

	res = KT_OK;

cleanup:

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
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record hash for metarecord with index %zu.", blocks->blockNo, blocks->nofRecordHashes);
		}
		/* Check if all record hashes are present in the current block. */
		if (blocks->nofRecordHashes < blocks->recordCount) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record hash for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks) + 1);
		}
	}

	if (blocks->keepTreeHashes) {
		if (!blocks->keepRecordHashes && !blocks->balanced && !blocks->finalTreeHashesSome) {
			/* If LOGSIG12 format is used, metarecords are mandatory for closing unbalanced blocks. */
			if (blocks->version == LOGSIG12) {
				res = KT_VERIFICATION_FAILURE;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete block is closed without a metarecord.", blocks->blockNo);
			}
		}
		/* Check if all mandatory tree hashes are present in the current block. */
		if (blocks->nofTreeHashes < maxTreeHashes) {
			res = KT_VERIFICATION_FAILURE;
			if (blocks->metaRecord) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing tree hash(es) for metarecord with index %zu.", blocks->blockNo, blocks->nofRecordHashes - 1);
			} else {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing tree hash(es) for logline no. %zu.", blocks->blockNo, blocks->recordCount + blocks->nofTotalRecordHashes);
			}
		}
		/* Check if the block contains too few final tree hashes. */
		if (blocks->nofTreeHashes < maxTreeHashes + maxFinalHashes) {
			/* Check if none of the final tree hashes have yet been received. (Final tree hashes must all be present or all missing.) */
			if (blocks->nofTreeHashes == maxTreeHashes) {
				/* Check if there is reason to expect final tree hashes. */
				if (blocks->finalTreeHashesSome || blocks->keepRecordHashes) {
					/* All final tree hashes are missing, but at least they are being expected -> this is OK and can be repaired. */
					blocks->finalTreeHashesNone = 1;
				} else {
					/* If LOGSIG12 format is used, metarecords are mandatory for closing unbalanced blocks. */
					if (blocks->version == LOGSIG12) {
						/* All of the final tree hashes are missing, but they are not being expected either (e.g. missing metarecord). This should never happen. */
						res = KT_VERIFICATION_FAILURE;
						ERR_CATCH_MSG(err, res, "Error: Block no. %zu: all final tree hashes are missing and block is closed without a metarecord.", blocks->blockNo);
					}
				}
			} else {
				/* If some final tree hashes are present, they must all be present. */
				res = KT_VERIFICATION_FAILURE;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: found %zu final tree hashes instead of %zu.", blocks->blockNo, blocks->nofTreeHashes - maxTreeHashes, maxFinalHashes);
			}
		}
		/* Check if the block contains too many optional tree hashes. */
		if (blocks->nofTreeHashes > maxTreeHashes + maxFinalHashes) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: found %zu final tree hashes instead of %zu.", blocks->blockNo, blocks->nofTreeHashes - maxTreeHashes, maxFinalHashes);
		}
		if (blocks->nofTreeHashes == maxTreeHashes + maxFinalHashes) {
			blocks->finalTreeHashesAll = 1;
		}
	}

	res = KT_OK;

cleanup:

	return res;
}

static int process_block_signature(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_PublicationsFile *pubFile, SIGNATURE_PROCESSORS *processors, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *verificationResult = NULL;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvSig = NULL;
	KSI_TlvElement *tlvRfc3161 = NULL;
	KSI_TlvElement *recChain = NULL;
	KSI_TlvElement *hashStep = NULL;
	KSI_Integer *t0 = NULL;
	size_t j;

	KSI_VerificationContext_init(&context, ksi);

	if (set == NULL || err == NULL || ksi == NULL || processors == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	blocks->sigNo++;
	if (blocks->sigNo > blocks->blockNo) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: block signature data without preceding block header found.", blocks->sigNo);
	}

	print_progressDescExtended(set, 0, DEBUG_LEVEL_3, "Block no. %3zu: processing block signature data... ", blocks->blockNo);

	res = tlv_element_parse_and_check_sub_elements(err, ksi, blocks->ftlv_raw, blocks->ftlv_len, blocks->ftlv.hdr_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse block signature as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &blocks->recordCount);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record count in block signature.", blocks->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x906, &tlvRfc3161);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract RFC3161 element in block signature.", blocks->blockNo);

	if (tlvRfc3161 != NULL) {
		/* Convert the RFC3161 timestamp into KSI signature and replace it in the TLV. */
		res = convert_signature(ksi, tlvRfc3161->ptr + tlvRfc3161->ftlv.hdr_len, tlvRfc3161->ftlv.dat_len, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to convert RFC3161 element in block signature.", blocks->blockNo);

		res = KSI_TlvElement_removeElement(tlv, 0x906, NULL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to remove RFC3161 timestamp from block signature.", blocks->blockNo);
		res = tlv_element_set_signature(tlv, ksi, 0x905, sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to insert KSI signature in block signature.", blocks->blockNo);
		KSI_Signature_free(sig);
		sig = NULL;

		blocks->warningLegacy = 1;
	}
	res = KSI_TlvElement_getElement(tlv, 0x905, &tlvSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract KSI signature element in block signature.", blocks->blockNo);

	if (tlvSig == NULL) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing KSI signature in block signature.", blocks->blockNo);
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
			res = add_record_hash_to_merkle_tree(ksi, err, blocks, 1, blocks->metarecordHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);
		}

		/* If the block contains neither record hashes nor tree hashes:
		 * Calculate missing record hashes from the records in the logfile and
		 * build the Merkle tree according to the record count in the signature data. */
		if (blocks->keepRecordHashes == 0 && blocks->keepTreeHashes == 0) {
			while (blocks->nofRecordHashes < blocks->recordCount) {
				blocks->nofRecordHashes++;
				res = get_hash_of_logline(blocks, files, &hash);
				if (res == KT_IO_ERROR) {
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: at least %zu loglines expected, end of logfile reached.", blocks->blockNo, get_nof_lines(blocks));
				} else {
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate hash of logline no. %zu.", blocks->blockNo, blocks->nofRecordHashes);
				}
				res = add_record_hash_to_merkle_tree(ksi, err, blocks, 0, hash);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add hash to Merkle tree.", blocks->blockNo);
				KSI_DataHash_free(hash);
				hash = NULL;
			}
		}
	}

	/* If no record hashes were computed or encountered, previous leaf hashes must not be compared. */
	if (blocks->nofRecordHashes == 0) {
		KSI_DataHash_free(blocks->prevLeaf);
		blocks->prevLeaf = NULL;
	}

	/* If we have any record hashes directly from log signature file or indirectly from log file,
	 * their count must match the record count in block signature. */
	if (blocks->nofRecordHashes && blocks->nofRecordHashes != blocks->recordCount) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: expected %zu record hashes, but found %zu.", blocks->blockNo, blocks->recordCount, blocks->nofRecordHashes);
	}
	print_progressResultExtended(set, DEBUG_LEVEL_3, res);


	blocks->nofTotalRecordHashes += blocks->nofRecordHashes;

	if (blocks->firstLineInBlock < blocks->nofTotalRecordHashes) {
		print_debugExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Lines processed %zu - %zu (%zu)\n", blocks->blockNo, blocks->firstLineInBlock, blocks->nofTotalRecordHashes, blocks->recordCount - blocks->nofMetaRecords);
	} else if (blocks->recordCount == 1 && blocks->nofMetaRecords == 1) {
		print_debugExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Line processed n/a\n", blocks->blockNo);
	} else if (blocks->firstLineInBlock == blocks->nofTotalRecordHashes) {
		print_debugExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Line processed %zu\n", blocks->blockNo,  blocks->firstLineInBlock);
	} else {
		print_debugExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Line processed <unknown>\n", blocks->blockNo);
	}


	print_progressDescExtended(set, 1, DEBUG_LEVEL_3, "Block no. %3zu: verifying KSI signature... ", blocks->blockNo);


	res = calculate_root_hash(ksi, blocks, (KSI_DataHash**)&context.documentHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get root hash for verification.", blocks->blockNo);

	context.docAggrLevel = get_aggregation_level(blocks);

	if (processors->verify_signature) {
		res = LOGKSI_Signature_parseWithPolicy(err, ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_EMPTY, NULL, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature.", blocks->blockNo);

		res = processors->verify_signature(set, err, ksi, blocks, files, sig, (KSI_DataHash*)context.documentHash, context.docAggrLevel, &verificationResult);
		if (res != KSI_OK) {
			blocks->nofTotalFailedBlocks++;
			ERR_TRCKR_ADD(err, res, "Error: Block no. %zu: KSI signature verification failed.", blocks->blockNo);
			goto cleanup;
		}
		/* TODO: add dumping of verification results. */
		KSI_PolicyVerificationResult_free(verificationResult);
		verificationResult = NULL;

	} else if (processors->extend_signature) {
		time_t t = 0;

		res = LOGKSI_Signature_parseWithPolicy(err, ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_INTERNAL, &context, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature.", blocks->blockNo);

		print_progressResultExtended(set, DEBUG_LEVEL_3, res);

		res = processors->extend_signature(set, err, ksi, blocks, files, sig, pubFile, &context, &ext);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extend KSI signature.", blocks->blockNo);

		res = KSI_Signature_getPublicationInfo(ext, NULL, NULL, &t, NULL, NULL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get publication time from KSI signature.", blocks->blockNo);

		blocks->extendedToTime = t;

		res = tlv_element_set_signature(tlv, ksi, 0x905, ext);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize extended KSI signature.", blocks->blockNo);

		res = KSI_TlvElement_serialize(tlv, blocks->ftlv_raw, SOF_FTLV_BUFFER, &blocks->ftlv_len, 0);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize extended block signature.", blocks->blockNo);

		if (blocks->warningLegacy) {
			int convertLegacy = PARAM_SET_isSetByName(set, "enable-rfc3161-conversion");

			if (files->internal.bOverwrite && !convertLegacy) {
				res = KT_RFC3161_EXT_IMPOSSIBLE;
				ERR_CATCH_MSG(err, res, "Error: Overwriting of legacy log signature file not enabled. Run 'logksi extend' with '--enable-rfc3161-conversion' to convert RFC3161 timestamps to KSI signatures.");
			}
			blocks->warningLegacy = 0;
		}
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->files.outSig) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to write extended signature to extended log signature file.", blocks->blockNo);
		}

		KSI_DataHash_free((KSI_DataHash*)context.documentHash);
		context.documentHash = NULL;
		KSI_VerificationContext_clean(&context);
	} else if (processors->extract_signature) {
		res = LOGKSI_Signature_parseWithPolicy(err, ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_INTERNAL, &context, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature.", blocks->blockNo);

		if (blocks->nofExtractPositionsInBlock) {
			if (fwrite(tlvSig->ptr, 1, tlvSig->ftlv.dat_len + tlvSig->ftlv.hdr_len, files->files.outProof) != tlvSig->ftlv.dat_len + tlvSig->ftlv.hdr_len) {
				res = KT_IO_ERROR;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to write KSI signature to integrity proof file.", blocks->blockNo);
			}
		}


		for (j = 0; j < blocks->nofExtractPositionsInBlock; j++) {
			unsigned char buf[0xFFFF + 4];
			size_t len = 0;
			size_t i;

			if (blocks->extractInfo[j].extractOffset && blocks->extractInfo[j].extractOffset <= blocks->nofRecordHashes) {
				size_t rowNumber = blocks->nofTotalRecordHashes - blocks->nofRecordHashes + blocks->extractInfo[j].extractOffset;

				print_progressResultExtended(set, DEBUG_LEVEL_2, res);
				print_progressDescExtended(set, 0, DEBUG_LEVEL_3, "Block no. %3zu: extracting log records (line %3zu)... ", blocks->blockNo, rowNumber);
				print_progressDescExtended(set, 0, DEBUG_EQUAL | DEBUG_LEVEL_2, "Extracting log record from block %3zu (line %3zu)... ", blocks->blockNo, rowNumber);

				res = KSI_TlvElement_new(&recChain);
				ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to create record chain.", blocks->extractInfo[j].extractPos);
				recChain->ftlv.tag = 0x0907;

				if (blocks->extractInfo[j].logLine) {
					if (fwrite(blocks->extractInfo[j].logLine, 1, strlen(blocks->extractInfo[j].logLine), files->files.outLog) != strlen(blocks->extractInfo[j].logLine)) {
						res = KT_IO_ERROR;
						ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to write log record to log records file.", blocks->extractInfo[j].extractPos);
					}
				} else if (blocks->extractInfo[j].metaRecord){
					res = KSI_TlvElement_setElement(recChain, blocks->extractInfo[j].metaRecord);
					ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to add metarecord to record chain.", blocks->extractInfo[j].extractPos);
				}
				res = tlv_element_set_hash(recChain, ksi, 0x01, blocks->extractInfo[j].extractRecord);
				ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to add record hash to record chain.", blocks->extractInfo[j].extractPos);

				for (i = 0; i < blocks->extractInfo[j].extractLevel; i++) {
					if (blocks->extractInfo[j].extractChain[i].sibling) {
						res = KSI_TlvElement_new(&hashStep);
						ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to create hash step no. %zu.", blocks->extractInfo[j].extractPos, i + 1);

						if (blocks->extractInfo[j].extractChain[i].dir == LEFT_LINK) {
							hashStep->ftlv.tag = 0x02;
						}
						else {
							hashStep->ftlv.tag = 0x03;
						}
						if (blocks->extractInfo[j].extractChain[i].corr) {
							res = tlv_element_set_uint(hashStep, ksi, 0x01, blocks->extractInfo[j].extractChain[i].corr);
							ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to add level correction to hash step no. %zu.", blocks->extractInfo[j].extractPos, i + 1);
						}
						res = tlv_element_set_hash(hashStep, ksi, 0x02, blocks->extractInfo[j].extractChain[i].sibling);
						ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to add sibling hash to hash step no. %zu.", blocks->extractInfo[j].extractPos, i + 1);
						res = KSI_TlvElement_appendElement(recChain, hashStep);
						ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to add hash step no. %zu.", blocks->extractInfo[j].extractPos, i + 1);

						KSI_TlvElement_free(hashStep);
						hashStep = NULL;
					}
				}
				res = KSI_TlvElement_serialize(recChain, buf, sizeof(buf), &len, 0);
				ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to serialize record chain.", blocks->extractInfo[j].extractPos);

				if (fwrite(buf, 1, len, files->files.outProof) != len) {
					res = KT_IO_ERROR;
					ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to write record chain to integrity proof file.", blocks->extractInfo[j].extractPos);
				}
				KSI_TlvElement_free(recChain);
				recChain = NULL;
			}

		}

		print_progressResultExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, res);
		print_progressResultExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_3, res);
	}

	{
		KSI_Integer *t1 = NULL;
		char sigTimeStr[256] = "<null>";
		res = KSI_Signature_getSigningTime(sig, &t1);
		ERR_CATCH_MSG(err, res, NULL);

		blocks->sigTime_1 = KSI_Integer_getUInt64(t1);

		print_debugExtended(set, DEBUG_LEVEL_3, "Block no. %3zu: Signing time: (%llu) %s\n", blocks->blockNo, blocks->sigTime_1, ksi_signature_sigTimeToString(sig, sigTimeStr, sizeof(sigTimeStr)));
	}


	res = KT_OK;

cleanup:
	if (processors->extract_signature) print_progressResultExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, res);
	print_progressResultExtended(set, DEBUG_LEVEL_3, res);

	KSI_Signature_free(sig);
	KSI_Signature_free(ext);
	KSI_DataHash_free((KSI_DataHash*)context.documentHash);
	KSI_DataHash_free(hash);
	KSI_VerificationContext_clean(&context);
	KSI_PolicyVerificationResult_free(verificationResult);
	KSI_TlvElement_free(tlvSig);
	KSI_TlvElement_free(tlvRfc3161);
	KSI_TlvElement_free(tlv);
	KSI_TlvElement_free(hashStep);
	KSI_TlvElement_free(recChain);
	KSI_Integer_free(t0);
	return res;
}

static int process_ksi_signature(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, SIGNATURE_PROCESSORS *processors, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_Signature *sig = NULL;
	KSI_PolicyVerificationResult *verificationResult = NULL;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlvSig = NULL;
	KSI_DataHasher *hasher = NULL;
	KSI_HashAlgorithm algo;

	if (set == NULL || err == NULL || ksi == NULL || processors == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	blocks->blockNo++;
	blocks->sigNo++;
	print_progressDescExtended(set, 0, DEBUG_LEVEL_3, "Block no. %3zu: processing KSI signature ... ", blocks->blockNo);

	res = tlv_element_parse_and_check_sub_elements(err, ksi, blocks->ftlv_raw, blocks->ftlv_len, blocks->ftlv.hdr_len, &tlvSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature as TLV element.", blocks->blockNo);

	print_progressResultExtended(set, DEBUG_LEVEL_3, res);
	print_progressDescExtended(set, 1, DEBUG_LEVEL_3, "Block no. %3zu: verifying KSI signature... ", blocks->blockNo);

	if (processors->verify_signature) {
		res = LOGKSI_Signature_parseWithPolicy(err, ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_EMPTY, NULL, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature.", blocks->blockNo);

		res = processors->verify_signature(set, err, ksi, blocks, files, sig, NULL, 0, &verificationResult);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: KSI signature verification failed.", blocks->blockNo);
		/* TODO: add dumping of verification results. */
		KSI_PolicyVerificationResult_free(verificationResult);
		verificationResult = NULL;

		res = KSI_Signature_getDocumentHash(sig, &hash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get root hash from KSI signature.", blocks->blockNo);

		res = KSI_DataHash_getHashAlg(hash, &algo);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get algorithm ID from root hash.", blocks->blockNo);

		if (blocks->hasher == NULL || blocks->hashAlgo != algo) {
			res = KSI_DataHasher_open(ksi, algo, &hasher);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: could not open datahasher.", blocks->blockNo);
		}

		blocks->hashAlgo = algo;
		if (hasher) {
			KSI_DataHasher_free(blocks->hasher);
			blocks->hasher = hasher;
			hasher = NULL;
		}

		KSI_DataHash_free(blocks->rootHash);
		blocks->rootHash = KSI_DataHash_ref(hash);
	}
	res = KT_OK;

cleanup:

	print_progressResultExtended(set, DEBUG_LEVEL_3, res);
	KSI_Signature_free(sig);
	KSI_PolicyVerificationResult_free(verificationResult);
	KSI_TlvElement_free(tlvSig);
	KSI_DataHasher_free(hasher);
	return res;
}

static int process_hash_step(ERR_TRCKR *err, KSI_CTX *ksi, KSI_TlvElement *tlv, BLOCK_INFO *blocks, KSI_DataHash *inputHash, KSI_DataHash **outputHash) {
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
	res = tlv_element_get_hash(err, tlv, ksi, 0x02, &siblingHash);
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

static int process_record_chain(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_DataHash *recordHash = NULL;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvMetaRecord = NULL;
	KSI_DataHash *tmpHash = NULL;
	KSI_DataHash *root = NULL;
	KSI_DataHash *replacement = NULL;

	if (err == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDescExtended(set, 0, DEBUG_LEVEL_3, "Block no. %3zu: processing record hash... ", blocks->blockNo);

	blocks->nofRecordHashes++;

	res = tlv_element_parse_and_check_sub_elements(err, ksi, blocks->ftlv_raw, blocks->ftlv_len, blocks->ftlv.hdr_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse record chain as TLV element.", blocks->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x911, &tlvMetaRecord);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract metarecord in record chain.", blocks->blockNo);

	KSI_DataHash_free(blocks->metarecordHash);
	blocks->metarecordHash = NULL;
	if (tlvMetaRecord != NULL) {
		res = get_hash_of_metarecord(blocks, tlvMetaRecord, &hash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate metarecord hash.", blocks->blockNo);

		blocks->metarecordHash = KSI_DataHash_ref(hash);
	}

	res = tlv_element_get_hash(err, tlv, ksi, 0x01, &recordHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse hash of logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));

	if (blocks->metarecordHash != NULL) {
		/* This is a metarecord hash. */
		res = logksi_datahash_compare(err, blocks->metarecordHash, recordHash, "Metarecord hash computed from metarecord: ", "Metarecord hash stored in integrity proof file: ");
		res = continue_on_hash_fail(res, set, blocks, blocks->metarecordHash, recordHash, &replacement);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: metarecord hashes not equal.", blocks->blockNo);
	} else {
		/* This is a logline record hash. */
		if (files->files.inLog) {
			res = get_hash_of_logline(blocks, files, &hash);
			if (res == KT_IO_ERROR) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: record hash no. %zu does not have a matching logline, end of logfile reached.", blocks->blockNo, get_nof_lines(blocks));
			} else {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate hash of logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));
			}

			res = logksi_datahash_compare(err, hash, recordHash, "Record hash computed from logline: ", "Record hash stored in integrity proof file: ");
			if (res != KT_OK) {
				print_debug("Failed to verify logline no. %zu: %s", get_nof_lines(blocks), blocks->logLine);
			}
			res = continue_on_hash_fail(res, set, blocks, hash, recordHash, &replacement);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: record hashes not equal.", blocks->blockNo);
		} else {
			replacement = KSI_DataHash_ref(recordHash);
		}
	}

	if (tlv->subList) {
		int i;
		blocks->treeHeight = 0;
		root = KSI_DataHash_ref(replacement);

		print_progressResultExtended(set, DEBUG_LEVEL_3, res);
		print_progressDescExtended(set, 0, DEBUG_LEVEL_3, "Block no. %3zu: processing hash chain... ", blocks->blockNo);
		for (i = 0; i < KSI_TlvElementList_length(tlv->subList); i++) {
			KSI_TlvElement *tmpTlv = NULL;

			res = KSI_TlvElementList_elementAt(tlv->subList, i, &tmpTlv);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get element %d from TLV.", blocks->blockNo, i);
			if (tmpTlv && (tmpTlv->ftlv.tag == 0x02 || tmpTlv->ftlv.tag == 0x03)) {
				res = process_hash_step(err, ksi, tmpTlv, blocks, root, &tmpHash);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to process hash step.", blocks->blockNo);

				KSI_DataHash_free(root);
				root = tmpHash;
				tmpHash = NULL;
			}
		}

		res = logksi_datahash_compare(err, root, blocks->rootHash, "Root hash computed from hash chain: ", "Root hash stored in KSI signature: ");
		KSI_DataHash_free(replacement);
		replacement = NULL;
		res = continue_on_hash_fail(res, set, blocks, root, blocks->rootHash, &replacement);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: root hashes not equal.", blocks->blockNo);
	} else {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get sub TLVs from record chain.", blocks->blockNo);
	}
	res = KT_OK;

cleanup:

	print_progressResultExtended(set, DEBUG_LEVEL_3, res);
	KSI_DataHash_free(recordHash);
	KSI_DataHash_free(hash);
	KSI_DataHash_free(root);
	KSI_DataHash_free(tmpHash);
	KSI_DataHash_free(replacement);
	KSI_TlvElement_free(tlv);
	KSI_TlvElement_free(tlvMetaRecord);
	return res;
}

static int process_partial_block(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_DataHash *hash = NULL;
	KSI_DataHash *rootHash = NULL;
	KSI_DataHash *replacement = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvNoSig = NULL;

	if (err == NULL || ksi == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDescExtended(set, 0, DEBUG_LEVEL_3, "Block no. %3zu: processing partial block data... ", blocks->blockNo);

	blocks->partNo++;
	if (blocks->partNo > blocks->blockNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: partial block data without preceding block header found.", blocks->sigNo);
	}

	res = tlv_element_parse_and_check_sub_elements(err, ksi, blocks->ftlv_raw, blocks->ftlv_len, blocks->ftlv.hdr_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse block signature as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &blocks->recordCount);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record count in blocks file.", blocks->blockNo);

	res = is_block_signature_expected(err, blocks);
	if (res != KT_OK) goto cleanup;

	res = KSI_TlvElement_getElement(tlv, 0x02, &tlvNoSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract 'no-sig' element in blocks file.", blocks->blockNo);

	res = tlv_element_get_hash(err, tlvNoSig, ksi, 0x01, &hash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse root hash.", blocks->blockNo);

	if (blocks->nofRecordHashes && blocks->nofRecordHashes != blocks->recordCount) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: expected %zu records in blocks file, but found %zu records.", blocks->blockNo, blocks->recordCount, blocks->nofRecordHashes);
	}

	/* If the blocks file contains hashes, re-compute and compare the root hash against the provided root hash. */
	if (blocks->nofRecordHashes) {
		res = calculate_root_hash(ksi, blocks, &rootHash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate root hash.", blocks->blockNo);

		res = logksi_datahash_compare(err, rootHash, hash, "Root hash computed from record hashes: ", "Unsigned root hash stored in block data file: ");
		res = continue_on_hash_fail(res, set, blocks, rootHash, hash, &replacement);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: root hashes not equal.", blocks->blockNo);
	} else {
		replacement = KSI_DataHash_ref(hash);
	}

	blocks->rootHash = replacement;

	res = KT_OK;

cleanup:

	print_progressResultExtended(set, DEBUG_LEVEL_3, res);
	KSI_DataHash_free(rootHash);
	KSI_DataHash_free(hash);
	KSI_TlvElement_free(tlv);
	KSI_TlvElement_free(tlvNoSig);
	return res;
}

static int process_partial_signature(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, SIGNATURE_PROCESSORS *processors, BLOCK_INFO *blocks, IO_FILES *files, int progress) {
	int res;
	KSI_Signature *sig = NULL;
	KSI_DataHash *hash = NULL;
	KSI_DataHash *rootHash = NULL;
	KSI_DataHash *missing = NULL;
	KSI_DataHash *replacement = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvSig = NULL;
	KSI_TlvElement *tlvNoSig = NULL;
	KSI_TlvElement *tlvRfc3161 = NULL;
	int insertHashes = 0;

	if (err == NULL || ksi == NULL || processors == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDescExtended(set, 0, DEBUG_LEVEL_3, "Block no. %3zu: processing partial signature data... ", blocks->blockNo);

	blocks->sigNo++;
	if (blocks->sigNo > blocks->blockNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: block signature data without preceding block header found.", blocks->sigNo);
	}
	res = tlv_element_parse_and_check_sub_elements(err, ksi, blocks->ftlv_raw, blocks->ftlv_len, blocks->ftlv.hdr_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse block signature as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &blocks->recordCount);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record count in signatures file.", blocks->blockNo);

	res = is_block_signature_expected(err, blocks);
	if (res != KT_OK) goto cleanup;

	/* If no record hashes were computed or encountered, previous leaf hashes must not be compared. */
	if (blocks->nofRecordHashes == 0) {
		KSI_DataHash_free(blocks->prevLeaf);
		blocks->prevLeaf = NULL;
	}

	if (blocks->nofRecordHashes && blocks->nofRecordHashes != blocks->recordCount) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: expected %zu records in signatures file, but found %zu records in blocks file.", blocks->blockNo, blocks->recordCount, blocks->nofRecordHashes);
	}

	insertHashes = PARAM_SET_isSetByName(set, "insert-missing-hashes");
	if (blocks->finalTreeHashesNone && insertHashes) {
		if (blocks->keepRecordHashes || (!blocks->keepRecordHashes && blocks->finalTreeHashesSome)) {
			do {
				missing = NULL;
				res = merge_one_level(ksi, blocks, &missing);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing tree hash could not be computed.", blocks->blockNo);
				if (missing) {
					res = tlv_element_write_hash(missing, 0x903, files->files.outSig);
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing tree hash could not be written.", blocks->blockNo);
					KSI_DataHash_free(missing);
				}
			} while (missing);
			blocks->finalTreeHashesNone = 0;
			blocks->finalTreeHashesAll = 1;
		}
	}

	res = KSI_TlvElement_getElement(tlv, 0x906, &tlvRfc3161);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract RFC3161 element in block signature.", blocks->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x905, &tlvSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract KSI signature element in signatures file.", blocks->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x02, &tlvNoSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract 'no-sig' element in signatures file.", blocks->blockNo);

	if (tlvSig != NULL || tlvRfc3161 != NULL) {
		KSI_DataHash *docHash = NULL;

		if (tlvSig != NULL) {
			res = LOGKSI_Signature_parseWithPolicy(err, ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_EMPTY, NULL, &sig);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature in signatures file.", blocks->blockNo);
		} else {
			/* Convert the RFC3161 timestamp into KSI signature. */
			res = convert_signature(ksi, tlvRfc3161->ptr + tlvRfc3161->ftlv.hdr_len, tlvRfc3161->ftlv.dat_len, &sig);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to convert RFC3161 element in block signature.", blocks->blockNo);
			blocks->warningLegacy = 1;
		}

		res = KSI_Signature_getDocumentHash(sig, &docHash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get root hash from KSI signature.", blocks->blockNo);

		/* Compare signed root hash with unsigned root hash. */
		if (blocks->rootHash) {
			res = logksi_datahash_compare(err, blocks->rootHash, docHash, "Unsigned root hash stored in block data file: ", "Signed root hash stored in KSI signature: ");
			res = continue_on_hash_fail(res, set, blocks, blocks->rootHash, docHash, &replacement);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: root hashes not equal.", blocks->blockNo);
		} else if (blocks->nofRecordHashes) {
			/* Compute the root hash and compare with signed root hash. */
			res = calculate_root_hash(ksi, blocks, &rootHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate root hash.", blocks->blockNo);

			res = logksi_datahash_compare(err, rootHash, docHash, "Root hash computed from record hashes: ", "Signed root hash stored in KSI signature: ");
			res = continue_on_hash_fail(res, set, blocks, rootHash, docHash, &replacement);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: root hashes not equal.", blocks->blockNo);
		}
	} else if (tlvNoSig != NULL) {
		blocks->noSigNo++;
		res = tlv_element_get_hash(err, tlvNoSig, ksi, 0x01, &hash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse root hash.", blocks->blockNo);

		/* Compare unsigned root hashes. */
		if (blocks->rootHash) {
			res = logksi_datahash_compare(err, blocks->rootHash, hash, "Unsigned root hash stored in block data file: ", "Unsigned root hash stored in block signature file: ");
			res = continue_on_hash_fail(res, set, blocks, blocks->rootHash, hash, &replacement);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: root hashes not equal.", blocks->blockNo);
		} else if (blocks->nofRecordHashes) {
			/* Compute the root hash and compare with unsigned root hash. */
			res = calculate_root_hash(ksi, blocks, &rootHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate root hash.", blocks->blockNo);

			res = logksi_datahash_compare(err, rootHash, hash, "Root hash computed from record hashes: ", "Unsigned root hash stored in block signature file: ");
			res = continue_on_hash_fail(res, set, blocks, rootHash, hash, &replacement);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: root hashes not equal.", blocks->blockNo);
		}

		if (processors->create_signature) {
			print_progressResultExtended(set, DEBUG_LEVEL_3, res);

			if (progress) {
				print_debug("Progress: signing block %3zu of %3zu unsigned blocks. Estimated time remaining: %3zu seconds.\n", blocks->noSigNo, blocks->noSigCount, blocks->noSigCount - blocks->noSigNo + 1);
			}
			print_progressDescExtended(set, 1, DEBUG_LEVEL_3, "Block no. %3zu: creating missing KSI signature... ", blocks->blockNo);

			res = processors->create_signature(set, err, ksi, blocks, files, hash, get_aggregation_level(blocks), &sig);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to sign root hash.", blocks->blockNo);

			blocks->noSigCreated++;
			blocks->curBlockJustReSigned = 1;

			res = KSI_TlvElement_new(&tlvSig);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize KSI signature.", blocks->blockNo);
			tlvSig->ftlv.tag = 0x904;

			res = tlv_element_set_uint(tlvSig, ksi, 0x01, blocks->recordCount);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize KSI signature.", blocks->blockNo);

			res = tlv_element_set_signature(tlvSig, ksi, 0x905, sig);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize KSI signature.", blocks->blockNo);

			res = KSI_TlvElement_serialize(tlvSig, blocks->ftlv_raw, SOF_FTLV_BUFFER, &blocks->ftlv_len, 0);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize KSI signature.", blocks->blockNo);
		} else {
			/* Missing signatures found during integration. */
			blocks->warningSignatures = 1;
			blocks->unsignedRootHash = 1;
		}
	} else {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: block signature missing in signatures file.", blocks->blockNo);
	}

	if (sig != NULL){
		KSI_Integer *t1 = NULL;

		res = KSI_Signature_getSigningTime(sig, &t1);
		ERR_CATCH_MSG(err, res, NULL);

		blocks->sigTime_1 = KSI_Integer_getUInt64(t1);
	} else {
		blocks->curBlockNotSigned = 1;
	}

	if (files->files.outSig) {
		print_progressResultExtended(set, DEBUG_LEVEL_3, res);
		print_progressDescExtended(set, 0, DEBUG_LEVEL_3, "Block no. %3zu: writing block signature to file... ", blocks->blockNo);

		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->files.outSig) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to write signature data log signature file.", blocks->blockNo);
		}
	}

	blocks->nofTotalRecordHashes += blocks->nofRecordHashes;

	res = KT_OK;

cleanup:

	print_progressResultExtended(set, DEBUG_LEVEL_3, res);

	KSI_Signature_free(sig);
	KSI_DataHash_free(hash);
	KSI_DataHash_free(rootHash);
	KSI_DataHash_free(missing);
	KSI_DataHash_free(replacement);
	KSI_TlvElement_free(tlvSig);
	KSI_TlvElement_free(tlvNoSig);
	KSI_TlvElement_free(tlvRfc3161);
	KSI_TlvElement_free(tlv);
	return res;
}

static int check_warnings(BLOCK_INFO *blocks) {
	if (blocks) {
		if (blocks->warningSignatures || blocks->warningTreeHashes || blocks->warningLegacy) {
			return 1;
		}
	}
	return 0;
}

static int finalize_log_signature(PARAM_SET* set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_DataHash* inputHash, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	char buf[2];
	char inHash[256] = "<null>";
	char outHash[256] = "<null>";
	int shortIndentation = 13;
	int longIndentation = 29;



	if (err == NULL || blocks == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}



	if (blocks->blockNo == 0) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: No blocks found.");
	}

	/* Finlize last block. */
	res = finalize_block(set, err, ksi, blocks, files);
	ERR_CATCH_MSG(err, res, "Error: Unable to finalize last block.");

	print_progressDescExtended(set, 0, DEBUG_LEVEL_3, "Finalizing log signature... ");

	/* Log file must not contain more records than log signature file. */
	if (files->files.inLog) {
		if (fread(buf, 1, 1, files->files.inLog) > 0) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: end of log file contains unexpected records.", blocks->blockNo);
		}
	}

	/* Signatures file must not contain more blocks than blocks file. */
	if (files->files.partsSig) {
		if (fread(buf, 1, 1, files->files.partsSig) > 0) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: end of signatures file contains unexpected data.", blocks->blockNo);
		}
	}

	if (blocks->nofHashFails) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: %zu hash comparison failures found.", blocks->nofHashFails);
	}

	if (blocks->nofExtractPositionsFound < blocks->nofExtractPositions) {
		res = KT_INVALID_CMD_PARAM;
		ERR_CATCH_MSG(err, res, "Error: Extract position %zu out of range - not enough loglines.", blocks->extractPositions[blocks->nofExtractPositionsFound]);
	}



	res = KT_OK;

cleanup:

	print_progressResultExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_1, res);
	print_progressResultExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, res);
	print_progressResultExtended(set, DEBUG_LEVEL_3, res);
	print_debugExtended(set, DEBUG_SMALLER | DEBUG_LEVEL_3, "Summary of logfile:\n");

	print_debugExtended(set, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of blocks:", blocks->blockNo);
	if (blocks->nofTotalFailedBlocks > 0) print_debugExtended(set, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of failures:", blocks->nofTotalFailedBlocks);
	print_debugExtended(set, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of record hashes:", blocks->nofTotalRecordHashes); /* Meta records not included. */

	if (blocks->noSigNo > 0) {
		if (blocks->noSigCreated) {
			print_debugExtended(set, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of resigned blocks:", blocks->noSigNo);
		} else {
			print_debugExtended(set, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of unsigned blocks:", blocks->noSigNo);
		}
	}

	if (blocks->nofTotalMetarecors > 0) print_debugExtended(set, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of meta-records:", blocks->nofTotalMetarecors); /* Meta records not included. */
	if (blocks->nofHashFails > 0) print_debugExtended(set, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of hash failures:", blocks->nofHashFails);
	if (blocks->nofExtractPositions > 0) print_debugExtended(set, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Records extracted:", blocks->nofExtractPositions);

	LOGKSI_DataHash_toString(inputHash, inHash, sizeof(inHash));
	LOGKSI_DataHash_toString(blocks->prevLeaf, outHash, sizeof(outHash));

	if (blocks->taskId == TASK_VERIFY || blocks->taskId == TASK_INTEGRATE) {
		print_debugExtended(set, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%s\n", shortIndentation, "Input hash:", inHash); /* Meta records not included. */
		print_debugExtended(set, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%s\n", shortIndentation, "Output hash:", outHash); /* Meta records not included. */
	}


	if (check_warnings(blocks)) {
		print_warnings("\n");
		if (blocks && blocks->warningSignatures) {
			print_warnings("Warning: Unsigned root hashes found.\n         Run 'logksi sign' to perform signing recovery.\n");
		}

		if (blocks && blocks->warningTreeHashes) {
			print_warnings("Warning: Some tree hashes are missing from the log signature file.\n         Run 'logksi sign' with '--insert-missing-hashes' to repair the log signature.\n");
		}

		if (blocks && blocks->warningLegacy) {
			print_warnings("Warning: RFC3161 timestamp(s) found in log signature.\n         Run 'logksi extend' with '--enable-rfc3161-conversion' to convert RFC3161 timestamps to KSI signatures.\n");
		}
	}

	return res;
}

static void BLOCK_INFO_freeAndClearInternals(BLOCK_INFO *blocks) {
	unsigned char i = 0;
	size_t j;

	if (blocks) {
		KSI_DataHash_free(blocks->prevLeaf);
		KSI_OctetString_free(blocks->randomSeed);
		while (i < blocks->treeHeight) {
			KSI_DataHash_free(blocks->MerkleTree[i]);
			KSI_DataHash_free(blocks->notVerified[i]);
			blocks->MerkleTree[i] = NULL;
			blocks->notVerified[i] = NULL;
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
		KSI_DataHasher_free(blocks->hasher);
		KSI_DataHash_free(blocks->inputHash);

		/* Set objects to NULL. */
		blocks->prevLeaf = NULL;
		blocks->randomSeed = NULL;
		blocks->rootHash = NULL;
		blocks->metarecordHash = NULL;
		blocks->extractMask = NULL;
		blocks->extractPositions = NULL;
		blocks->extractInfo = NULL;
		blocks->logLine = NULL;
		blocks->metaRecord = NULL;
		blocks->hasher = NULL;
		blocks->inputHash = NULL;

		blocks->blockNo = 0;
		blocks->sigNo = 0;
		blocks->blockCount = 0;
		blocks->noSigCreated = 0;
		blocks->nofTotalMetarecors = 0;
		blocks->nofTotalRecordHashes = 0;
		blocks->extendedToTime = 0;
		blocks->taskId = TASK_NONE;
	}
}

static int count_blocks(ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, FILE *in) {
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
		ERR_CATCH_MSG(err, res, "Error: Unable to get file handle position.");
	}

	while (!feof(in)) {
		res = KSI_FTLV_fileRead(in, blocks->ftlv_raw, SOF_FTLV_BUFFER, &blocks->ftlv_len, &blocks->ftlv);
		if (res == KSI_OK) {
			switch (blocks->ftlv.tag) {
				case 0x901:
					blocks->blockCount++;
				break;

				case 0x904:
					res = tlv_element_parse_and_check_sub_elements(err, ksi, blocks->ftlv_raw, blocks->ftlv_len, blocks->ftlv.hdr_len, &tlv);
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse block signature as TLV element.", blocks->blockNo);
					res = KSI_TlvElement_getElement(tlv, 0x02, &tlvNoSig);
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract 'no-sig' element in signatures file.", blocks->blockNo);

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
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete data found in log signature file.", blocks->blockNo);
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
				if (err) ERR_TRCKR_ADD(err, res, "Error: Could not rewind input stream.");
			}
		}
	}
	KSI_TlvElement_free(tlvNoSig);
	KSI_TlvElement_free(tlv);

	return res;
}

void BLOCK_INFO_reset(BLOCK_INFO *block) {
	if (block != NULL) {
		memset(block, 0, sizeof(BLOCK_INFO) - sizeof(block->warnBuf) - sizeof(block->errorBuf));
		block->errorBuf[0] = 0;
		block->warnBuf[0] = 0;
	}
}

static int process_log_signature_general_components_(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_PublicationsFile *pubFile, int withBlockSignature, BLOCK_INFO *blocks, IO_FILES *files, SIGNATURE_PROCESSORS *processors) {
	int res = KT_UNKNOWN_ERROR;
	static int printHeader = 0;

	if (set == NULL || err == NULL || ksi == NULL || blocks == NULL || files == NULL || (withBlockSignature && processors == NULL)) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	switch (blocks->ftlv.tag) {
		case 0x901:
			res = finalize_block(set, err, ksi, blocks, files);
			if (res != KT_OK) goto cleanup;

			res = init_next_block(blocks);
			if (res != KT_OK) goto cleanup;

			res = process_block_header(set, err, ksi, blocks, files);
			if (res != KT_OK) goto cleanup;

			printHeader = 1;

		break;

		case 0x902:
			if (printHeader) print_debugExtended(set, DEBUG_LEVEL_3, "Block no. %3zu: {", blocks->blockNo);
			print_debugExtended(set, DEBUG_LEVEL_3, "r" );
			printHeader = 0;

			res = process_record_hash(set, err, ksi, blocks, files);
			if (res != KT_OK) goto cleanup;
		break;

		case 0x903:
			if (printHeader) print_debugExtended(set, DEBUG_LEVEL_3, "Block no. %3zu: {", blocks->blockNo);
			print_debugExtended(set, DEBUG_LEVEL_3, ".");
			printHeader = 0;

			res = process_tree_hash(set, err, ksi, blocks, files);
			if (res != KT_OK) goto cleanup;
		break;

		case 0x911:
			if (printHeader) print_debugExtended(set, DEBUG_LEVEL_3, "Block no. %3zu: {", blocks->blockNo);
			print_debugExtended(set, DEBUG_LEVEL_3, "M");
			printHeader = 0;

			res = process_metarecord(set, err, ksi, blocks, files);
			if (res != KT_OK) goto cleanup;
		break;

		default:
			if (withBlockSignature && blocks->ftlv.tag) {
				print_debugExtended(set, DEBUG_LEVEL_3, "}\n");
				res = process_block_signature(set, err, ksi, pubFile, processors, blocks, files);
				if (res != KT_OK) goto cleanup;
			} else {
				res = KT_INVALID_INPUT_FORMAT;
				goto cleanup;
			}
		break;
	}

	res = KT_OK;

cleanup:

	return res;
}

static int process_log_signature(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	return process_log_signature_general_components_(set, err, ksi, NULL, 0, blocks, files, NULL);
}

static int process_log_signature_with_block_signature(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_PublicationsFile *pubFile, BLOCK_INFO *blocks, IO_FILES *files, SIGNATURE_PROCESSORS *processors) {
	return process_log_signature_general_components_(set, err, ksi, pubFile, 1, blocks, files, processors);
}

int logsignature_extend(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_PublicationsFile* pubFile, EXTENDING_FUNCTION extend_signature, IO_FILES *files) {
	int res;
	BLOCK_INFO blocks;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;
	KSI_DataHash *theFirstInputHashInFile = NULL;

	if (set == NULL || err == NULL || ksi == NULL || extend_signature == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	BLOCK_INFO_reset(&blocks);
	blocks.ftlv_raw = ftlv_raw;
	blocks.taskId = TASK_EXTEND;
	memset(&processors, 0, sizeof(processors));
	processors.extend_signature = extend_signature;

	res = process_magic_number(set, err, &blocks, files);

	if (res != KT_OK) goto cleanup;

	while (!feof(files->files.inSig)) {
		res = KSI_FTLV_fileRead(files->files.inSig, blocks.ftlv_raw, SOF_FTLV_BUFFER, &blocks.ftlv_len, &blocks.ftlv);
		if (res == KSI_OK) {
			switch (blocks.ftlv.tag) {
				case 0x901:
					if (theFirstInputHashInFile == NULL) theFirstInputHashInFile = KSI_DataHash_ref(blocks.inputHash);
				case 0x902:
				case 0x903:
				case 0x911:
				case 0x904:
					res = process_log_signature_with_block_signature(set, err, ksi, pubFile, &blocks, files, &processors);
					if (res != KT_OK) goto cleanup;
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
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete data found in log signature file.", blocks.blockNo);
			} else {
				break;
			}
		}
	}

	res = finalize_log_signature(set, err, ksi, theFirstInputHashInFile, &blocks, files);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	BLOCK_INFO_freeAndClearInternals(&blocks);
	KSI_DataHash_free(theFirstInputHashInFile);

	return res;
}

int logsignature_verify(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash *firstLink, VERIFYING_FUNCTION verify_signature, IO_FILES *files, KSI_DataHash **lastLeaf) {
	int res;

	KSI_DataHash *theFirstInputHashInFile = NULL;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;
	int isFirst = 1;

	if (set == NULL || err == NULL || ksi == NULL || blocks == NULL || verify_signature == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	blocks->ftlv_raw = ftlv_raw;
	blocks->taskId = TASK_VERIFY;
	memset(&processors, 0, sizeof(processors));
	processors.verify_signature = verify_signature;

	res = process_magic_number(set, err, blocks, files);
	if (res != KT_OK) goto cleanup;

	while (!feof(files->files.inSig)) {
		res = KSI_FTLV_fileRead(files->files.inSig, blocks->ftlv_raw, SOF_FTLV_BUFFER, &blocks->ftlv_len, &blocks->ftlv);
		if (res == KSI_OK) {
			switch (blocks->version) {
				case LOGSIG11:
				case LOGSIG12:
					switch (blocks->ftlv.tag) {
						case 0x904:
						case 0x901:
						case 0x902:
						case 0x903:
						case 0x911:
							res = process_log_signature_with_block_signature(set, err, ksi, NULL, blocks, files, &processors);
							if (res != KT_OK) goto cleanup;
						break;

						default:
							/* TODO: unknown TLV found. Either
							 * 1) Warn user and skip TLV
							 * 2) Copy TLV (maybe warn user)
							 * 3) Abort extending with an error
							 */
						break;
					}

					/* Addidional post processor for block header. */
					if (blocks->ftlv.tag == 0x901) {
						char buf[256];
						LOGKSI_DataHash_toString(blocks->prevLeaf, buf, sizeof(buf));
						print_progressResultExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, res);

						/* Free previous reference to the input hash and make a new reference. */
						if (theFirstInputHashInFile == NULL) theFirstInputHashInFile = KSI_DataHash_ref(blocks->prevLeaf);
						print_debugExtended(set, DEBUG_LEVEL_3, "Block no. %3zu: input hash: %s.\n", blocks->blockNo, buf);
						print_progressDescExtended(set, 0, DEBUG_EQUAL | DEBUG_LEVEL_2 , "Verifying block no. %3zu... ", blocks->blockNo);


						/* Check if the last leaf from the previous block matches with the current first block. */
						if (isFirst == 1 && firstLink != NULL) {
							print_progressDescExtended(set, 0, DEBUG_LEVEL_3, "Block no. %3zu: verifying inter-linking input hash... ", blocks->blockNo);
							isFirst = 0;
							if (!KSI_DataHash_equals(firstLink, blocks->prevLeaf)) {
								char buf_imp[1024];
								char buf_exp_imp[1024];
								char buf_fname[4096];
								char *prevBlockSource = "Unexpected and not initialized previous block source.";
								const char *firstBlockSource = IO_FILES_getCurrentLogFilePrintRepresentation(files);

								res = KT_VERIFICATION_FAILURE;

								if (PARAM_SET_isSetByName(set, "input-hash") && files->previousLogFile[0] == '\0') {
									char *fname = NULL;
									PARAM_SET_getStr(set, "input-hash", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &fname);

									PST_snprintf(buf_fname, sizeof(buf_fname), "from --input-hash %s", fname);
									prevBlockSource = buf_fname;
								} else {
									prevBlockSource = files->previousLogFile;
								}

								ERR_TRCKR_ADD(err, res, "Error: Block no. %zu: The last leaf from the previous block (%s) does not match with the current first block (%s). Expecting '%s', but got '%s'.", blocks->blockNo, prevBlockSource, firstBlockSource, LOGKSI_DataHash_toString(firstLink, buf_exp_imp, sizeof(buf_exp_imp)), LOGKSI_DataHash_toString(blocks->prevLeaf, buf_imp, sizeof(buf_imp)));

								goto cleanup;
							}
							print_progressResultExtended(set, DEBUG_LEVEL_3, res);
						}

					}

				break;

				case RECSIG11:
				case RECSIG12:
					switch (blocks->ftlv.tag) {
						case 0x905:
						{
							res = process_ksi_signature(set, err, ksi, &processors, blocks, files);
							if (res != KT_OK) goto cleanup;
						}
						break;

						case 0x907:
						{
							res = process_record_chain(set, err, ksi, blocks, files);
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
			if (blocks->ftlv_len > 0) {
				res = KT_INVALID_INPUT_FORMAT;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete data found in log signature file.", blocks->blockNo);
			} else {
				break;
			}
		}
	}


	/* If requested, return last leaf of last block. */
	if (lastLeaf != NULL) {
		*lastLeaf = KSI_DataHash_ref(blocks->prevLeaf);
	}

	res = finalize_log_signature(set, err, ksi, theFirstInputHashInFile, blocks, files);
	if (res != KT_OK) goto cleanup;

	if (blocks->errSignTime) {
		res = KT_VERIFICATION_FAILURE;
		ERR_TRCKR_ADD(err, res, "Error: Log block has signing time more recent than consecutive block!");
		goto cleanup;
	}

	res = KT_OK;

cleanup:

	print_progressResultExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, res);
	KSI_DataHash_free(theFirstInputHashInFile);
	BLOCK_INFO_freeAndClearInternals(blocks);

	return res;
}

int verify_extract_positions(ERR_TRCKR *err, char *records) {
	int res;

	if (records == NULL || *records == 0) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	while (*records) {
		char c = *records;
		if (isspace(c)) {
			res = KT_INVALID_CMD_PARAM;
			ERR_CATCH_MSG(err, res, "Error: List of positions must not contain whitespace. Use ',' and '-' as separators.");
		}
		if (!isdigit(c) && c != ',' && c != '-') {
			res = KT_INVALID_CMD_PARAM;
			ERR_CATCH_MSG(err, res, "Error: Positions must be represented by positive decimal integers, using a list of comma-separated ranges.");
		}
		records++;
	}
	res = KT_OK;

cleanup:

	return res;
}

void IO_FILES_init(IO_FILES *files) {
	if (files != NULL) {
		memset(&files->user, 0, sizeof(USER_FILE_NAMES));
		memset(&files->internal, 0, sizeof(INTERNAL_FILE_NAMES));
		memset(&files->files, 0, sizeof(INTERNAL_FILE_HANDLES));

		files->previousLogFile[0] = '\0';
		files->previousSigFile[0] = '\0';
	}
}

void IO_FILES_StorePreviousFileNames(IO_FILES *files) {
	if (files == NULL) return;

	/* Make copy of previous file names. */
	if (files->internal.inLog == NULL) {
		PST_strncpy(files->previousLogFile, "stdin", sizeof(files->previousLogFile));
	} else {
		PST_strncpy(files->previousLogFile, files->internal.inLog, sizeof(files->previousLogFile));
	}

	if (files->internal.inSig == NULL) {
		PST_strncpy(files->previousSigFile, "stdin", sizeof(files->previousSigFile));
	} else {
		PST_strncpy(files->previousSigFile, files->internal.inSig, sizeof(files->previousSigFile));
	}
}

const char *IO_FILES_getCurrentLogFilePrintRepresentation(IO_FILES *files) {
	int logStdin = 0;

	if (files == NULL) return NULL;

	logStdin = files->internal.inLog == NULL;
	return logStdin ? "stdin" : files->internal.inLog;
}


int logsignature_extract(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, IO_FILES *files) {
	int res;
	BLOCK_INFO blocks;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;
	KSI_DataHash *theFirstInputHashInFile = NULL;

	if (set == NULL || err == NULL || ksi == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	BLOCK_INFO_reset(&blocks);
	blocks.ftlv_raw = ftlv_raw;
	blocks.taskId = TASK_EXTRACT;
	memset(&processors, 0, sizeof(processors));
	processors.extract_signature = 1;

	res = PARAM_SET_getStr(set, "r", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &blocks.records);
	if (res != KT_OK) goto cleanup;

	res = verify_extract_positions(err, blocks.records);
	if (res != KT_OK) goto cleanup;

	/* Initialize the first extract position. */
	res = extract_next_position(err, blocks.records, &blocks);
	if (res != KT_OK) goto cleanup;

	res = process_magic_number(set, err, &blocks, files);
	if (res != KT_OK) goto cleanup;

	while (!feof(files->files.inSig)) {
		res = KSI_FTLV_fileRead(files->files.inSig, blocks.ftlv_raw, SOF_FTLV_BUFFER, &blocks.ftlv_len, &blocks.ftlv);
		if (res == KSI_OK) {
			switch (blocks.ftlv.tag) {
				case 0x901:
					if (theFirstInputHashInFile == NULL) theFirstInputHashInFile = KSI_DataHash_ref(blocks.inputHash);
				case 0x902:
				case 0x903:
				case 0x911:
				case 0x904:
					res = process_log_signature_with_block_signature(set, err, ksi, NULL, &blocks, files, &processors);
					if (res != KT_OK) goto cleanup;
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
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete data found in log signature file.", blocks.blockNo);
			} else {
				break;
			}
		}
	}

	res = finalize_log_signature(set, err, ksi, theFirstInputHashInFile, &blocks, files);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	BLOCK_INFO_freeAndClearInternals(&blocks);
	KSI_DataHash_free(theFirstInputHashInFile);

	return res;
}

int logsignature_integrate(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, IO_FILES *files) {
	int res;
	BLOCK_INFO blocks;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;
	KSI_DataHash *theFirstInputHashInFile = NULL;

	if (err == NULL || ksi == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	BLOCK_INFO_reset(&blocks);
	blocks.ftlv_raw = ftlv_raw;
	blocks.taskId = TASK_INTEGRATE;
	memset(&processors, 0, sizeof(processors));

	res = process_magic_number(set, err, &blocks, files);
	if (res != KT_OK) goto cleanup;

	while (!feof(files->files.partsBlk)) {
		res = KSI_FTLV_fileRead(files->files.partsBlk, blocks.ftlv_raw, SOF_FTLV_BUFFER, &blocks.ftlv_len, &blocks.ftlv);
		if (res == KSI_OK) {
			switch (blocks.ftlv.tag) {
				case 0x901:
					if (theFirstInputHashInFile == NULL) theFirstInputHashInFile = KSI_DataHash_ref(blocks.inputHash);
				case 0x902:
				case 0x903:
				case 0x911:
					res = process_log_signature(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;
				case 0x904:
				{
					print_debugExtended(set, DEBUG_LEVEL_3, "}\n");
					print_progressDescExtended(set, 0, DEBUG_EQUAL | DEBUG_LEVEL_2, "Integrating block no. %3zu: into log signature... ", blocks.blockNo);

					res = process_partial_block(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;

					res = KSI_FTLV_fileRead(files->files.partsSig, blocks.ftlv_raw, SOF_FTLV_BUFFER, &blocks.ftlv_len, &blocks.ftlv);
					if (res != KT_OK) {
						if (blocks.ftlv_len > 0) {
							res = KT_INVALID_INPUT_FORMAT;
							ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete data found in signatures file.", blocks.blockNo);
						} else {
							res = KT_VERIFICATION_FAILURE;
							ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unexpected end of signatures file.", blocks.blockNo);
						}
					}
					if (blocks.ftlv.tag != 0x904) {
						res = KT_INVALID_INPUT_FORMAT;
						ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unexpected TLV %04X read from block-signatures file.", blocks.blockNo, blocks.ftlv.tag);
					}

					res = process_partial_signature(set, err, ksi, &processors, &blocks, files, 0);
					if (res != KT_OK) goto cleanup;
					print_progressResultExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, res);
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
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete data found in blocks file.", blocks.blockNo);
			} else {
				break;
			}
		}
	}

	res = finalize_log_signature(set, err, ksi, theFirstInputHashInFile, &blocks, files);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:
	print_progressResultExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, res);
	BLOCK_INFO_freeAndClearInternals(&blocks);
	KSI_DataHash_free(theFirstInputHashInFile);

	return res;
}

static int wrapper_LOGKSI_createSignature(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files, KSI_DataHash *hash, KSI_uint64_t rootLevel, KSI_Signature **sig) {
	int res = KT_UNKNOWN_ERROR;

	if (set == NULL || err == NULL || ksi == NULL || blocks == NULL || files == NULL || hash == NULL || sig == NULL) {
		return KT_INVALID_ARGUMENT;
	}

	print_progressDescExtended(set, 1, DEBUG_EQUAL | DEBUG_LEVEL_2, "Signing Block no. %3zu... ", blocks->blockNo);
	res = LOGKSI_createSignature(err, ksi, hash, rootLevel, sig);
	print_progressResultExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, res);

	return res;
}

int logsignature_sign(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, IO_FILES *files) {
	int res;
	int progress;
	BLOCK_INFO blocks;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;
	KSI_DataHash *theFirstInputHashInFile = NULL;

	if (set == NULL || err == NULL || ksi == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	BLOCK_INFO_reset(&blocks);
	blocks.ftlv_raw = ftlv_raw;
	blocks.taskId = TASK_SIGN;
	memset(&processors, 0, sizeof(processors));
	processors.create_signature = wrapper_LOGKSI_createSignature;

	res = process_magic_number(set, err, &blocks, files);
	if (res != KT_OK) goto cleanup;

	if (files->files.inSig != stdin) {
		progress = (PARAM_SET_isSetByName(set, "d")&& PARAM_SET_isSetByName(set, "show-progress"));
	} else {
		/* Impossible to estimate signing progress if input is from stdin. */
		progress = 0;
	}

	if (progress) {
		res = count_blocks(err, ksi, &blocks, files->files.inSig);
		if (res != KT_OK) goto cleanup;
		print_debug("Progress: %3zu of %3zu blocks need signing. Estimated signing time: %3zu seconds.\n", blocks.noSigCount, blocks.blockCount, blocks.noSigCount);
	}

	while (!feof(files->files.inSig)) {
		res = KSI_FTLV_fileRead(files->files.inSig, blocks.ftlv_raw, SOF_FTLV_BUFFER, &blocks.ftlv_len, &blocks.ftlv);
		if (res == KSI_OK) {
			switch (blocks.ftlv.tag) {
				case 0x901:
					if (theFirstInputHashInFile == NULL) theFirstInputHashInFile = KSI_DataHash_ref(blocks.inputHash);
				case 0x902:
				case 0x903:
				case 0x911:
					res = process_log_signature(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x904:
				{
					print_debugExtended(set, DEBUG_LEVEL_3, "}\n");
					res = process_partial_signature(set, err, ksi, &processors, &blocks, files, progress);
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
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete data found in log signature file.", blocks.blockNo);
			} else {
				break;
			}
		}
	}

	res = finalize_log_signature(set, err, ksi, theFirstInputHashInFile, &blocks, files);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:
	print_progressResultExtended(set, DEBUG_EQUAL | DEBUG_LEVEL_2, res);
	BLOCK_INFO_freeAndClearInternals(&blocks);
	KSI_DataHash_free(theFirstInputHashInFile);

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
			ERR_CATCH_MSG(err, res, "Error: Could not find file %s.", name);
		} else {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Could not open file %s.", name);
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
