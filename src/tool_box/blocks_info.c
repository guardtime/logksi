/*
 * Copyright 2013-2019 Guardtime, Inc.
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
#include "io_files.h"
#include "logksi_err.h"
#include "param_set/strn.h"
#include "blocks_info.h"
#include "blocks_info_impl.h"
#include "extract_info.h"

static int block_info_calculate_new_leaf_hash(BLOCK_INFO *blocks, KSI_CTX *ksi, KSI_DataHash *recordHash, int isMetaRecordHash, KSI_DataHash **leafHash);

int block_info_merge_one_level(BLOCK_INFO *blocks, KSI_CTX *ksi, KSI_DataHash **hash) {
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
				res = block_info_calculate_new_tree_hash(blocks, blocks->MerkleTree[i], root, i + 2, &tmp);
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

int block_info_calculate_root_hash(BLOCK_INFO *blocks, KSI_CTX *ksi, KSI_DataHash **hash) {
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
				res = block_info_calculate_new_tree_hash(blocks, blocks->MerkleTree[i], root, i + 2, &tmp);
				if (res != KT_OK) goto cleanup;

				res = block_info_extract_update_record_chain(blocks, i, 1, root);
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

int block_info_get_aggregation_level(BLOCK_INFO *blocks) {
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

int block_info_add_leaf_hash_to_merkle_tree(BLOCK_INFO *blocks, KSI_CTX *ksi, KSI_DataHash *hash, int isMetaRecordHash) {
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
		res = block_info_calculate_new_tree_hash(blocks, blocks->MerkleTree[i], right, i + 2, &tmp);
		if (res != KT_OK) goto cleanup;

		res = block_info_extract_update_record_chain(blocks, i, 0, right);
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

int block_info_add_record_hash_to_merkle_tree(BLOCK_INFO *blocks, ERR_TRCKR *err, KSI_CTX *ksi, int isMetaRecordHash, KSI_DataHash *hash) {
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

	res = block_info_calculate_new_leaf_hash(blocks, ksi, hash, isMetaRecordHash, &lastHash);
	if (res != KT_OK) goto cleanup;

	res = block_info_extract_update(blocks, err, isMetaRecordHash, hash);
	if (res != KT_OK) goto cleanup;

	res = block_info_add_leaf_hash_to_merkle_tree(blocks, ksi, lastHash, isMetaRecordHash);
	if (res != KT_OK) goto cleanup;

cleanup:

	KSI_DataHash_free(lastHash);
	return res;
}

static int block_info_store_logline(BLOCK_INFO *blocks, char *buf) {
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

int block_info_calculate_hash_of_logline_and_store_logline(BLOCK_INFO *blocks, IO_FILES *files, KSI_DataHash **hash) {
	int res;
	KSI_DataHash *tmp = NULL;
	/* Maximum line size is 64K characters, without newline character. */
	char buf[0x10000 + 2];

	if (files == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (files->files.inLog) {
		res = SMART_FILE_gets(files->files.inLog, buf, sizeof(buf), NULL);
		if (res != SMART_FILE_OK) goto cleanup;

		res = KSI_DataHasher_reset(blocks->hasher);
		if (res != KSI_OK) goto cleanup;

		/* Last character (newline) is not used in hash calculation. */
		res = KSI_DataHasher_add(blocks->hasher, buf, strlen(buf) - 1);
		if (res != KSI_OK) goto cleanup;

		res = KSI_DataHasher_close(blocks->hasher, &tmp);
		if (res != KSI_OK) goto cleanup;

		/* Store logline for extraction. */
		res = block_info_store_logline(blocks, buf);
		if (res != KT_OK) goto cleanup;
	}
	*hash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(tmp);
	return res;
}

static int block_info_store_metarecord(BLOCK_INFO *blocks, KSI_TlvElement *tlv) {
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

int block_info_calculate_new_tree_hash(BLOCK_INFO *blocks, KSI_DataHash *leftHash, KSI_DataHash *rightHash, unsigned char level, KSI_DataHash **nodeHash) {
	int res;
	KSI_DataHash *tmp = NULL;

	if (blocks == NULL || leftHash == NULL || rightHash == NULL || nodeHash == NULL) {
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

int block_info_calculate_hash_of_metarecord_and_store_metarecord(BLOCK_INFO *blocks, KSI_TlvElement *tlv, KSI_DataHash **hash) {
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
	res = block_info_store_metarecord(blocks, tlv);
	if (res != KT_OK) goto cleanup;

	*hash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(tmp);
	return res;
}

static int block_info_calculate_new_leaf_hash(BLOCK_INFO *blocks, KSI_CTX *ksi, KSI_DataHash *recordHash, int isMetaRecordHash, KSI_DataHash **leafHash) {
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
		res = block_info_calculate_new_tree_hash(blocks, recordHash, mask, 1, &tmp);
		if (res != KT_OK) goto cleanup;
	} else {
		res = block_info_calculate_new_tree_hash(blocks, mask, recordHash, 1, &tmp);
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

int BLOCK_INFO_setErrorLevel(BLOCK_INFO *blocks, int lvl) {
	if (blocks == NULL || lvl == LOGKSI_VER_RES_INVALID || lvl >= LOGKSI_VER_RES_COUNT) return KT_INVALID_ARGUMENT;
	if (blocks->logksiVerRes < lvl) blocks->logksiVerRes = lvl;
	return KT_OK;
}

void BLOCK_INFO_freeAndClearInternals(BLOCK_INFO *blocks) {
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

		REGEXP_free(blocks->client_id_match);

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
		blocks->client_id_match = NULL;
		blocks->client_id_last[0] = '\0';

		blocks->isContinuedOnFail = 0;
		blocks->blockNo = 0;
		blocks->sigNo = 0;
		blocks->blockCount = 0;
		blocks->noSigCreated = 0;
		blocks->nofTotalMetarecors = 0;
		blocks->nofTotalRecordHashes = 0;
		blocks->extendedToTime = 0;
		blocks->outSigModified = 0;
		blocks->taskId = TASK_NONE;
		blocks->quietError = 0;
		blocks->rec_time_in_file_min = 0;
		blocks->rec_time_in_file_max = 0;
		blocks->rec_time_min = 0;
		blocks->rec_time_max = 0;
		blocks->logksiVerRes = LOGKSI_VER_RES_INVALID;
	}
}

void BLOCK_INFO_clearAll(BLOCK_INFO *block) {
	if (block != NULL) {
		memset(block, 0, sizeof(BLOCK_INFO));
	}
}