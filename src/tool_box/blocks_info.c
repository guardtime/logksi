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

static int block_info_calculate_new_leaf_hash(LOGKSI *logksi, KSI_CTX *ksi, KSI_DataHash *recordHash, int isMetaRecordHash, KSI_DataHash **leafHash);

void EXTRACT_INFO_clean(EXTRACT_INFO *obj);
void EXTRACT_INFO_freeAndClearInternals(EXTRACT_INFO *obj);

void EXTRACT_TASK_clean(EXTRACT_TASK *obj);
void EXTRACT_TASK_freeAndClearInternals(EXTRACT_TASK *obj);

void SIGN_TASK_clean(SIGN_TASK *obj);
void SIGN_TASK_freeAndClearInternals(SIGN_TASK *obj);

void VERIFY_TASK_clean(VERIFY_TASK *obj);
void VERIFY_TASK_freeAndClearInternals(VERIFY_TASK *obj);

void EXTEND_TASK_freeAndClearInternals(EXTEND_TASK *obj);
void EXTEND_TASK_clean(EXTEND_TASK *obj);

void INTEGRATE_TASK_freeAndClearInternals(INTEGRATE_TASK *obj);
void INTEGRATE_TASK_clean(INTEGRATE_TASK *obj);

int block_info_merge_one_level(LOGKSI *logksi, KSI_CTX *ksi, KSI_DataHash **hash) {
	int res;
	unsigned char i = 0;
	KSI_DataHash *root = NULL;
	KSI_DataHash *tmp = NULL;

	if (ksi == NULL || logksi == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	while (i < logksi->treeHeight) {
		if (logksi->MerkleTree[i]) {
			if (root == NULL) {
				/* Initialize root hash only if there is at least one more hash afterwards. */
				if (i < logksi->treeHeight - 1) {
					root = KSI_DataHash_ref(logksi->MerkleTree[i]);
					KSI_DataHash_free(logksi->MerkleTree[i]);
					logksi->MerkleTree[i] = NULL;
				}
			} else {
				res = block_info_calculate_new_tree_hash(logksi, logksi->MerkleTree[i], root, i + 2, &tmp);
				if (res != KT_OK) goto cleanup;

				KSI_DataHash_free(root);
				root = tmp;

				KSI_DataHash_free(logksi->MerkleTree[i]);
				logksi->MerkleTree[i] = KSI_DataHash_ref(root);
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

int block_info_calculate_root_hash(LOGKSI *logksi, KSI_CTX *ksi, KSI_DataHash **hash) {
	int res;
	unsigned char i = 0;
	KSI_DataHash *root = NULL;
	KSI_DataHash *tmp = NULL;

	if (ksi == NULL || logksi == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (logksi->balanced) {
		root = KSI_DataHash_ref(logksi->MerkleTree[logksi->treeHeight - 1]);
	} else {
		while (i < logksi->treeHeight) {
			if (root == NULL) {
				root = KSI_DataHash_ref(logksi->MerkleTree[i]);
				i++;
				continue;
			}
			if (logksi->MerkleTree[i]) {
				res = block_info_calculate_new_tree_hash(logksi, logksi->MerkleTree[i], root, i + 2, &tmp);
				if (res != KT_OK) goto cleanup;

				res = block_info_extract_update_record_chain(logksi, i, 1, root);
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

int block_info_get_aggregation_level(LOGKSI *logksi) {
	int level = 0;
	if (logksi != NULL) {
		if (logksi->file.version == LOGSIG11) {
			/* To be backward compatible with a bug in LOGSIG11 implementation of rsyslog-ksi,
			 * we must sign tree hashes with level 0 regardless of the tree height. */
			level = 0;
		} else if (logksi->block.recordCount){
			/* LOGSIG12 implementation:
			 * Calculate the aggregation level from the number of records in the block (tree).
			 * Level is log2 dependent on the number of records,
			 * and is the same for all perfect and smaller trees.
			 * E.g. level = 4 for 5.. 8 records
			 *      level = 5 for 9..16 records etc.
			 * Level for the single node tree that uses blinding masks is 1. */
			level = 1;
			size_t c = logksi->block.recordCount - 1;
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

int block_info_add_leaf_hash_to_merkle_tree(LOGKSI *logksi, KSI_CTX *ksi, KSI_DataHash *hash, int isMetaRecordHash) {
	int res;
	unsigned char i = 0;
	KSI_DataHash *right = NULL;
	KSI_DataHash *tmp = NULL;

	if (ksi == NULL || logksi == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	right = KSI_DataHash_ref(hash);

	logksi->balanced = 0;

	while (logksi->MerkleTree[i] != NULL) {
		res = block_info_calculate_new_tree_hash(logksi, logksi->MerkleTree[i], right, i + 2, &tmp);
		if (res != KT_OK) goto cleanup;

		res = block_info_extract_update_record_chain(logksi, i, 0, right);
		if (res != KT_OK) goto cleanup;

		KSI_DataHash_free(logksi->notVerified[i]);
		logksi->notVerified[i] = KSI_DataHash_ref(right);
		KSI_DataHash_free(right);
		right = tmp;
		KSI_DataHash_free(logksi->MerkleTree[i]);
		logksi->MerkleTree[i] = NULL;
		i++;
	}
	logksi->MerkleTree[i] = right;
	KSI_DataHash_free(logksi->notVerified[i]);
	logksi->notVerified[i] = KSI_DataHash_ref(logksi->MerkleTree[i]);

	if (i == logksi->treeHeight) {
		logksi->treeHeight++;
		logksi->balanced = 1;
	}

	KSI_DataHash_free(logksi->prevLeaf);
	logksi->prevLeaf = KSI_DataHash_ref(hash);
	right = NULL;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(right);
	KSI_DataHash_free(tmp);
	return res;
}

int block_info_add_record_hash_to_merkle_tree(LOGKSI *logksi, ERR_TRCKR *err, KSI_CTX *ksi, int isMetaRecordHash, KSI_DataHash *hash) {
	int res;
	KSI_DataHash *lastHash = NULL;

	if (ksi == NULL || logksi == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Do not allow meta records to be extracted. */
	if (isMetaRecordHash) {
		logksi->file.nofTotalMetarecords++;
		logksi->block.nofMetaRecords++;
		logksi->file.nofTotalRecordHashes--;
	}

	res = block_info_calculate_new_leaf_hash(logksi, ksi, hash, isMetaRecordHash, &lastHash);
	if (res != KT_OK) goto cleanup;

	res = block_info_extract_update(logksi, err, isMetaRecordHash, hash);
	if (res != KT_OK) goto cleanup;

	res = block_info_add_leaf_hash_to_merkle_tree(logksi, ksi, lastHash, isMetaRecordHash);
	if (res != KT_OK) goto cleanup;

cleanup:

	KSI_DataHash_free(lastHash);
	return res;
}

static int block_info_store_logline(LOGKSI *logksi, char *buf) {
	int res;
	char *tmp = NULL;

	if (logksi == NULL || buf == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = (char*)malloc(strlen(buf) + 1);
	if (tmp == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	strncpy(tmp, buf, strlen(buf) + 1);
	free(logksi->logLine);
	logksi->logLine = tmp;
	tmp = NULL;

	res = KT_OK;

cleanup:

	free(tmp);
	return res;
}

int block_info_calculate_hash_of_logline_and_store_logline(LOGKSI *logksi, IO_FILES *files, KSI_DataHash **hash) {
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

		res = KSI_DataHasher_reset(logksi->hasher);
		if (res != KSI_OK) goto cleanup;

		/* Last character (newline) is not used in hash calculation. */
		res = KSI_DataHasher_add(logksi->hasher, buf, strlen(buf) - 1);
		if (res != KSI_OK) goto cleanup;

		res = KSI_DataHasher_close(logksi->hasher, &tmp);
		if (res != KSI_OK) goto cleanup;

		/* Store logline for extraction. */
		res = block_info_store_logline(logksi, buf);
		if (res != KT_OK) goto cleanup;
	}
	*hash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(tmp);
	return res;
}

static int block_info_store_metarecord(LOGKSI *logksi, KSI_TlvElement *tlv) {
	int res;
	size_t len = 0;
	unsigned char *buf = NULL;

	if (logksi == NULL || tlv == NULL) {
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

	free(logksi->task.extract.metaRecord);
	logksi->task.extract.metaRecord = buf;
	buf = NULL;

	res = KT_OK;

cleanup:

	free(buf);
	return res;
}

int block_info_calculate_new_tree_hash(LOGKSI *logksi, KSI_DataHash *leftHash, KSI_DataHash *rightHash, unsigned char level, KSI_DataHash **nodeHash) {
	int res;
	KSI_DataHash *tmp = NULL;

	if (logksi == NULL || leftHash == NULL || rightHash == NULL || nodeHash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_DataHasher_reset(logksi->hasher);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addImprint(logksi->hasher, leftHash);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addImprint(logksi->hasher, rightHash);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_add(logksi->hasher, &level, 1);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_close(logksi->hasher, &tmp);
	if (res != KSI_OK) goto cleanup;

	*nodeHash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(tmp);
	return res;
}

int block_info_calculate_hash_of_metarecord_and_store_metarecord(LOGKSI *logksi, KSI_TlvElement *tlv, KSI_DataHash **hash) {
	int res;
	KSI_DataHash *tmp = NULL;

	if (tlv == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_DataHasher_reset(logksi->hasher);
	if (res != KSI_OK) goto cleanup;

	/* The complete metarecord TLV us used in hash calculation. */
	res = KSI_DataHasher_add(logksi->hasher, tlv->ptr, tlv->ftlv.hdr_len + tlv->ftlv.dat_len);
	if (res != KSI_OK) goto cleanup;

	res = KSI_DataHasher_close(logksi->hasher, &tmp);
	if (res != KSI_OK) goto cleanup;

	/* Store metarecord for extraction. */
	res = block_info_store_metarecord(logksi, tlv);
	if (res != KT_OK) goto cleanup;

	*hash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(tmp);
	return res;
}

static int block_info_calculate_new_leaf_hash(LOGKSI *logksi, KSI_CTX *ksi, KSI_DataHash *recordHash, int isMetaRecordHash, KSI_DataHash **leafHash) {
	int res;
	KSI_DataHash *mask = NULL;
	KSI_DataHash *tmp = NULL;

	if (ksi == NULL || logksi == NULL || recordHash == NULL || leafHash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_DataHasher_reset(logksi->hasher);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addImprint(logksi->hasher, logksi->prevLeaf);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addOctetString(logksi->hasher, logksi->randomSeed);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_close(logksi->hasher, &mask);
	if (res != KSI_OK) goto cleanup;

	KSI_DataHash_free(logksi->task.extract.extractMask);
	logksi->task.extract.extractMask = KSI_DataHash_ref(mask);

	if (isMetaRecordHash) {
		res = block_info_calculate_new_tree_hash(logksi, recordHash, mask, 1, &tmp);
		if (res != KT_OK) goto cleanup;
	} else {
		res = block_info_calculate_new_tree_hash(logksi, mask, recordHash, 1, &tmp);
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

void LOGKSI_freeAndClearInternals(LOGKSI *logksi) {
	unsigned char i = 0;

	if (logksi) {
		KSI_DataHash_free(logksi->prevLeaf);
		KSI_OctetString_free(logksi->randomSeed);
		while (i < logksi->treeHeight) {
			KSI_DataHash_free(logksi->MerkleTree[i]);
			KSI_DataHash_free(logksi->notVerified[i]);
			logksi->MerkleTree[i] = NULL;
			logksi->notVerified[i] = NULL;
			i++;
		}

		EXTRACT_TASK_freeAndClearInternals(&logksi->task.extract);
		SIGN_TASK_freeAndClearInternals(&logksi->task.sign);
		VERIFY_TASK_freeAndClearInternals(&logksi->task.verify);
		INTEGRATE_TASK_freeAndClearInternals(&logksi->task.integrate);
		EXTEND_TASK_freeAndClearInternals(&logksi->task.extend);

		free(logksi->logLine);
		KSI_DataHasher_free(logksi->hasher);


		/* Set objects to NULL. */
		logksi->prevLeaf = NULL;
		logksi->randomSeed = NULL;
		logksi->logLine = NULL;
		logksi->hasher = NULL;

		logksi->isContinuedOnFail = 0;
		logksi->blockNo = 0;
		logksi->sigNo = 0;
		logksi->taskId = TASK_NONE;
		logksi->quietError = 0;

		logksi->file.nofTotalMetarecords = 0;
		logksi->file.nofTotalRecordHashes = 0;
		logksi->file.rec_time_in_file_min = 0;
		logksi->file.rec_time_in_file_max = 0;
	}
}

void LOGKSI_clearAll(LOGKSI *logksi) {
	if (logksi != NULL) {
		memset(logksi, 0, sizeof(LOGKSI));
	}
}

void BLOCK_INFO_initialize(BLOCK_INFO *inf) {
	if (inf == NULL) return;

	memset(inf, 0, sizeof(BLOCK_INFO));

	inf->inputHash = NULL;
	inf->rootHash = NULL;
	inf->metarecordHash = NULL;

	return;
}

void BLOCK_INFO_freeAndClearInternals(BLOCK_INFO *inf) {
	if (inf == NULL) return;

	KSI_DataHash_free(inf->inputHash);
	KSI_DataHash_free(inf->rootHash);
	KSI_DataHash_free(inf->metarecordHash);

	BLOCK_INFO_initialize(inf);

	return;
}

void EXTRACT_INFO_clean(EXTRACT_INFO *obj) {
	int i = 0;
	if (obj == NULL) return;
	memset(obj, 0, sizeof(EXTRACT_INFO));

	obj->extractRecord = NULL;
	obj->metaRecord = NULL;
	obj->logLine = NULL;

	for (i = 0; i < MAX_TREE_HEIGHT; i++) {
		obj->extractChain[i].sibling = NULL;
		obj->extractChain[i].dir = LEFT_LINK;
	}

	return;
}

void EXTRACT_INFO_freeAndClearInternals(EXTRACT_INFO *obj) {
	int i = 0;
	if (obj == NULL) return;

	KSI_DataHash_free(obj->extractRecord);
	KSI_TlvElement_free(obj->metaRecord);
	free(obj->logLine);

	for (i = 0; i < obj->extractLevel; i++) {
		KSI_DataHash_free(obj->extractChain[i].sibling);
	}

	EXTRACT_INFO_clean(obj);
//	free(obj);

	return;
}


void SIGN_TASK_clean(SIGN_TASK *obj) {
	if (obj == NULL) return;
	memset(obj, 0, sizeof(SIGN_TASK));
	return;
}

void SIGN_TASK_freeAndClearInternals(SIGN_TASK *obj) {
	if (obj == NULL) return;
	SIGN_TASK_clean(obj);
	return;
}

void EXTEND_TASK_clean(EXTEND_TASK *obj) {
	if (obj == NULL) return;
	memset(obj, 0, sizeof(EXTEND_TASK));
	return;
}

void EXTEND_TASK_freeAndClearInternals(EXTEND_TASK *obj) {
	if (obj == NULL) return;
	EXTEND_TASK_clean(obj);
	return;
}

void INTEGRATE_TASK_clean(INTEGRATE_TASK *obj) {
	if (obj == NULL) return;
	memset(obj, 0, sizeof(INTEGRATE_TASK));
	return;
}

void INTEGRATE_TASK_freeAndClearInternals(INTEGRATE_TASK *obj) {
	if (obj == NULL) return;
	INTEGRATE_TASK_clean(obj);
	return;
}

void EXTRACT_TASK_clean(EXTRACT_TASK *obj) {
	if (obj == NULL) return;
	memset(obj, 0, sizeof(EXTRACT_TASK));

	obj->extractPositions = NULL;
	obj->extractMask = NULL;
	obj->metaRecord = NULL;
	obj->extractInfo = NULL;

	return;
}

void EXTRACT_TASK_freeAndClearInternals(EXTRACT_TASK *obj) {
	int i = 0;

	if (obj == NULL) return;

	free(obj->extractPositions);
	KSI_DataHash_free(obj->extractMask);
	free(obj->metaRecord);

	for (i = 0; i < obj->nofExtractPositionsInBlock; i++) {
		EXTRACT_INFO_freeAndClearInternals(&obj->extractInfo[i]);
	}

	free(obj->extractInfo);

	EXTRACT_TASK_clean(obj);

	return;
}

void VERIFY_TASK_clean(VERIFY_TASK *obj) {
	if (obj == NULL) return;
	memset(obj, 0, sizeof(VERIFY_TASK));
	obj->client_id_match = NULL;
	obj->client_id_last[0] = '\0';
	return;
}

void VERIFY_TASK_freeAndClearInternals(VERIFY_TASK *obj) {
	if (obj == NULL) return;
	REGEXP_free(obj->client_id_match);
	VERIFY_TASK_clean(obj);
	return;
}