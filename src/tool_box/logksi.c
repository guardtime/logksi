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
#include "logksi.h"
#include "logksi_impl.h"
#include "extract_info.h"
#include "merkle_tree.h"

static void extract_task_free_and_clear_internals(EXTRACT_TASK *obj);
static void sign_task_free_and_clear_internals(SIGN_TASK *obj);
static void verify_task_free_and_clear_internals(VERIFY_TASK *obj);
static void extend_task_free_and_clear_internals(EXTEND_TASK *obj);
static void integrate_task_free_and_clear_internals(INTEGRATE_TASK *obj);
static void file_info_free_and_clear_internals(FILE_INFO *obj);
static void block_info_free_and_clear_internals(BLOCK_INFO *obj);

static void extract_task_initialize(EXTRACT_TASK *obj);
static void sign_task_initialize(SIGN_TASK *obj);
static void verify_task_initialize(VERIFY_TASK *obj);
static void extend_task_initialize(EXTEND_TASK *obj);
static void integrate_task_initialize(INTEGRATE_TASK *obj);
static void file_info_initialize(FILE_INFO *obj);
static void block_info_initialize(BLOCK_INFO *obj);

static void block_info_reset_block_info(BLOCK_INFO *obj);
static void extract_task_reset_block_info(EXTRACT_TASK *obj);
static void integrate_task_reset_block_info(INTEGRATE_TASK *obj);
static void sign_task_reset_block_info(SIGN_TASK *obj);
static void extend_task_reset_block_info(EXTEND_TASK *obj);

void LOGKSI_initialize(LOGKSI *obj) {
	if (obj == NULL) return;

	obj->taskId = TASK_NONE;
	obj->blockNo = 0;
	obj->currentLine = 0;
	obj->quietError = 0;
	obj->isContinuedOnFail = 0;
	obj->sigNo = 0;
	obj->sigTime_0 = 0;

	obj->ftlv_len = 0;
	obj->ftlv_raw = NULL;

	obj->err = NULL;
	obj->tree = NULL;
	obj->logLine = NULL;

	extract_task_initialize(&obj->task.extract);
	sign_task_initialize(&obj->task.sign);
	verify_task_initialize(&obj->task.verify);
	extend_task_initialize(&obj->task.extend);
	integrate_task_initialize(&obj->task.integrate);

	file_info_initialize(&obj->file);
	block_info_initialize(&obj->block);

	return;
}

void LOGKSI_freeAndClearInternals(LOGKSI *logksi) {
	if (logksi == NULL) return;

	MERKLE_TREE_free(logksi->tree);
	if (logksi->logLine) free(logksi->logLine);

	extract_task_free_and_clear_internals(&logksi->task.extract);
	sign_task_free_and_clear_internals(&logksi->task.sign);
	verify_task_free_and_clear_internals(&logksi->task.verify);
	integrate_task_free_and_clear_internals(&logksi->task.integrate);
	extend_task_free_and_clear_internals(&logksi->task.extend);

	file_info_free_and_clear_internals(&logksi->file);
	block_info_free_and_clear_internals(&logksi->block);

	LOGKSI_initialize(logksi);

	return;
}

void LOGKSI_resetBlockInfo(LOGKSI *logksi) {
	if (logksi == NULL) return;
	block_info_reset_block_info(&logksi->block);
	extract_task_reset_block_info(&logksi->task.extract);
	integrate_task_reset_block_info(&logksi->task.integrate);
	sign_task_reset_block_info(&logksi->task.sign);
	extend_task_reset_block_info(&logksi->task.extend);
}

int LOGKSI_get_aggregation_level(LOGKSI *logksi) {
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

int LOGKSI_calculate_hash_of_logline_and_store_logline(LOGKSI *logksi, IO_FILES *files, KSI_DataHash **hash) {
	int res;
	KSI_DataHash *tmp = NULL;
	KSI_DataHasher *pHasher = NULL;
	/* Maximum line size is 64K characters, without newline character. */
	char buf[0x10000 + 2];

	if (files == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = MERKLE_TREE_getHasher(logksi->tree, &pHasher);
	if (res != KSI_OK) goto cleanup;

	if (files->files.inLog) {
		res = SMART_FILE_gets(files->files.inLog, buf, sizeof(buf), NULL);
		if (res != SMART_FILE_OK) goto cleanup;

		res = KSI_DataHasher_reset(pHasher);
		if (res != KSI_OK) goto cleanup;

		/* Last character (newline) is not used in hash calculation. */
		res = KSI_DataHasher_add(pHasher, buf, strlen(buf) - 1);
		if (res != KSI_OK) goto cleanup;

		res = KSI_DataHasher_close(pHasher, &tmp);
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
	logksi->task.extract.metaRecord_len = len;
	buf = NULL;

	res = KT_OK;

cleanup:

	free(buf);
	return res;
}

int LOGKSI_calculate_hash_of_metarecord_and_store_metarecord(LOGKSI *logksi, KSI_TlvElement *tlv, KSI_DataHash **hash) {
	int res;
	KSI_DataHash *tmp = NULL;
	KSI_DataHasher *pHasher = NULL;

	if (tlv == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = MERKLE_TREE_getHasher(logksi->tree, &pHasher);
	if (res != KSI_OK) goto cleanup;

	res = KSI_DataHasher_reset(pHasher);
	if (res != KSI_OK) goto cleanup;

	/* The complete metarecord TLV us used in hash calculation. */
	res = KSI_DataHasher_add(pHasher, tlv->ptr, tlv->ftlv.hdr_len + tlv->ftlv.dat_len);
	if (res != KSI_OK) goto cleanup;

	res = KSI_DataHasher_close(pHasher, &tmp);
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












static void extract_task_initialize(EXTRACT_TASK *obj) {
	if (obj == NULL) return;
	obj->info = NULL;
	obj->metaRecord = NULL;
	obj->metaRecord_len = 0;
	return;
}

static void sign_task_initialize(SIGN_TASK *obj) {
	if (obj == NULL) return;
	obj->blockCount = 0;
	obj->curBlockJustReSigned = 0;
	obj->noSigCount = 0;
	obj->noSigCreated = 0;
	obj->noSigNo = 0;
	obj->outSigModified = 0;
	return;
}

static void verify_task_initialize(VERIFY_TASK *obj) {
	if (obj == NULL) return;
	obj->errSignTime = 0;
	obj->lastBlockWasSkipped = 0;
	obj->client_id_match = NULL;
	obj->client_id_last[0] = '\0';
	return;
}

static void extend_task_initialize(EXTEND_TASK *obj) {
	if (obj == NULL) return;
	obj->extendedToTime = 0;
	return;
}

static void integrate_task_initialize(INTEGRATE_TASK *obj) {
	if (obj == NULL) return;
	obj->partNo = 0;
	obj->unsignedRootHash = 0;
	obj->warningSignatures = 0;
	return;
}

static void file_info_initialize(FILE_INFO *obj) {
	if (obj == NULL) return;
	obj->nofTotaHashFails = 0;
	obj->nofTotalFailedBlocks = 0;
	obj->nofTotalMetarecords = 0;
	obj->nofTotalRecordHashes = 0;
	obj->recTimeMax = 0;
	obj->recTimeMin = 0;
	obj->version = UNKN_VER;
	obj->warningLegacy = 0;
	obj->warningTreeHashes = 0;
	return;
}

static void block_info_initialize(BLOCK_INFO *obj) {
	if (obj == NULL) return;

	obj->curBlockNotSigned = 0;
	obj->finalTreeHashesAll = 0;
	obj->finalTreeHashesLeaf = 0;
	obj->finalTreeHashesNone = 0;
	obj->finalTreeHashesSome = 0;
	obj->firstLineNo = 0;
	obj->keepRecordHashes = 0;
	obj->keepTreeHashes = 0;
	obj->nofHashFails = 0;
	obj->nofMetaRecords = 0;
	obj->nofRecordHashes = 0;
	obj->nofTreeHashes = 0;
	obj->recTimeMax = 0;
	obj->recTimeMin = 0;
	obj->recordCount = 0;
	obj->sigTime_1 = 0;
	obj->signatureTLVReached = 0;

	obj->hashAlgo = KSI_HASHALG_INVALID_VALUE;

	obj->inputHash = NULL;
	obj->rootHash = NULL;
	obj->metarecordHash = NULL;

	return;
}



static void extract_task_free_and_clear_internals(EXTRACT_TASK *obj) {
	if (obj == NULL) return;
	if (obj->metaRecord) free(obj->metaRecord);
	EXTRACT_INFO_free(obj->info);
	extract_task_initialize(obj);
	return;
}

static void sign_task_free_and_clear_internals(SIGN_TASK *obj) {
	if (obj == NULL) return;
	sign_task_initialize(obj);
	return;
}

static void verify_task_free_and_clear_internals(VERIFY_TASK *obj) {
	if (obj == NULL) return;
	REGEXP_free(obj->client_id_match);
	verify_task_initialize(obj);
	return;
}

static void integrate_task_free_and_clear_internals(INTEGRATE_TASK *obj) {
	if (obj == NULL) return;
	integrate_task_initialize(obj);
	return;
}

static void extend_task_free_and_clear_internals(EXTEND_TASK *obj) {
	if (obj == NULL) return;
	extend_task_initialize(obj);
	return;
}

static void file_info_free_and_clear_internals(FILE_INFO *obj) {
	if (obj == NULL) return;
	file_info_initialize(obj);
	return;
}

static void block_info_free_and_clear_internals(BLOCK_INFO *obj) {
	if (obj == NULL) return;

	KSI_DataHash_free(obj->inputHash);
	KSI_DataHash_free(obj->rootHash);
	KSI_DataHash_free(obj->metarecordHash);

	block_info_initialize(obj);

	return;
}



static void block_info_reset_block_info(BLOCK_INFO *obj) {
	block_info_free_and_clear_internals(obj);
}

static void extract_task_reset_block_info(EXTRACT_TASK *obj) {
	if (obj == NULL) return;
	free(obj->metaRecord);
	obj->metaRecord = NULL;
	EXTRACT_INFO_resetBlockInfo(obj->info);
	return;
}

static void integrate_task_reset_block_info(INTEGRATE_TASK *obj) {
	if (obj == NULL) return;
	obj->unsignedRootHash = 0;
	return;
}

static void sign_task_reset_block_info(SIGN_TASK *obj) {
	if (obj == NULL) return;
	obj->curBlockJustReSigned = 0;
	return;
}

static void extend_task_reset_block_info(EXTEND_TASK *obj) {
	if (obj == NULL) return;
	obj->extendedToTime = 0;
	return;
}
