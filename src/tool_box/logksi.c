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
#include "logksi_err.h"
#include "logksi.h"
#include "logksi_impl.h"

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
static void logksi_reset_block_info(LOGKSI *logksi);

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
	obj->logLine_capacity = 0;
	obj->logLine_len = 0;

	obj->logksiVerRes = LOGKSI_VER_RES_INVALID;

	extract_task_initialize(&obj->task.extract);
	sign_task_initialize(&obj->task.sign);
	verify_task_initialize(&obj->task.verify);
	extend_task_initialize(&obj->task.extend);
	integrate_task_initialize(&obj->task.integrate);

	file_info_initialize(&obj->file);
	block_info_initialize(&obj->block);

	return;
}

static int logksi_get_line_buffer(LOGKSI *logksi, int incr, char **buf, size_t *capacity) {
	char *tmp = NULL;
	size_t new_cap = 0;

	if (logksi == NULL || buf == NULL || capacity == NULL) return KT_INVALID_ARGUMENT;

	if (logksi->logLine_capacity == 0 || incr) {
		if (logksi->logLine_capacity == LINE_BUFFER_LIMIT) return KT_INDEX_OVF;

		new_cap = logksi->logLine_capacity == 0 ? (1024) : (logksi->logLine_capacity * 2);
		if (new_cap > LINE_BUFFER_LIMIT) new_cap = LINE_BUFFER_LIMIT;
		tmp = realloc(logksi->logLine, new_cap);
		if (tmp == NULL) return KT_OUT_OF_MEMORY;

		logksi->logLine_capacity = new_cap;
		logksi->logLine = tmp;
		tmp = NULL;
	}

	*buf = logksi->logLine;
	*capacity = logksi->logLine_capacity;

	return KT_OK;
}

int LOGKSI_readLine(LOGKSI *logksi, SMART_FILE *file) {
	int res = KT_UNKNOWN_ERROR;
	int i = 0;
	char *buf = NULL;
	size_t buf_cap;
	size_t read_count = 0;

	if (logksi == NULL || file == NULL) return KT_INVALID_ARGUMENT;

	do {
		size_t c = 0;

		res = logksi_get_line_buffer(logksi, i > 0, &buf, &buf_cap);
		if (res != KT_OK) return res;

		res = SMART_FILE_readLine(file, buf + read_count, buf_cap - read_count - 2, &c);
		if (res != SMART_FILE_OK && res != SMART_FILE_BUFFER_TOO_SMALL) return res;

		read_count += c;
		i++;
	} while(res == SMART_FILE_BUFFER_TOO_SMALL);

	buf[read_count] = '\n';
	buf[read_count + 1] = '\0';
	logksi->logLine_len = read_count + 1;

	return KT_OK;
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



/* Called right before process_block_header. */
int LOGKSI_initNextBlock(LOGKSI *logksi) {
	if (logksi == NULL) return KT_INVALID_ARGUMENT;

	logksi->blockNo++;

	/* Previous and current (next) signature time. Note that 0 indicates not set. */
	if (logksi->block.sigTime_1 > 0 || logksi->block.curBlockNotSigned) {
		logksi->sigTime_0 = logksi->block.sigTime_1;
		logksi->block.sigTime_1 = 0;
	}

	logksi_reset_block_info(logksi);

	logksi->block.firstLineNo = logksi->file.nofTotalRecordHashes + 1;

	return KT_OK;
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

int LOGKSI_hasWarnings(LOGKSI *logksi) {
	if (logksi) {
		if (logksi->task.integrate.warningSignatures || logksi->file.warningTreeHashes || logksi->file.warningLegacy) {
			return 1;
		}
	}
	return 0;
}

int LOGKSI_getMaxFinalHashes(LOGKSI *logksi) {
	int finalHashes = 0;
	int i;
	if (logksi) {
		for (i = 0; i < MERKLE_TREE_getHeight(logksi->tree); i++) {
			KSI_DataHash *hsh = NULL;
			int res = KT_UNKNOWN_ERROR;

			res = MERKLE_TREE_getSubTreeRoot(logksi->tree, i, &hsh);
			if (res != KT_OK) return finalHashes;

			if (hsh != NULL) {
				finalHashes++;
			}

			KSI_DataHash_free(hsh);
		}
		finalHashes--;
	}
	return finalHashes;
}


size_t LOGKSI_getNofLines(LOGKSI *logksi) {
	if (logksi) {
		return logksi->block.nofRecordHashes + logksi->file.nofTotalRecordHashes;
	} else {
		return 0;
	}
}

int LOGKSI_setErrorLevel(LOGKSI *logksi, int lvl) {
	if (logksi == NULL || lvl == LOGKSI_VER_RES_INVALID || lvl >= LOGKSI_VER_RES_COUNT) return KT_INVALID_ARGUMENT;
	if (logksi->logksiVerRes < lvl) logksi->logksiVerRes = lvl;
	return KT_OK;
}

int LOGKSI_getErrorLevel(LOGKSI *logksi) {
	if (logksi == NULL) return LOGKSI_VER_RES_INVALID;
	return logksi->logksiVerRes;
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

static void logksi_reset_block_info(LOGKSI *logksi) {
	if (logksi == NULL) return;
	block_info_reset_block_info(&logksi->block);
	extract_task_reset_block_info(&logksi->task.extract);
	integrate_task_reset_block_info(&logksi->task.integrate);
	sign_task_reset_block_info(&logksi->task.sign);
	extend_task_reset_block_info(&logksi->task.extend);
}

struct STATE_FILE_st {
	LOGSIG_VERSION ver;
	SMART_FILE *state_file;
	KSI_DataHash *hash;
	KSI_HashAlgorithm aggrAlgo;
};

int STATE_FILE_open(int readOnly, const char *fname, KSI_CTX *ksi, STATE_FILE **state) {
	int res = KT_OK;
	SMART_FILE *tmp_in_out_file = NULL;
	KSI_DataHash *tmp_hash = NULL;
	STATE_FILE *tmp = NULL;
	LOGSIG_VERSION ver = KSISTAT10;		/* Init with default version. */
	uint8_t algo = 0;
	uint8_t digest_len = 0;
	KSI_HashAlgorithm aggrAlgo = KSI_HASHALG_INVALID_VALUE;
	size_t read_count = 0;


	if (state == NULL) return KT_INVALID_ARGUMENT;

	if (SMART_FILE_doFileExist(fname)) {
		unsigned char digest[256];
		unsigned char dummy;

		res = SMART_FILE_open(fname, "rb", &tmp_in_out_file);
		if (res != SMART_FILE_OK) goto cleanup;

		ver = LOGSIG_VERSION_getFileVer(tmp_in_out_file);
		switch(ver) {
			case KSISTAT10:
				res = SMART_FILE_read(tmp_in_out_file, (unsigned char*)&algo, 1, &read_count);
				if (res != SMART_FILE_OK) goto cleanup;

				if (read_count != 1) {
					res = KT_UNEXPECTED_EOF;
					goto cleanup;
				}

				if (KSI_getHashLength(algo) == 0) {
					res = KSI_UNKNOWN_HASH_ALGORITHM_ID;
					goto cleanup;
				}

				if (!KSI_isHashAlgorithmSupported(algo)) {
					res = KSI_UNAVAILABLE_HASH_ALGORITHM;
					goto cleanup;
				}

				if (!KSI_isHashAlgorithmTrusted(algo)) {
					res = KSI_UNTRUSTED_HASH_ALGORITHM;
					goto cleanup;
				}

				res = SMART_FILE_read(tmp_in_out_file, (unsigned char*)&digest_len, 1, &read_count);
				if (res != SMART_FILE_OK) goto cleanup;

				if (read_count != 1) {
					res = KT_UNEXPECTED_EOF;
					goto cleanup;
				}

				if (digest_len != KSI_getHashLength(algo)) {
					res = KT_INVALID_INPUT_FORMAT;
					goto cleanup;
				}

				res = SMART_FILE_read(tmp_in_out_file, digest, digest_len, &read_count);
				if (res != SMART_FILE_OK) goto cleanup;

				if (read_count != digest_len) {
					res = KT_UNEXPECTED_EOF;
					goto cleanup;
				}

				res = SMART_FILE_read(tmp_in_out_file, &dummy, 1, &read_count);
				if (res != SMART_FILE_OK) goto cleanup;

				if (!SMART_FILE_isEof(tmp_in_out_file)) {
					res = KT_INVALID_INPUT_FORMAT;
					goto cleanup;
				}

				res = KSI_DataHash_fromDigest(ksi, algo, digest, digest_len, &tmp_hash);
				if (res != SMART_FILE_OK) goto cleanup;

				res = KSI_DataHash_getHashAlg(tmp_hash, &aggrAlgo);
				if (res != SMART_FILE_OK) goto cleanup;

				res = SMART_FILE_close(tmp_in_out_file);
				if (res != SMART_FILE_OK) goto cleanup;

				tmp_in_out_file = NULL;
			break;
			default:
				res = KT_INVALID_INPUT_FORMAT;
				goto cleanup;
		}
	} else if (readOnly && fname != NULL) {
		res = KT_IO_ERROR;
		goto cleanup;
	}

	if (!readOnly && fname != NULL) {
		res = SMART_FILE_open(fname, "wb", &tmp_in_out_file);
		if (res != SMART_FILE_OK) goto cleanup;
	}

	tmp = malloc(sizeof(STATE_FILE));
	if (tmp == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ver = ver;
	tmp->state_file = tmp_in_out_file;
	tmp->hash = tmp_hash;
	tmp->aggrAlgo = aggrAlgo;
	tmp_in_out_file = NULL;
	tmp_hash = NULL;
	*state = tmp;
	tmp = NULL;

	res = KT_OK;

cleanup:

	SMART_FILE_close(tmp_in_out_file);
	KSI_DataHash_free(tmp_hash);
	free(tmp);

	return res;
}

int STATE_FILE_update(STATE_FILE *state, KSI_DataHash *hash) {
	int res = KT_UNKNOWN_ERROR;
	if(state == NULL || hash == NULL) return KT_INVALID_ARGUMENT;

	KSI_DataHash_free(state->hash);
	state->hash = KSI_DataHash_ref(hash);

	if (state->aggrAlgo == KSI_HASHALG_INVALID_VALUE) {
		res = KSI_DataHash_getHashAlg(hash, &state->aggrAlgo);
		if (res != KSI_OK) goto cleanup;
	}

	if (state->state_file != NULL) {
		const char *magic = NULL;
		KSI_HashAlgorithm algo = 0;
		const unsigned char *digest = NULL;
		size_t digest_len = 0;
		uint8_t algo_and_len[2];

		magic = LOGSIG_VERSION_toString(state->ver);
		if (magic == NULL) {
			res = KT_UNKNOWN_ERROR;
			goto cleanup;
		}

		res = KSI_DataHash_extract(hash, &algo, &digest, &digest_len);
		if (res != KT_OK) goto cleanup;

		if (digest_len > 0xff) {
			res = KT_UNKNOWN_ERROR;
			goto cleanup;
		}

		algo_and_len[0] = algo;
		algo_and_len[1] = digest_len;

		res = SMART_FILE_rewind(state->state_file);
		if (res != KT_OK) goto cleanup;
		res = SMART_FILE_write(state->state_file, (const unsigned char*)magic, strlen(magic), NULL);
		if (res != KT_OK) goto cleanup;
		res = SMART_FILE_write(state->state_file, algo_and_len, 2, NULL);
		if (res != KT_OK) goto cleanup;
		res = SMART_FILE_write(state->state_file, digest, digest_len, NULL);
		if (res != KT_OK) goto cleanup;
	}

	res = KT_OK;

cleanup:

	return res;

}

void STATE_FILE_close(STATE_FILE *state) {
	if (state == NULL) return;
	SMART_FILE_close(state->state_file);
	KSI_DataHash_free(state->hash);
	free(state);
	return;
}

KSI_DataHash* STATE_FILE_lastLeaf(STATE_FILE *state) {
	if (state == NULL) return NULL;
	return state->hash;
}

KSI_HashAlgorithm STATE_FILE_hashAlgo(STATE_FILE *state) {
	if (state == NULL) return KSI_HASHALG_INVALID_VALUE;
	return state->aggrAlgo;
}

int STATE_FILE_setHashAlgo(STATE_FILE *state, KSI_HashAlgorithm algo) {
	if (state == NULL) return KT_INVALID_ARGUMENT;
	state->aggrAlgo = algo;
	return KT_OK;
}