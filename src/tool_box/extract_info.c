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
#include <ctype.h>
#include <ksi/ksi.h>
#include <ksi/tlv_element.h>
#include "logksi_err.h"
#include "err_trckr.h"
#include "tlv_object.h"
#include "smart_file.h"
#include "api_wrapper.h"
#include"rsyslog.h"
#include "extract_info.h"

static int add_hash_to_record_chain(EXTRACT_INFO *extracts, LINK_DIRECTION dir, KSI_DataHash *hash, int corr);
static int expand_extract_info(LOGKSI *logksi);
static int add_position(ERR_TRCKR *err, long int n, LOGKSI *logksi);

int block_info_extract_update_record_chain(LOGKSI *logksi, unsigned char level, int finalize, KSI_DataHash *leftLink) {
	int res;
	size_t j;
	int condition;

	if (logksi == NULL || leftLink == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	for (j = 0; j < logksi->task.extract.nofExtractPositionsInBlock; j++) {
		if (logksi->task.extract.extractInfo[j].extractOffset <= logksi->block.nofRecordHashes) {
			if (finalize) {
				condition = (level + 1 >= logksi->task.extract.extractInfo[j].extractLevel);
			} else {
				condition = (level + 1 == logksi->task.extract.extractInfo[j].extractLevel);
			}
			if (condition) {
				if (((logksi->task.extract.extractInfo[j].extractOffset - 1) >> level) & 1L) {
					res = add_hash_to_record_chain(logksi->task.extract.extractInfo + j, RIGHT_LINK, logksi->MerkleTree[level], level + 1 - logksi->task.extract.extractInfo[j].extractLevel);
				} else {
					res = add_hash_to_record_chain(logksi->task.extract.extractInfo + j, LEFT_LINK, leftLink, level + 1 - logksi->task.extract.extractInfo[j].extractLevel);
				}
				if (res != KT_OK) goto cleanup;
			}
		}
	}

	res = KT_OK;

cleanup:

	return res;
}

int block_info_extract_next_position(LOGKSI *logksi, ERR_TRCKR *err, char *range) {
	int res;
	static long int n = 0;
	static long int from = 0;
	static char *endp = NULL;
	static char digit_expected = 1;
	static char dash_allowed = 1;
	static char get_next_n = 1;
	static char *records = NULL;

	if (range == NULL || logksi == NULL) {
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
				res = add_position(err, n, logksi);
				if (res != KT_OK) goto cleanup;
				records = endp;
				digit_expected = 0;
				goto cleanup;
			} else if (from < n) {
				/* Add the next position in the range. */
				from++;
				res = add_position(err, from, logksi);
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

int block_info_extract_update(LOGKSI *logksi, ERR_TRCKR *err, int isMetaRecordHash, KSI_DataHash *hash) {
	int res;
	EXTRACT_INFO *extractInfo = NULL;

	if (logksi == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/*
	 * Enter only if not all extract positions are found AND
	 * Current record hash is at desired position
	 */
	if (logksi->task.extract.nofExtractPositionsFound < logksi->task.extract.nofExtractPositions &&
		logksi->task.extract.extractPositions[logksi->task.extract.nofExtractPositionsFound] - logksi->file.nofTotalRecordHashes == logksi->block.nofRecordHashes) {
		/* make room in extractInfo */
		res = expand_extract_info(logksi);
		if (res != KT_OK) goto cleanup;

		extractInfo = &logksi->task.extract.extractInfo[logksi->task.extract.nofExtractPositionsInBlock - 1];

		extractInfo->extractPos = logksi->task.extract.extractPositions[logksi->task.extract.nofExtractPositionsFound];
		extractInfo->extractOffset = logksi->block.nofRecordHashes;
		extractInfo->extractRecord = KSI_DataHash_ref(hash);
		if (!isMetaRecordHash) {
			extractInfo->metaRecord = NULL;
			extractInfo->logLine = strdup(logksi->logLine);
			if (extractInfo->logLine == NULL) {
				res = KT_OUT_OF_MEMORY;
				goto cleanup;
			}
		} else {
			extractInfo->logLine = NULL;
			res = KSI_TlvElement_parse(logksi->task.extract.metaRecord, 0xffff, &extractInfo->metaRecord);
			if (res != KT_OK) goto cleanup;
		}
		logksi->task.extract.nofExtractPositionsFound++;

		if (isMetaRecordHash) {
			res = add_hash_to_record_chain(extractInfo, LEFT_LINK, logksi->task.extract.extractMask, 0);
		} else {
			res = add_hash_to_record_chain(extractInfo, RIGHT_LINK, logksi->task.extract.extractMask, 0);
		}
		if (res != KT_OK) goto cleanup;

		if (logksi->task.extract.records && logksi->task.extract.nofExtractPositionsFound == logksi->task.extract.nofExtractPositions) {
			res = block_info_extract_next_position(logksi, err, logksi->task.extract.records);
			if (res != KT_OK) goto cleanup;
		}
	}


	res = KT_OK;

cleanup:

	return res;
}

int block_info_extract_verify_positions(ERR_TRCKR *err, char *records) {
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

static int add_position(ERR_TRCKR *err, long int n, LOGKSI *logksi) {
	int res;
	size_t *tmp = NULL;

	if (n <= 0 || logksi == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (logksi->task.extract.nofExtractPositions) {
		if (n <= logksi->task.extract.extractPositions[logksi->task.extract.nofExtractPositions - 1]) {
			res = KT_INVALID_CMD_PARAM;
			ERR_CATCH_MSG(err, res, "Error: List of positions must be given in strictly ascending order.");
		}
	}

	if (logksi->task.extract.extractPositions == NULL) {
		tmp = (size_t*)malloc(sizeof(size_t));
	} else {
		tmp = (size_t*)realloc(logksi->task.extract.extractPositions, sizeof(size_t) * (logksi->task.extract.nofExtractPositions + 1));
	}

	if (tmp == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	logksi->task.extract.extractPositions = tmp;
	tmp = NULL;
	logksi->task.extract.extractPositions[logksi->task.extract.nofExtractPositions] = n;
	logksi->task.extract.nofExtractPositions++;
	res = KT_OK;


cleanup:

	return res;
}

static int expand_extract_info(LOGKSI *logksi) {
	int res;
	EXTRACT_INFO *tmp = NULL;

	if (logksi == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (logksi->task.extract.extractInfo == NULL) {
		tmp = (EXTRACT_INFO*)malloc(sizeof(EXTRACT_INFO));
	} else {
		tmp = (EXTRACT_INFO*)realloc(logksi->task.extract.extractInfo, sizeof(EXTRACT_INFO) * (logksi->task.extract.nofExtractPositionsInBlock + 1));
	}

	if (tmp == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	logksi->task.extract.extractInfo = tmp;

	/**
	 * TODO:
	 * TODO:
	 * TODO:
	 * TODO:
	 * TODO:
	 * TODO: Siin teha clean funktsiooniga.
	 */


	tmp = NULL;
	memset(logksi->task.extract.extractInfo + logksi->task.extract.nofExtractPositionsInBlock, 0, sizeof(EXTRACT_INFO));
	logksi->task.extract.nofExtractPositionsInBlock++;
	res = KT_OK;

cleanup:

	free(tmp);
	return res;
}

static int add_hash_to_record_chain(EXTRACT_INFO *extracts, LINK_DIRECTION dir, KSI_DataHash *hash, int corr) {
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