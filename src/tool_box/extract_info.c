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
#include "merkle_tree.h"
#include "extract_info.h"

typedef struct NEXT_REC_st NEXT_REC;

static int next_rec_reset(NEXT_REC *recextract, const char *range);
static int next_rec_extract_next_position(NEXT_REC *recextract, long *position);
static int foldl_aggr_chain(void *acc, LINK_DIRECTION dir, KSI_DataHash *sibling, size_t corr);
static int record_info_set_value(RECORD_INFO *extractInfo, size_t pos, size_t offs, KSI_DataHash *hsh, int isMetaRecordHash, void *raw, size_t len);
static void record_info_clean(RECORD_INFO *obj);

static int extract_info_add_position(EXTRACT_INFO *extract, long int n);
static int extract_info_register_next_extract_position(EXTRACT_INFO *info);
static int extract_info_add_position(EXTRACT_INFO *extract, long int n);

#define REC_SIZE_INCR 32


typedef struct REC_CHAIN_st {
	LINK_DIRECTION dir;
	KSI_DataHash *sibling;
	size_t corr;
} REC_CHAIN;

struct RECORD_INFO_st {
	size_t extractLine;							/* Position of the current record (log line number). */
	size_t extractOffset;						/* Record position in tree (count of record hashes and meta record hashes). */
	size_t extractLevel;						/* Level of the record chain root. */
	char *logLine;								/* Log line thats record chain is extracted. */
	KSI_TlvElement *metaRecord;
	KSI_DataHash *extractRecord;				/* Hash value thats record chain is extracted. */
	REC_CHAIN extractChain[MAX_TREE_HEIGHT];	/* Record chain. */
};

struct NEXT_REC_st {
	long int n;
	long int from;
	char *endp;
	char digit_expected;
	char dash_allowed;
	char get_next_n;
	const char *records;
};

struct EXTRACT_INFO_st {
	const char *pRange;					/* (old name records) Reference to PARAM_SET value. Maybe rename or make as const. */
	size_t *extractPositions;			/* Array containing list of extract positions (log line numbers). */
	size_t nofExtractPositions;			/* Count of all extract positions (in extractPositions). */
	size_t nofExtractPositionsFound;	/* Count of all extract positions found. */

	NEXT_REC recExtract;				/* Helper data struct to extract record values from range string. */

	RECORD_INFO *records;				/* Actual data structures containing extracted hash value and matching record chain. */
	size_t records_capacity;			/* The size of extractPositions array. */
	size_t nofExtractPositionsInBlock;	/* Count of \c records elements in array. Incremented by EXTRACT_INFO_getNew. */
};

struct aggr_chain_fold_st {
	KSI_HashChainLinkList *chainList;
	KSI_HashAlgorithm hashAlgo;
	KSI_CTX *ksi;
};

int EXTRACT_INFO_new(const char *range, EXTRACT_INFO **info) {
	int res = KT_UNKNOWN_ERROR;
	EXTRACT_INFO *tmp = NULL;

	if (info == NULL || range == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = (EXTRACT_INFO*)malloc(sizeof(EXTRACT_INFO));
	if (tmp == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->records_capacity = 0;
	tmp->nofExtractPositions = 0;
	tmp->nofExtractPositionsFound = 0;
	tmp->nofExtractPositionsInBlock = 0;
	tmp->pRange = range;

	tmp->extractPositions = NULL;
	tmp->records = NULL;

	res = next_rec_reset(&tmp->recExtract, tmp->pRange);
	if (res != KT_OK) goto cleanup;

	res = extract_info_register_next_extract_position(tmp);
	if (res != KT_OK) goto cleanup;

	*info = tmp;
	tmp = NULL;

	res = KT_OK;

cleanup:

	free(tmp);

	return res;
}




int RECORD_INFO_setRecordHash(RECORD_INFO *extractInfo, size_t pos, size_t offs, KSI_DataHash *hsh, const char *logLine) {
	return record_info_set_value(extractInfo, pos, offs, hsh, 0, (void*)logLine, 0);
}

int RECORD_INFO_setMetaRecordHash(RECORD_INFO *extractInfo, size_t pos, size_t offs, KSI_DataHash *hsh, unsigned char *raw, size_t raw_len) {
	return record_info_set_value(extractInfo, pos, offs, hsh, 1, raw, raw_len);
}

int RECORD_INFO_add_hash_to_record_chain(RECORD_INFO *extracts, LINK_DIRECTION dir, KSI_DataHash *hash, int corr) {
	int res;

	if (extracts == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (extracts->extractLevel >= MAX_TREE_HEIGHT) {
		res = KT_INDEX_OVF;
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

int RECORD_INFO_getLine(RECORD_INFO *record, size_t *lineNr, char **logLine) {
	if (record == NULL || (lineNr == NULL && logLine == NULL)) return KT_INVALID_ARGUMENT;
	if (lineNr) *lineNr = record->extractLine;
	if (logLine) *logLine = record->logLine;
	return KT_OK;
}

int RECORD_INFO_getPositionInTree(RECORD_INFO *record, size_t *recordOffset, size_t *recordRootLvl) {
	if (record == NULL || (recordOffset == NULL && recordRootLvl != NULL)) return KT_INVALID_ARGUMENT;
	if (recordOffset) *recordOffset = record->extractOffset;
	if (recordRootLvl) *recordRootLvl = record->extractLevel;
	return KT_OK;
}

int RECORD_INFO_getRecordHash(RECORD_INFO *record, KSI_DataHash **extractRecord) {
	if (record == NULL || extractRecord == NULL) return KT_INVALID_ARGUMENT;
	*extractRecord = KSI_DataHash_ref(record->extractRecord);
	return KT_OK;
}

int RECORD_INFO_getMetadata(RECORD_INFO *record, KSI_TlvElement **metaRecord) {
	if (record == NULL || metaRecord == NULL) return KT_INVALID_ARGUMENT;
	*metaRecord = KSI_TlvElement_ref(record->metaRecord);
	return KT_OK;
}

int RECORD_INFO_foldl(RECORD_INFO *record,
					void *acc,
					int (*f)(void *, LINK_DIRECTION, KSI_DataHash*, size_t)) {
	int res = KT_UNKNOWN_ERROR;
	size_t i = 0;

	if (record == NULL || acc == NULL || f == NULL) return KT_INVALID_ARGUMENT;

	for (i = 0; i < record->extractLevel; i++) {
		res = f(acc, record->extractChain[i].dir, record->extractChain[i].sibling, record->extractChain[i].corr);
		if (res != KT_OK) return res;
	}

	return KT_OK;
}

int RECORD_INFO_getAggregationHashChain(RECORD_INFO *record, KSI_CTX *ksi, KSI_AggregationHashChain **aggrChain) {
	KSI_HashChainLinkList *chainList;
	KSI_AggregationHashChain *tmp = NULL;
	KSI_DataHash *hashRef = NULL;
	KSI_Integer *hashId = NULL;

	int res = KT_INVALID_ARGUMENT;
	struct aggr_chain_fold_st acc;

	if (ksi == NULL || record == NULL || aggrChain == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;

	}

	/* Create a list for aggregation hash chain links, fold over
	 * extract records and fill the list. */
	res = KSI_HashChainLinkList_new(&chainList);
	if (res != KSI_OK) goto cleanup;

	acc.chainList = chainList;
	acc.ksi = ksi;
	acc.hashAlgo = KSI_HASHALG_INVALID_VALUE;

	res = RECORD_INFO_foldl(record, &acc, foldl_aggr_chain);
	if (res != KT_OK) return res;

	/* Create aggregation hash chain and fill its fields. */
	res = KSI_AggregationHashChain_new(acc.ksi, &tmp);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AggregationHashChain_setChain(tmp, chainList);
	if (res != KSI_OK) goto cleanup;
	chainList = NULL;

	hashRef = KSI_DataHash_ref(record->extractRecord);
	res = KSI_AggregationHashChain_setInputHash(tmp, hashRef);
	if (res != KSI_OK) goto cleanup;
	hashRef = NULL;

	res = KSI_Integer_new(acc.ksi, acc.hashAlgo, &hashId);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AggregationHashChain_setAggrHashId(tmp, hashId);
	if (res != KSI_OK) goto cleanup;
	hashId = NULL;

	*aggrChain = tmp;
	tmp = NULL;


cleanup:

	KSI_AggregationHashChain_free(tmp);
	KSI_DataHash_free(hashRef);
	KSI_Integer_free(hashId);
	KSI_HashChainLinkList_free(chainList);
	return KT_OK;
}


void EXTRACT_INFO_resetBlockInfo(EXTRACT_INFO *extract) {
	size_t i = 0;
	size_t j = 0;

	if (extract == NULL) return;

	for (j = 0; j < extract->nofExtractPositionsInBlock; j++) {
		for (i = 0; i < extract->records[j].extractLevel; i++) {
			KSI_DataHash_free(extract->records[j].extractChain[i].sibling);
			extract->records[j].extractChain[i].sibling = NULL;
		}
		extract->records[j].extractLevel = 0;
		KSI_DataHash_free(extract->records[j].extractRecord);
		extract->records[j].extractRecord = NULL;
		free(extract->records[j].logLine);
		extract->records[j].logLine = NULL;
		KSI_TlvElement_free(extract->records[j].metaRecord);
		extract->records[j].metaRecord = NULL;
	}

	extract->nofExtractPositionsInBlock = 0;

	return;
}

void EXTRACT_INFO_free(EXTRACT_INFO *extract) {
	if (extract == NULL) return;

	if (extract->extractPositions) free(extract->extractPositions);

	/* Free data allocated during last block. */
	EXTRACT_INFO_resetBlockInfo(extract);
	if (extract->records) free(extract->records);
	free(extract);
}

int EXTRACT_INFO_getNewRecord(EXTRACT_INFO *extract, size_t *index, RECORD_INFO **info) {
	int res;
	RECORD_INFO *tmp = NULL;

	if (extract == NULL || info == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (extract->records_capacity < extract->nofExtractPositionsInBlock + 1) {
		size_t new_size = 0;

		if (extract->records_capacity == 0) {
			new_size = REC_SIZE_INCR;
			tmp = (RECORD_INFO*)malloc(sizeof(RECORD_INFO) * new_size);
		} else {
			new_size = extract->records_capacity + REC_SIZE_INCR;
			tmp = (RECORD_INFO*)realloc(extract->records, sizeof(RECORD_INFO) * new_size);
		}

		if (tmp == NULL) {
			res = KT_OUT_OF_MEMORY;
			goto cleanup;
		}

		extract->records_capacity = new_size;

		extract->records = tmp;
		tmp = NULL;
	}

	/* Clean next extract position. */
	record_info_clean(&extract->records[extract->nofExtractPositionsInBlock]);
	*info = &extract->records[extract->nofExtractPositionsInBlock];

	if (index != NULL) {
		*index = extract->nofExtractPositionsInBlock;
	}

	extract->nofExtractPositionsInBlock++;

	res = KT_OK;

cleanup:

	free(tmp);

	return res;
}

int EXTRACT_INFO_isLastPosPending(EXTRACT_INFO *info) {
	if (info == NULL) return 0;
	return info->nofExtractPositionsFound < info->nofExtractPositions;
}

int EXTRACT_INFO_moveToNext(EXTRACT_INFO *info) {
	if (info == NULL) return KT_INVALID_ARGUMENT;
	if (info->nofExtractPositionsFound + 1 > info->nofExtractPositions) return KT_INDEX_OVF;
	info->nofExtractPositionsFound++;
	return extract_info_register_next_extract_position(info);
}

size_t EXTRACT_INFO_getNextPosition(EXTRACT_INFO *info) {
	if (info == NULL) return 0;
	if (info->nofExtractPositionsFound == info->nofExtractPositions) return 0;
	return info->extractPositions[info->nofExtractPositionsFound];
}

size_t EXTRACT_INFO_getPositionsInBlock(EXTRACT_INFO *info) {
	if (info == NULL) return 0;
	return info->nofExtractPositionsInBlock;
}

size_t EXTRACT_INFO_getPositionsExtracted(EXTRACT_INFO *info) {
	if (info == NULL) return 0;
	return info->nofExtractPositionsFound;
}

int EXTRACT_INFO_getRecord(EXTRACT_INFO *extract, size_t index, RECORD_INFO **pRec) {
	int res;

	if (extract == NULL || index >= extract->nofExtractPositionsInBlock || pRec == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (index >= extract->nofExtractPositionsInBlock || index >= extract->records_capacity) {
		res = KT_INDEX_OVF;
		goto cleanup;
	}

	*pRec = &extract->records[index];

	res = KT_OK;

cleanup:

	return res;
}




static int next_rec_reset(NEXT_REC *recextract, const char *range) {
	if (recextract == NULL || range == NULL) return KT_INVALID_ARGUMENT;

	recextract->n = 0;
	recextract->from = 0;
	recextract->endp = NULL;
	recextract->digit_expected = 1;
	recextract->dash_allowed = 1;
	recextract->get_next_n = 1;
	recextract->records = range;

	return KT_OK;
}

static int next_rec_extract_next_position(NEXT_REC *recextract, long *position) {
	int res = KT_UNKNOWN_ERROR;
	long tmp = -1;

	if (recextract == NULL || position == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	while (*recextract->records) {
		if (isspace(*recextract->records)) {
			res = KT_INVALID_INPUT_FORMAT;
			goto cleanup;
		}
		if(!recextract->digit_expected) {
			/* Process either ',' or '-' as a separator. */
			recextract->digit_expected = 1;
			if (*recextract->records == ',') {
				recextract->dash_allowed = 1;
				recextract->records++;
				recextract->from = 0;
				recextract->get_next_n = 1;
				continue;
			} else if (*recextract->records == '-') {
				if (recextract->dash_allowed) {
					recextract->dash_allowed = 0;
					recextract->records++;
					recextract->from = recextract->n;
					recextract->get_next_n = 1;
					continue;
				} else {
					res = KT_INVALID_INPUT_FORMAT;
					goto cleanup;
				}
			} else {
				res = KT_INVALID_INPUT_FORMAT;
				goto cleanup;
			}
		} else {
			/* Get the next integer and interpret it as a single position or range of positions. */
			if (recextract->get_next_n) {
				recextract->n = strtol(recextract->records, &recextract->endp, 10);
				recextract->get_next_n = 0;
				if (recextract->endp == recextract->records) {
					res = KT_INVALID_INPUT_FORMAT;
					goto cleanup;
				}
			}
			if (recextract->n <= 0) {
				res = KT_INVALID_INPUT_FORMAT;
				goto cleanup;
			} else if (recextract->from == 0) {
				tmp = recextract->n;

				recextract->records = recextract->endp;
				recextract->digit_expected = 0;
				res = KT_OK;
				goto cleanup;
			} else if (recextract->from < recextract->n) {
				/* Add the next position in the range. */
				recextract->from++;
				tmp = recextract->from;
				res = KT_OK;
				if (recextract->from < recextract->n) {
					goto cleanup;
				} else {
					recextract->records = recextract->endp;
					recextract->digit_expected = 0;
					goto cleanup;
				}
			} else {
				res = KT_INVALID_INPUT_FORMAT;
				goto cleanup;
			}
		}
	}

	/* Make sure the last processed character was a digit. */
	if(recextract->digit_expected) {
		res = KT_INVALID_INPUT_FORMAT;
		goto cleanup;
	}

	res = KT_OK;

cleanup:

	if (res == KT_OK) {
		*position = tmp;
	}

	return res;
}

static int foldl_aggr_chain(void *acc, LINK_DIRECTION dir, KSI_DataHash *sibling, size_t corr) {
	int res = KT_UNKNOWN_ERROR;
	KSI_HashChainLinkList *chainList = NULL;
	KSI_DataHash *hashRef = NULL;
	KSI_HashChainLink *link = NULL;
	KSI_Integer *lvlcrct = NULL;

	struct aggr_chain_fold_st *wrap = NULL;

	if (acc == NULL || sibling == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	wrap = acc;
	chainList = wrap->chainList;


	/* Extract hash algorithm. */
	if (wrap->hashAlgo == KSI_HASHALG_INVALID_VALUE) {
		res = KSI_DataHash_getHashAlg(sibling, &wrap->hashAlgo);
		if (res != KSI_OK) goto cleanup;
	}


	res = KSI_HashChainLink_new(wrap->ksi, &link);
	if (res != KSI_OK) goto cleanup;

	hashRef = KSI_DataHash_ref(sibling);
	res = KSI_HashChainLink_setImprint(link, hashRef);
	if (res != KSI_OK) goto cleanup;
	hashRef = NULL;

	res = KSI_HashChainLink_setIsLeft(link, (dir == LEFT_LINK));
	if (res != KSI_OK) goto cleanup;

	res = KSI_Integer_new(wrap->ksi, corr, &lvlcrct);
	if (res != KSI_OK) goto cleanup;

	res = KSI_HashChainLink_setLevelCorrection(link, lvlcrct);
	if (res != KSI_OK) goto cleanup;
	lvlcrct = NULL;

	res = KSI_HashChainLinkList_append(chainList, link);
	if (res != KSI_OK) goto cleanup;
	link = NULL;


	res = KT_OK;

cleanup:

	KSI_HashChainLink_free(link);
	KSI_DataHash_free(hashRef);
	KSI_Integer_free(lvlcrct);

	return KT_OK;
}

static int record_info_set_value(RECORD_INFO *extractInfo, size_t pos, size_t offs, KSI_DataHash *hsh, int isMetaRecordHash, void *raw, size_t len) {
	int res = KT_UNKNOWN_ERROR;

	if (extractInfo == NULL || hsh == NULL || raw == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	extractInfo->extractLine = pos;
	extractInfo->extractOffset = offs;
	extractInfo->extractRecord = hsh;

	if (isMetaRecordHash) {
		unsigned char *meta = raw;
		extractInfo->logLine = NULL;

		res = KSI_TlvElement_parse(meta, len, &extractInfo->metaRecord);
		if (res != KT_OK) goto cleanup;
	} else {
		char *logLine = raw;
		extractInfo->metaRecord = NULL;

		extractInfo->logLine = logLine;
		if (extractInfo->logLine == NULL) {
			res = KT_OUT_OF_MEMORY;
			goto cleanup;
		}
	}

	res = KT_OK;

cleanup:
	return res;
}

static void record_info_clean(RECORD_INFO *obj) {
	int i = 0;
	if (obj == NULL) return;
	memset(obj, 0, sizeof(RECORD_INFO));

	obj->extractRecord = NULL;
	obj->metaRecord = NULL;
	obj->logLine = NULL;

	for (i = 0; i < MAX_TREE_HEIGHT; i++) {
		obj->extractChain[i].sibling = NULL;
		obj->extractChain[i].dir = LEFT_LINK;
	}

	return;
}

static int extract_info_register_next_extract_position(EXTRACT_INFO *info) {
	int res;
	long position = 0;


	if (info == NULL){
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = next_rec_extract_next_position(&info->recExtract, &position);
	if (res != KT_OK) goto cleanup;

	if (position > 0) {
		res = extract_info_add_position(info, position);
		if (res != KT_OK) goto cleanup;
	}

	res = KT_OK;

	cleanup:
	return res;
}

static int extract_info_add_position(EXTRACT_INFO *extract, long int n) {
	int res;
	size_t *tmp = NULL;

	if (extract == NULL || n <= 0) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	if (extract->nofExtractPositions) {
		if (n <= extract->extractPositions[extract->nofExtractPositions - 1]) {
			res = KT_INVALID_INPUT_FORMAT;
			goto cleanup;
		}
	}

	if (extract->extractPositions == NULL) {
		tmp = (size_t*)malloc(sizeof(size_t));
	} else {
		tmp = (size_t*)realloc(extract->extractPositions, sizeof(size_t) * (extract->nofExtractPositions + 1));
	}

	if (tmp == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	extract->extractPositions = tmp;
	tmp = NULL;
	extract->extractPositions[extract->nofExtractPositions] = n;
	extract->nofExtractPositions++;
	res = KT_OK;


cleanup:

	return res;
}
