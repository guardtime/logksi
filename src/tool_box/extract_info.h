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

#ifndef EXTRACT_INFO_H
#define	EXTRACT_INFO_H

#include <stddef.h>
#include <ksi/ksi.h>
#include <ksi/tlv_element.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct RECORD_INFO_st RECORD_INFO;
typedef struct EXTRACT_INFO_st EXTRACT_INFO;

typedef enum {
	LEFT_LINK = 0,
	RIGHT_LINK = 1
} LINK_DIRECTION;

int EXTRACT_INFO_new(const char *range, EXTRACT_INFO **info);
void EXTRACT_INFO_free(EXTRACT_INFO *extract);
int EXTRACT_INFO_getNewRecord(EXTRACT_INFO *extract, size_t *index, RECORD_INFO **info);
int EXTRACT_INFO_getRecord(EXTRACT_INFO *extract, size_t index, RECORD_INFO **pRec);
void EXTRACT_INFO_resetBlockInfo(EXTRACT_INFO *extract);
int EXTRACT_INFO_isLastPosPending(EXTRACT_INFO *info);
int EXTRACT_INFO_moveToNext(EXTRACT_INFO *info);
size_t EXTRACT_INFO_getNextPosition(EXTRACT_INFO *info);
size_t EXTRACT_INFO_getPositionsInBlock(EXTRACT_INFO *info);
size_t EXTRACT_INFO_getPositionsExtracted(EXTRACT_INFO *info);

int RECORD_INFO_setRecordHash(RECORD_INFO *extractInfo, size_t pos, size_t offs, KSI_DataHash *hsh, const char *logLine);
int RECORD_INFO_setMetaRecordHash(RECORD_INFO *extractInfo, size_t pos, size_t offs, KSI_DataHash *hsh, unsigned char *raw, size_t raw_len);
int RECORD_INFO_add_hash_to_record_chain(RECORD_INFO *extracts, LINK_DIRECTION dir, KSI_DataHash *hash, int corr);
int RECORD_INFO_getLine(RECORD_INFO *record, size_t *lineNr, char **logLine);
int RECORD_INFO_getPositionInTree(RECORD_INFO *record, size_t *recordOffset, size_t *recordRootLvl);
int RECORD_INFO_getRecordHash(RECORD_INFO *record, KSI_DataHash **extractRecord);
int RECORD_INFO_getMetadata(RECORD_INFO *record, KSI_TlvElement **metaRecord);

int RECORD_INFO_foldl(RECORD_INFO *record,
					void *acc,
					int (*f)(void *, LINK_DIRECTION, KSI_DataHash*, size_t));

int RECORD_INFO_getAggregationHashChain(RECORD_INFO *record, KSI_CTX *ksi, KSI_AggregationHashChain **aggrChain);


#ifdef	__cplusplus
}
#endif

#endif	/* EXTRACT_INFO_H */