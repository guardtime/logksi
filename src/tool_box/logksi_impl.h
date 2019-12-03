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

#ifndef BLOCKS_INFO_IMPL_H
#define	BLOCKS_INFO_IMPL_H

#include <stddef.h>
#include <ksi/hash.h>
#include <ksi/fast_tlv.h>
#include <ksi/tlv_element.h>
#include "regexpwrap.h"
#include "merkle_tree.h"
#include "err_trckr.h"
#include "extract_info.h"

#ifdef	__cplusplus
extern "C" {
#endif

#define MAGIC_SIZE 8

typedef enum {
	TASK_NONE = 0x00,
	TASK_VERIFY,
	TASK_EXTEND,
	TASK_EXTRACT,
	TASK_SIGN,
	TASK_INTEGRATE,
} LOGKSI_TASK_ID;

typedef enum {
	LOGSIG11 = 0,
	LOGSIG12 = 1,
	RECSIG11 = 2,
	RECSIG12 = 3,
	LOG12BLK = 4,
	LOG12SIG = 5,
	NOF_VERS,
	UNKN_VER = 0xff
} LOGSIG_VERSION;

typedef struct SIGN_TASK_st {
	size_t blockCount;				/* Count of blocks counted in the beginning of the sign task. */
	size_t noSigCount;				/* Count of not signed blocks counted in the beginning of the sign task. */
	size_t noSigNo;					/* Number of the last unsigned blocks. */
	size_t noSigCreated;			/* Count of signatures created for unsigned blocks. */
	char curBlockJustReSigned;
	char outSigModified;			/* Indicates that output signature file is actually modified. */
} SIGN_TASK;

typedef struct INTEGRATE_TASK_st {
	size_t partNo;					/* Index of partial blocks (incremented if partial block is processed). */
	char unsignedRootHash;
	char warningSignatures;
} INTEGRATE_TASK;

typedef struct EXTRACT_TASK_st {
	EXTRACT_INFO *info;
	unsigned char *metaRecord;
	size_t metaRecord_len;
} EXTRACT_TASK;

typedef struct EXTEND_TASK_st {
	uint64_t extendedToTime;
} EXTEND_TASK;

typedef struct VERIFY_TASK_st {
	char client_id_last[0xffff];	/* Last signer id. Used to detect change. */
	REGEXP *client_id_match;		/* A regular expression value to be matched with KSI signatures. */
	char lastBlockWasSkipped;		/* If block is skipped (--continue-on-failure) due to verification failure, this is set. It is cleared in process_ksi_signature or process_block_signature. */
	char errSignTime;				/* Signing time check failed. */
} VERIFY_TASK;

typedef struct TASK_SPECIFIC_st {
	SIGN_TASK sign;
	INTEGRATE_TASK integrate;
	EXTRACT_TASK extract;
	EXTEND_TASK extend;
	VERIFY_TASK verify;
} TASK_SPECIFIC;

typedef struct FILE_INFO_st {
	LOGSIG_VERSION version;			/* Version of the log signature. */
	size_t nofTotalRecordHashes;	/* All record hashes over all blocks. Tree and Meta-record hashes are not included! Note that it is updated in the end of the block. */
	size_t nofTotalMetarecords;		/* All meta-record over all blocks. */
	size_t nofTotalFailedBlocks;
	size_t nofTotaHashFails;		/* Overall count of hahs failures inside log signature. */
	uint64_t recTimeMin;			/* The lowest record time value in the log file, extracted from the log line. */
	uint64_t recTimeMax;			/* The highest record time value in the log file, extracted from the log line. */
	char warningLegacy;
	char warningTreeHashes;
} FILE_INFO;

typedef struct BLOCK_INF_st {
	size_t firstLineNo;				/* First line in current block. */
	size_t recordCount;				/* Record count read from block signature, partial block or partial block signature. It is just a number and may differ from the real count! */
	size_t nofRecordHashes;			/* Number of all records and meta record hashes that are aggregated into a tree (no tree_hash included). */
	size_t nofMetaRecords;			/* Number of meta-records inside a block. */
	size_t nofTreeHashes;
	size_t nofHashFails;			/* Count of hahs failures inside log block. */
	uint64_t recTimeMin;			/* The lowest record time value in the block, extracted from the log line. */
	uint64_t recTimeMax;			/* The highest record time value in the block, extracted from the log line. */
	uint64_t sigTime_1;
	KSI_HashAlgorithm hashAlgo;		/* Hash algorithm used for aggregation. */
	KSI_DataHash *inputHash;		/* Just a reference for the input hash of a block. */
	KSI_DataHash *rootHash;			/* Root hash value extracted from KSI signature / unsigned block marker. */
	KSI_DataHash *metarecordHash;
	char keepRecordHashes;			/* This is set to 1, when (meta-)record hash is read from file. Indicates that rsyslog keeps record hashes. */
	char keepTreeHashes;			/* This is set to 1, when tree hash is read from file. Indicates that rsyslog keeps tree hashes. */
	char finalTreeHashesNone;
	char finalTreeHashesSome;
	char finalTreeHashesAll;
	char finalTreeHashesLeaf;		/* This is set to 1, when block is closed prematurely with a metarecord, indicating to process the current tree hash as a mandatory leaf hash.*/
	char curBlockNotSigned;
	char signatureTLVReached;		/* This is set if signature TLV is reached (in process_block_signature, process_ksi_signature or process_partial_signature) and is cleared in init_next_block.*/
} BLOCK_INFO;

typedef struct {
	ERR_TRCKR *err;

	KSI_FTLV ftlv;
	unsigned char *ftlv_raw;
	size_t ftlv_len;

	LOGKSI_TASK_ID taskId;
	TASK_SPECIFIC task;

	FILE_INFO file;
	BLOCK_INFO block;

	size_t blockNo;					/* Index of current block (incremented if block header or KSI signature in excerpt file is processed). */
	size_t sigNo;					/* Index of block-signatures + ksi signatures + partial signatures. */
	size_t currentLine;				/* Current line number in current block. */
	char *logLine;
	char isContinuedOnFail;			/* Option --continue-on-failure is set. */
	int quietError;					/* In case of failure and --continue-on-fail, this option will keep the error code and block is not skipped. */
	uint64_t sigTime_0;

	MERKLE_TREE *tree;
} LOGKSI;

#ifdef	__cplusplus
}
#endif

#endif	/* BLOCKS_INFO_IMPL_H */