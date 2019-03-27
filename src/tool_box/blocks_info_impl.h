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

#ifdef	__cplusplus
extern "C" {
#endif

#define MAX_TREE_HEIGHT 31

typedef enum {
	LEFT_LINK = 0,
	RIGHT_LINK = 1
} LINK_DIRECTION;

typedef enum {
	TASK_NONE = 0x00,
	TASK_VERIFY,
	TASK_EXTEND,
	TASK_EXTRACT,
	TASK_SIGN,
	TASK_INTEGRATE,
} LOGKSI_TASK_ID;

typedef struct {
	LINK_DIRECTION dir;
	KSI_DataHash *sibling;
	size_t corr;
} REC_CHAIN;

typedef struct {
	size_t extractPos;
	size_t extractOffset;
	size_t extractLevel;
	char *logLine;
	KSI_TlvElement *metaRecord;
	KSI_DataHash *extractRecord;
	REC_CHAIN extractChain[MAX_TREE_HEIGHT];
} EXTRACT_INFO;

typedef enum {
	LOGSIG11 = 0,
	LOGSIG12 = 1,
	RECSIG11 = 2,
	RECSIG12 = 3
} LOGSIG_VERSION;

typedef struct {
	KSI_FTLV ftlv;
	unsigned char *ftlv_raw;
	size_t ftlv_len;

	size_t blockCount;				/* Count of blocks counted in the beginning of the sign task. */
	size_t noSigCount;				/* Count of not signed blocks counted in the beginning of the sign task. */

	size_t noSigCreated;			/* Count of signatures created for unsigned blocks. */
	size_t blockNo;					/* Index of current block (incremented if block header or KSI signature in excerpt file is processed ). */
	size_t partNo;					/* Index of partial blocks (incremented if partial block is processed). */
	size_t sigNo;					/* Index of block-signatures + ksi signatures + partial signatures. */
	size_t noSigNo;					/* Count of not signed blocks. */
	size_t recordCount;				/* Record count read from block signature, partial block or partial block signature. It is just a number and may differ from the real count! */
	size_t nofRecordHashes;			/* Number of all records that are aggregated into a tree (no tree_hash included, but metarecord record hash is counted. */
	size_t nofMetaRecords;			/* Number of meta-records inside a block. */
	size_t nofTotalRecordHashes;	/* All record hashes over all blocks. Meta-record hashes are not included! */
	size_t nofTotalMetarecors;		/* All meta-record over all blocks. */
	size_t nofTreeHashes;
	size_t firstLineInBlock;		/* First line in current block. */
	size_t currentLine;				/* Current line number in current block. */
	size_t nofTotalFailedBlocks;
	KSI_HashAlgorithm hashAlgo;
	KSI_OctetString *randomSeed;
	KSI_DataHash *inputHash;		/* Just a reference for the input hash of a block. */
	KSI_DataHash *prevLeaf;
	KSI_DataHash *MerkleTree[MAX_TREE_HEIGHT];
	KSI_DataHash *notVerified[MAX_TREE_HEIGHT];
	KSI_DataHash *rootHash;
	KSI_DataHash *metarecordHash;
	KSI_DataHash *extractMask;
	KSI_DataHasher *hasher;
	char *logLine;
	unsigned char *metaRecord;
	char *records;
	size_t nofExtractPositions;
	size_t *extractPositions;
	size_t nofExtractPositionsInBlock;
	size_t nofExtractPositionsFound;
	EXTRACT_INFO *extractInfo;
	unsigned char treeHeight;
	unsigned char balanced;
	LOGSIG_VERSION version;
	char warningLegacy;
	char keepRecordHashes;			/* This is set to 1, when (meta-)record hash is read from file. Indicates that rsyslog keeps record hashes. */
	char keepTreeHashes;			/* This is set to 1, when tree hash is read from file. Indicates that rsyslog keeps tree hashes. */
	char finalTreeHashesSome;
	char finalTreeHashesNone;
	char finalTreeHashesAll;
	char finalTreeHashesLeaf;
	char warningTreeHashes;
	char unsignedRootHash;
	char warningSignatures;
	char errSignTime;
	char curBlockNotSigned;
	char curBlockJustReSigned;
	char outSigModified;			/* Indicates that output signature file is actually modified. */
	char lastBlockWasSkipped;		/* If block is skipped (--continue-on-failure) due to verification failure, this is set. It is cleared in process_ksi_signature or process_block_signature. */
	char signatureTLVReached;		/* This is set if signature TLV is reached (in process_block_signature, process_ksi_signature or process_partial_signature) and is cleared in init_next_block.*/
	size_t nofTotaHashFails;		/* Overall count of hahs failures inside log signature. */
	size_t nofHashFails;			/* Count of hahs failures inside log block. */
	uint64_t sigTime_0;
	uint64_t sigTime_1;
	uint64_t extendedToTime;
	LOGKSI_TASK_ID taskId;

	char client_id_last[0xffff];	/* Last signer id. Used to detect change. */
	REGEXP *client_id_match;		/* A regular expression value to be matched with KSI signatures. */
} BLOCK_INFO;

#ifdef	__cplusplus
}
#endif

#endif	/* BLOCKS_INFO_IMPL_H */