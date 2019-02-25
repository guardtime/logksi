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

#ifndef BLOCKS_INFO_H
#define	BLOCKS_INFO_H

#include <ksi/ksi.h>
#include "blocks_info_impl.h"
#include "err_trckr.h"
#include "io_files.h"

#ifdef	__cplusplus
extern "C" {
#endif

int merge_one_level(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash **hash);
int calculate_root_hash(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash **hash);
int get_aggregation_level(BLOCK_INFO *blocks);
int add_leaf_hash_to_merkle_tree(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash *hash, int isMetaRecordHash);
int add_record_hash_to_merkle_tree(KSI_CTX *ksi, ERR_TRCKR *err, BLOCK_INFO *blocks, int isMetaRecordHash, KSI_DataHash *hash);
int store_logline(BLOCK_INFO *blocks, char *buf);
int get_hash_of_logline(BLOCK_INFO *blocks, IO_FILES *files, KSI_DataHash **hash);
int store_metarecord(BLOCK_INFO *blocks, KSI_TlvElement *tlv);
int calculate_new_tree_hash(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash *leftHash, KSI_DataHash *rightHash, unsigned char level, KSI_DataHash **nodeHash);
int get_hash_of_metarecord(BLOCK_INFO *blocks, KSI_TlvElement *tlv, KSI_DataHash **hash);
void BLOCK_INFO_reset(BLOCK_INFO *block);
void BLOCK_INFO_freeAndClearInternals(BLOCK_INFO *blocks);

#ifdef	__cplusplus
}
#endif

#endif	/* BLOCKS_INFO_H */