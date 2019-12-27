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

/* Functions for "more internal" use. */
int block_info_merge_one_level(BLOCK_INFO *blocks, KSI_CTX *ksi, KSI_DataHash **hash);
int block_info_calculate_root_hash(BLOCK_INFO *blocks, KSI_CTX *ksi, KSI_DataHash **hash);
int block_info_get_aggregation_level(BLOCK_INFO *blocks);
int block_info_add_leaf_hash_to_merkle_tree(BLOCK_INFO *blocks, KSI_CTX *ksi, KSI_DataHash *hash, int isMetaRecordHash);
int block_info_add_record_hash_to_merkle_tree(BLOCK_INFO *blocks, ERR_TRCKR *err, KSI_CTX *ksi, int isMetaRecordHash, KSI_DataHash *hash);
int block_info_calculate_hash_of_logline_and_store_logline(BLOCK_INFO *blocks, IO_FILES *files, KSI_DataHash **hash);
int block_info_calculate_new_tree_hash(BLOCK_INFO *blocks, KSI_DataHash *leftHash, KSI_DataHash *rightHash, unsigned char level, KSI_DataHash **nodeHash);
int block_info_calculate_hash_of_metarecord_and_store_metarecord(BLOCK_INFO *blocks, KSI_TlvElement *tlv, KSI_DataHash **hash);

void BLOCK_INFO_clearAll(BLOCK_INFO *block);
void BLOCK_INFO_freeAndClearInternals(BLOCK_INFO *blocks);
int BLOCK_INFO_setErrorLevel(BLOCK_INFO *blocks, int lvl);

#ifdef	__cplusplus
}
#endif

#endif	/* BLOCKS_INFO_H */