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
#include "blocks_info_impl.h"
#include "err_trckr.h"

#ifdef	__cplusplus
extern "C" {
#endif

int block_info_extract_update_record_chain(BLOCK_INFO *blocks, unsigned char level, int finalize, KSI_DataHash *leftLink);
int block_info_extract_next_position(BLOCK_INFO *blocks, ERR_TRCKR *err, char *range);
int block_info_extract_update(BLOCK_INFO *blocks, ERR_TRCKR *err, int isMetaRecordHash, KSI_DataHash *hash);
int block_info_extract_verify_positions(ERR_TRCKR *err, char *records);

#ifdef	__cplusplus
}
#endif

#endif	/* EXTRACT_INFO_H */