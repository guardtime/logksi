/*
 * Copyright 2013-2022 Guardtime, Inc.
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

#ifndef CHECK_H
#define	CHECK_H

#include <stddef.h>
#include <ctype.h>
#include <ksi/ksi.h>
#include "logksi_impl.h"
#include "io_files.h"
#include "debug_print.h"
#include "smart_file.h"

#ifdef	__cplusplus
extern "C" {
#endif

int check_file_header(SMART_FILE *in, ERR_TRCKR *err, LOGSIG_VERSION *expected_ver, size_t expected_ver_count, const char *human_readable_file_name, LOGSIG_VERSION *ver_out);
int logksi_datahash_compare(ERR_TRCKR *err, MULTI_PRINTER *mp, LOGKSI* logksi, int isLogline, KSI_DataHash *left, KSI_DataHash *right, const char * reason, const char *helpLeft_raw, const char *helpRight_raw);
int continue_on_hash_fail(int result, PARAM_SET *set, MULTI_PRINTER* mp, LOGKSI *logksi, KSI_DataHash *computed, KSI_DataHash *stored, KSI_DataHash **replacement);

int check_log_line_embedded_time(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi);
int check_log_record_embedded_time_against_ksi_signature_time(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi);
int check_log_signature_client_id(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, KSI_Signature *sig);
int check_block_signing_time_check(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files);
int check_record_time_check_between_files(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files);

int is_block_signature_expected(LOGKSI *logksi, ERR_TRCKR *err);
int is_record_hash_expected(LOGKSI *logksi, ERR_TRCKR *err);
int is_tree_hash_expected(LOGKSI *logksi, ERR_TRCKR *err);

uint64_t uint64_diff(uint64_t a, uint64_t b, int *sign);
char* time_diff_to_string(uint64_t time_diff, char *buf, size_t buf_len);

#ifdef	__cplusplus
}
#endif

#endif	/* CHECK_H */