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

/* To make function strptime prototype available. */
#define _XOPEN_SOURCE

#include <stdlib.h>
#include <string.h>
#include <ksi/ksi.h>
#include <ksi/tlv_element.h>
#include <gtrfc3161/tsconvert.h>
#include <ctype.h>
#include "param_set/param_set.h"
#include "param_set/strn.h"
#include "err_trckr.h"
#include "logksi_err.h"
#include "api_wrapper.h"
#include "printer.h"
#include "debug_print.h"
#include "tlv_object.h"
#include "extract_info.h"
#include "io_files.h"
#include "blocks_info.h"
#include "rsyslog.h"
#include "param_control.h"
#include <time.h>

static char* time_diff_to_string(uint64_t time_diff, char *buf, size_t buf_len);
static const char *io_files_getCurrentLogFilePrintRepresentation(IO_FILES *files);

#define SOF_ARRAY(x) (sizeof(x) / sizeof((x)[0]))

typedef struct {
	VERIFYING_FUNCTION verify_signature;
	EXTENDING_FUNCTION extend_signature;
	SIGNING_FUNCTION create_signature;
	int extract_signature;
} SIGNATURE_PROCESSORS;

static size_t get_nof_lines(BLOCK_INFO *blocks) {
	if (blocks) {
		return blocks->nofRecordHashes + blocks->nofTotalRecordHashes;
	} else {
		return 0;
	}
}

static size_t max_tree_hashes(size_t nof_records) {
	size_t max = 0;
	while (nof_records) {
		max = max + nof_records;
		nof_records = nof_records / 2;
	}
	return max;
}

static int block_info_calculate_hash_of_logline_and_store_logline_check_log_time(PARAM_SET* set, ERR_TRCKR *err, MULTI_PRINTER *mp, BLOCK_INFO *blocks, IO_FILES *files, KSI_DataHash **hash) {
	int res = KT_UNKNOWN_ERROR;
	uint64_t last_time = 0;
	const char *ret = NULL;

	if (set == NULL || err == NULL || mp == NULL || blocks == NULL || files == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = block_info_calculate_hash_of_logline_and_store_logline(blocks, files, hash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate hash of logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));


	if (blocks->taskId == TASK_VERIFY && PARAM_SET_isSetByName(set, "time-form")) {
		char *format = NULL;
		struct tm tmp_time;
		time_t t = 0;

		res = PARAM_SET_getStr(set, "time-form", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &format);
		ERR_CATCH_MSG(err, res, "Error: Unable to get time format string.");

		ret = strptime(blocks->logLine, format, &tmp_time);
		if (ret == NULL) {
			res = KT_INVALID_INPUT_FORMAT;
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Unable to extract timestamp (%s) from log line %zu: %.*s.\n", blocks->blockNo, format, get_nof_lines(blocks), (strlen(blocks->logLine) - 1), blocks->logLine);
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Unable to extract time stamp from log line %zu in block %zu:\n"
																						  "   + Log line:    '%.*s'\n"
																						  "   + Time format: '%s'\n"
																						  ,  get_nof_lines(blocks), blocks->blockNo, (strlen(blocks->logLine) - 1), blocks->logLine, format);

			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract time stamp from the logline no. %zu.", blocks->blockNo, get_nof_lines(blocks))
		}


		if (PARAM_SET_isSetByName(set, "time-base")) {
			int timeBase = 0;

			res = PARAM_SET_getObj(set, "time-base", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, (void**)&timeBase);
			ERR_CATCH_MSG(err, res, "Error: Unable to extract time base as integer.");

			tmp_time.tm_year = timeBase - 1900;
		}

		t = KSI_CalendarTimeToUnixTime(&tmp_time);

		/* Check the order of log lines. */
		last_time = blocks->rec_time_max == 0 ? blocks->rec_time_in_file_max : blocks->rec_time_max;

		if (blocks->rec_time_min == 0 && blocks->rec_time_in_file_max == 0) {
			blocks->rec_time_min = t;
			blocks->rec_time_max = t;
		} else {
			if (blocks->rec_time_min == 0 || blocks->rec_time_min > t) blocks->rec_time_min = t;
			if (blocks->rec_time_max < t) blocks->rec_time_max = t;

			if (PARAM_SET_isSetByName(set, "time-diff")) {
				size_t line_nr_0 = get_nof_lines(blocks) - 1;
				size_t line_nr_1 = get_nof_lines(blocks);

				if (last_time > t && line_nr_0 > 0) {
					char str_last_time[1024] = "<null>";
					char str_current_time[1024] = "<null>";
					int time_diff = 0;

					/* Check if deviation in current range is accepted. */
					if (PARAM_SET_isSetByName(set, "time-disordered")) {
						res = PARAM_SET_getObj(set, "time-disordered", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, (void**)&time_diff);
						ERR_CATCH_MSG(err, res, "Error: Unable to extract time base as integer.");

						if (last_time <= t + time_diff) {
							res = KT_OK;
							goto cleanup;
						}
					}

					res = KT_VERIFICATION_FAILURE;
					print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);
					LOGKSI_uint64_toDateString(last_time, str_last_time, sizeof(str_last_time));
					LOGKSI_uint64_toDateString(t, str_current_time, sizeof(str_current_time));
					blocks->nofTotalFailedBlocks++;

					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Log line %zu (%s) is more recent than log line %zu (%s).\n", blocks->blockNo, line_nr_0, str_last_time, line_nr_1, str_current_time);
					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Log line %zu in block %zu is more recent than log line %zu:\n"
																						  "   + Time for log line %zu: %s\n"
																						  "   + Time for log line %zu: %s\n"
																						  ,  line_nr_0, blocks->blockNo, line_nr_1, line_nr_0, str_last_time, line_nr_1, str_current_time);
					blocks->quietError = res;
					if (blocks->isContinuedOnFail) res = KT_OK;

					else ERR_TRCKR_ADD(err, res, "Error: Log line %zu in block %zu is more recent than log line %zu!", line_nr_0, blocks->blockNo, line_nr_1);
					goto cleanup;
				}
			}
		}

	}



	res = KT_OK;

cleanup:
	return res;
}

static int logksi_datahash_compare(ERR_TRCKR *err, MULTI_PRINTER *mp, BLOCK_INFO* blocks, int isLogline, KSI_DataHash *left, KSI_DataHash *right, const char * reason, const char *helpLeft_raw, const char *helpRight_raw) {
	int res;
	KSI_HashAlgorithm leftId;
	KSI_HashAlgorithm rightId;
	char buf[1024];
	const char *failureReason = NULL;
	int differentHashAlg = 0;

	if (mp == NULL || blocks == NULL || left == NULL || right == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	failureReason = (reason == NULL) ? "Hash values do not match" : reason;

	if (!KSI_DataHash_equals(left, right)) {
		const char *helpLeft = NULL;
		const char *helpRight = NULL;
		size_t minSize = 0;

		res = KT_VERIFICATION_FAILURE;
		print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);
		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);
		differentHashAlg = KSI_DataHash_getHashAlg(left, &leftId) == KSI_OK && KSI_DataHash_getHashAlg(right, &rightId) == KSI_OK && leftId != rightId;

		helpLeft = helpLeft_raw == NULL ? "Computed hash:" : helpLeft_raw;
		helpRight = helpRight_raw == NULL ? "Stored hash:" : helpRight_raw;
		minSize = strlen(helpLeft);
		minSize = strlen(helpRight) > minSize ? strlen(helpRight) : minSize;

		if (isLogline) {
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Failed to verify logline no. %zu:\n"
																				  "   + Logline:\n"
																				  "     '%.*s'\n", get_nof_lines(blocks), (strlen(blocks->logLine) - 1), blocks->logLine);
			if (differentHashAlg) print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "   + Hash algorithms differ!%s\n");
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "   + %s\n"
																				  "     %s\n", helpLeft, LOGKSI_DataHash_toString(left, buf, sizeof(buf)));
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "   + %s\n"
																				  "     %s\n", helpRight, LOGKSI_DataHash_toString(right, buf, sizeof(buf)));


			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: failed to verify logline no. %zu: %s", blocks->blockNo, get_nof_lines(blocks), blocks->logLine);
		} else {
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: %s:\n", failureReason);
			if (differentHashAlg) print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "   + Hash algorithms differ!%s\n");
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "   + %s\n"
																				  "     %s\n", helpLeft, LOGKSI_DataHash_toString(left, buf, sizeof(buf)));
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "   + %s\n"
																				  "     %s\n", helpRight, LOGKSI_DataHash_toString(right, buf, sizeof(buf)));
		}

		print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: %s\n", blocks->blockNo, failureReason);
		print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Hash algorithms differ\n", blocks->blockNo);
		print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: %-*s %s\n", blocks->blockNo, minSize, helpLeft, LOGKSI_DataHash_toString(left, buf, sizeof(buf)));
		print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: %-*s %s\n", blocks->blockNo, minSize, helpRight, LOGKSI_DataHash_toString(right, buf, sizeof(buf)));

		goto cleanup;
	}

	res = KT_OK;

cleanup:

	return res;
}

struct magic_reference_st {
	const char* name;
	LOGSIG_VERSION ver;
};

#define _LGVR(v) {#v, v}
struct magic_reference_st magic_reference[NOF_VERS] = {_LGVR(LOGSIG11), _LGVR(LOGSIG12), _LGVR(RECSIG11), _LGVR(RECSIG12), _LGVR(LOG12BLK), _LGVR(LOG12SIG)};
#undef _LGVR

static LOGSIG_VERSION file_version_by_string(const char *str) {
	int i = 0;
	if (str == NULL) return UNKN_VER;

	for (i = 0; i < NOF_VERS; i++) {
		if (strcmp(str, magic_reference[i].name) == 0) return magic_reference[i].ver;
	}

	return UNKN_VER;
}

static const char* file_version_to_string(LOGSIG_VERSION ver) {
	int i = 0;

	for (i = 0; i < NOF_VERS; i++) {
		if (magic_reference[i].ver == ver) return magic_reference[i].name;
	}

	return "<unknown file version>";
}

/**
 * Extracts file type by reading its magic bytes.
 * \param in		#SMART_FILE object wherefrom the magic bytes are read.
 * \return File version (#LOGSIG_VERSION) if successful or #UNKN_VER otherwise.
 */
static LOGSIG_VERSION get_file_version(SMART_FILE *in) {
	int res = KT_UNKNOWN_ERROR;
	char magic_from_file[MAGIC_SIZE + 1];
	size_t count = 0xff;

	if (in == NULL)	return UNKN_VER;

	res = SMART_FILE_read(in, (unsigned char*)magic_from_file, MAGIC_SIZE, &count);
	if (res != SMART_FILE_OK || count != MAGIC_SIZE) return UNKN_VER;

	magic_from_file[MAGIC_SIZE] = '\0';
	return file_version_by_string(magic_from_file);
}

static LOGSIG_VERSION get_integrity_proof_version(LOGSIG_VERSION ver) {
	switch(ver) {
		case LOGSIG11: return RECSIG11;
		case LOGSIG12: return RECSIG12;
		default: return UNKN_VER;
	}
}

static int check_file_header(SMART_FILE *in, ERR_TRCKR *err, LOGSIG_VERSION *expected_ver, size_t expected_ver_count, const char *human_readable_file_name, LOGSIG_VERSION *ver_out) {
	int res = KT_UNKNOWN_ERROR;
	LOGSIG_VERSION ver = UNKN_VER;
	char permitted_versions[1024] = "<unexpected>";
	int i = 0;
	size_t count = 0;

	if (in == NULL || err == NULL) return KT_INVALID_ARGUMENT;

	/* Get the actual version. */
	ver = get_file_version(in);
	if (ver_out != NULL) *ver_out = ver;

	/* Check if any of the file types matches. In case of success return with OK */
	for (i = 0; i < expected_ver_count; i++) {
		if (expected_ver[i] == ver) return KT_OK;
		count += PST_snprintf(permitted_versions + count, sizeof(permitted_versions) - count, "%s%s", (i > 0 ? ", " : ""), file_version_to_string(expected_ver[i]));
	}

    /* Format error messages.*/
	res = KT_INVALID_INPUT_FORMAT;
	if (expected_ver_count > 1) ERR_TRCKR_ADD(err, res, "Error: Expected file types {%s} but got %s!", permitted_versions, file_version_to_string(ver));
	else ERR_TRCKR_ADD(err, res, "Error: Expected file type %s but got %s!", permitted_versions, file_version_to_string(ver));
	ERR_TRCKR_ADD(err, res, "Error: Log signature file identification magic number not found.");
	ERR_TRCKR_ADD(err, res, "Error: Unable to parse %s file '%s'.", human_readable_file_name, SMART_FILE_getFname(in));

	return res;
}

static int process_magic_number(PARAM_SET* set, MULTI_PRINTER* mp, ERR_TRCKR *err, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	SMART_FILE *in = NULL;

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	in = files->files.partsBlk ? files->files.partsBlk : files->files.inSig;
	if (in == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Processing magic number... ");

	res = KT_INVALID_INPUT_FORMAT;

	if (files->files.partsBlk) {
		LOGSIG_VERSION exp_ver_blk[] = {LOG12BLK};
		LOGSIG_VERSION exp_ver_sig[] = {LOG12SIG};

		res = check_file_header(files->files.partsBlk, err, exp_ver_blk, SOF_ARRAY(exp_ver_blk), "block", NULL);
		if (res != KT_OK) goto cleanup;

		res = check_file_header(files->files.partsSig, err, exp_ver_sig, SOF_ARRAY(exp_ver_sig), "signature", NULL);
		if (res != KT_OK) goto cleanup;

		blocks->version = LOGSIG12;
	} else {
		LOGSIG_VERSION exp_ver[] = {LOGSIG11, LOGSIG12, RECSIG11, RECSIG12};
		res = check_file_header(files->files.inSig, err, exp_ver, SOF_ARRAY(exp_ver), "signature", &blocks->version);
		if (res != KT_OK) goto cleanup;
	}

	if (files->files.outSig) {
		res = SMART_FILE_write(files->files.outSig, (unsigned char*)file_version_to_string(blocks->version), MAGIC_SIZE, NULL);
		ERR_CATCH_MSG(err, res, "Error: Could not copy magic number to log signature file.");
	} else if (files->files.outProof) {
		res = SMART_FILE_write(files->files.outProof, (unsigned char*)file_version_to_string(get_integrity_proof_version(blocks->version)), MAGIC_SIZE, NULL);
		ERR_CATCH_MSG(err, res, "Error: Could not write magic number to integrity proof file.");
	}

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
	return res;
}

static int continue_on_hash_fail(int result, PARAM_SET *set, MULTI_PRINTER* mp, BLOCK_INFO *blocks, KSI_DataHash *computed, KSI_DataHash *stored, KSI_DataHash **replacement) {
	int res = result;

	if (set == NULL || blocks == NULL || computed == NULL || stored == NULL || replacement == NULL) {
		goto cleanup;
	}

	if (res == KT_OK) {
		*replacement = KSI_DataHash_ref(computed);
	} else {
		blocks->nofTotaHashFails++;
		blocks->nofHashFails++;
		if (PARAM_SET_isSetByName(set, "use-computed-hash-on-fail")) {
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "   + Using computed hash to continue.\n");
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Using computed hash to continue.\n", blocks->blockNo);
			*replacement = KSI_DataHash_ref(computed);
			res = KT_OK;
		} else if (PARAM_SET_isSetByName(set, "use-stored-hash-on-fail")) {
			*replacement = KSI_DataHash_ref(stored);
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "   + Using stored hash to continue.\n");
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Using stored hash to continue.\n", blocks->blockNo);
			res = KT_OK;
		} else {
			*replacement = KSI_DataHash_ref(computed);
		}
	}

cleanup:

	return res;
}

static char* time_diff_to_string(uint64_t time_diff, char *buf, size_t buf_len) {
	size_t count = 0;
	size_t reminder = 0;
	int d = 0;
	int H = 0;
	int M = 0;
	int S = 0;

	if (buf == NULL || buf_len == 0) {
		return NULL;
	}

	reminder = time_diff;
	d = reminder / (24 * 3600);
	reminder -= d * 24 * 3600;

	H = reminder / 3600;
	reminder -= H * 3600;

	M = reminder / 60;
	reminder -= M * 60;

	S = reminder;

	if (d > 0) {
		count += PST_snprintf(buf + count, buf_len - count, "%id", d);
	}

	count += PST_snprintf(buf + count, buf_len - count, "%s%02i:%02i:%02i", (d > 0 ? " " : ""), H, M, S);

	return buf;
}

static uint64_t uint64_diff(uint64_t a, uint64_t b, int *sign) {
	uint64_t diff;

	if (a > b) {
		if (sign != NULL) *sign = 1;
		diff = a - b;
	} else {
		if (sign != NULL) *sign = (a < b) ? -1 : 1;
		diff = b - a;
	}

	return diff;
}

/**
 * a > b ret 1
 * a == b ret 0
 * a < b ret -1
 */
static int uint64_signcmp(int sa, uint64_t a, int sb, uint64_t b) {
	sa = sa >= 0 ? 1 : -1;
	sb = sb >= 0 ? 1 : -1;

	if (sa == sb && a == b) return 0;
	else if (sa > sb || (sa == sb && ((sa == 1 && a > b) || (sa == -1 && a < b)))) return 1;

	return -1;
}

static int check_log_record_embedded_time_against_ksi_signature_time(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, BLOCK_INFO *blocks) {
	int res = KT_UNKNOWN_ERROR;
	int checkLogRecordTime = 0;

	if (set == NULL || mp == NULL || err == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	checkLogRecordTime = PARAM_SET_isSetByName(set, "time-form,time-diff");

	if (checkLogRecordTime && blocks->sigTime_1 != 0 && blocks->rec_time_min != 0 && blocks->rec_time_max != 0) {
		char str_sigTime1[1024] = "<null>";
		char str_rec_time_min[1024] = "<null>";
		char str_rec_time_max[1024] = "<null>";
		char str_diff_calc_past[1024] = "<null>";
		char str_diff_calc_future[1024] = "<null>";
		char str_diff_calc[1024] = "<null>";
		char str_allowed_diff[1024] = "<null>";
		int allowed_deviation_neg = 0;
		int allowed_deviation_pos = 0;
		int isSigTimeOlderThanRecTime = 0;
		int isTimeDiffTooLarge_future = 0;
		int isTimeDiffTooLarge_past = 0;
		int isTimeDiffTooLarge = 0;
		int neg_sign = 1;
		int diff_calc_less_recent_sign = 1;
		int diff_calc_most_recent_sign = 1;
		uint64_t diff_calc_most_recent = 0;
		uint64_t diff_calc_less_recent = 0;
		MIN_MAX_INT tmp;


		res = PARAM_SET_getObj(set, "time-diff", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, (void**)&tmp);
		ERR_CATCH_MSG(err, res, "Error: Unable to extract time base as integer.");

		if (tmp.count == 2) {
			allowed_deviation_neg = tmp.min;
			allowed_deviation_pos = tmp.max;
		} else {
			allowed_deviation_neg = tmp.min < 0 ? tmp.min : 0;
			allowed_deviation_pos = tmp.max > 0 ? tmp.max : 0;
		}

		/* Check for errors. */
		if (allowed_deviation_neg < 0) {
			neg_sign = -1;
		}

		diff_calc_most_recent = uint64_diff(blocks->sigTime_1, blocks->rec_time_max, &diff_calc_most_recent_sign);
		diff_calc_less_recent = uint64_diff(blocks->sigTime_1, blocks->rec_time_min, &diff_calc_less_recent_sign);
		isTimeDiffTooLarge_past = uint64_signcmp(diff_calc_less_recent_sign, diff_calc_less_recent, 1, allowed_deviation_pos) > 0;	/* Calculated deviation must be greater or equal to allowed deviation to fail. */
		isTimeDiffTooLarge_future = uint64_signcmp(diff_calc_most_recent_sign, diff_calc_most_recent, neg_sign, neg_sign * allowed_deviation_neg) < 0;	/* Calculated deviation must be smaller or equal to allowed deviation to fail. */
		isTimeDiffTooLarge = isTimeDiffTooLarge_past || isTimeDiffTooLarge_future;

		if (allowed_deviation_pos > 0 && allowed_deviation_neg == 0) {
			isSigTimeOlderThanRecTime = (blocks->sigTime_1 < blocks->rec_time_min) || (blocks->sigTime_1 < blocks->rec_time_max);
		}


		/* Format some strings for debugging output and error messages. */
		time_diff_to_string(diff_calc_less_recent, str_diff_calc_past, sizeof(str_diff_calc_past));
		time_diff_to_string(diff_calc_most_recent, str_diff_calc_future, sizeof(str_diff_calc_future));
		LOGKSI_uint64_toDateString(blocks->rec_time_min, str_rec_time_min, sizeof(str_rec_time_min));
		LOGKSI_uint64_toDateString(blocks->rec_time_max, str_rec_time_max, sizeof(str_rec_time_max));

		if (uint64_signcmp(diff_calc_most_recent_sign, diff_calc_most_recent, 1, 0) >= 0 && uint64_signcmp(diff_calc_less_recent_sign, diff_calc_less_recent, 1, 0) >= 0) {
			KSI_snprintf(str_diff_calc, sizeof(str_diff_calc), "%s%s", (diff_calc_less_recent_sign < 0 ? "-" : ""), str_diff_calc_past);
		} else if (uint64_signcmp(diff_calc_most_recent_sign, diff_calc_most_recent, 1, 0) <= 0 && uint64_signcmp(diff_calc_less_recent_sign, diff_calc_less_recent, 1, 0) <= 0) {
			KSI_snprintf(str_diff_calc, sizeof(str_diff_calc), "%s%s", (diff_calc_most_recent_sign < 0 ? "-" : ""), str_diff_calc_future);
		} else {
			KSI_snprintf(str_diff_calc, sizeof(str_diff_calc), "-%s - %s", str_diff_calc_future, str_diff_calc_past);
		}


		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: time extracted from least recent log line: %s\n", blocks->blockNo, str_rec_time_min);
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: time extracted from most recent log line:  %s\n", blocks->blockNo, str_rec_time_max);
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: block time window:  %s\n", blocks->blockNo, str_diff_calc);

		print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: checking if time embedded into log lines fits in specified time window relative to the KSI signature... ", blocks->blockNo);

		/* In case of failure leave a mark and format some more strings. */
		if (isSigTimeOlderThanRecTime || isTimeDiffTooLarge) {
			res = KT_VERIFICATION_FAILURE;
			blocks->nofTotalFailedBlocks++;
			print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

			LOGKSI_uint64_toDateString(blocks->sigTime_1, str_sigTime1, sizeof(str_sigTime1));

			if (allowed_deviation_neg != 0 && allowed_deviation_pos != 0) {
				char neg_buf[256];
				char pos_buf[256];

				time_diff_to_string(neg_sign * allowed_deviation_neg, neg_buf, sizeof(neg_buf));
				time_diff_to_string(allowed_deviation_pos, pos_buf, sizeof(pos_buf));

				KSI_snprintf(str_allowed_diff, sizeof(str_allowed_diff), "-%s - %s", neg_buf, pos_buf);
			} else if (allowed_deviation_neg != 0) {
				str_allowed_diff[0] = '-';
				time_diff_to_string(neg_sign * allowed_deviation_neg, str_allowed_diff + 1, sizeof(str_allowed_diff) - 1);
			} else if (allowed_deviation_pos != 0) {
				time_diff_to_string(allowed_deviation_pos, str_allowed_diff, sizeof(str_allowed_diff));
			} else {
				PST_strncpy(str_allowed_diff, "<unexpected: no value>", sizeof(str_allowed_diff));
			}

		}

		/* In case of failures format final error messages.*/
		if (isSigTimeOlderThanRecTime) {
				print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: %s the log lines are more recent than KSI signature.\n", blocks->blockNo, (blocks->sigTime_1 < blocks->rec_time_min ? "All" : "Some of"));
				print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: %s the log lines in block %zu are more recent than KSI signature:\n"
																					  "   + Signing time:                              %s\n"
																					  "   + Time extracted from least recent log line: %s\n"
																					  "   + Time extracted from most recent log line:  %s\n"
																					  ,  (blocks->sigTime_1 < blocks->rec_time_min ? "All" : "Some of"), blocks->blockNo, str_sigTime1, str_rec_time_min, str_rec_time_max);
			blocks->quietError = res;
			if (blocks->isContinuedOnFail) res = KT_OK;
			else ERR_TRCKR_ADD(err, res, "Error: %s the log lines in block %zu are more recent than KSI signature!", (blocks->sigTime_1 < blocks->rec_time_min ? "All" : "Some of"), blocks->blockNo);
			goto cleanup;
		} else if (isTimeDiffTooLarge) {
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Log lines do not fit into expected time window (%s).\n", blocks->blockNo, str_allowed_diff);
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Log lines in block %zu do not fit into time window:\n"
																				  "   + Signing time:                              %s\n"
																				  "   + Time extracted from least recent log line: %s\n"
																				  "   + Time extracted from most recent log line:  %s\n"
																				  "   + Block time window:                         %s\n"
																				  "   + Expected time window:                      %s\n"
																				  , blocks->blockNo, str_sigTime1, str_rec_time_min, str_rec_time_max, str_diff_calc, str_allowed_diff);
			blocks->quietError = res;
			if (blocks->isContinuedOnFail) res = KT_OK;
			else ERR_TRCKR_ADD(err, res, "Error: Log lines in block %zu do not fit into time window!", blocks->blockNo);
			goto cleanup;
		}

		if (res != KT_OK) goto cleanup;
	}

	res = KT_OK;

cleanup:

	return res;
}


#define SIZE_OF_SHORT_INDENTENTION 13
#define SIZE_OF_LONG_INDENTATION 29

static int handle_record_time_check_between_files(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, BLOCK_INFO *blocks, IO_FILES *files) {
	int res = KT_UNKNOWN_ERROR;

	if (set == NULL || mp == NULL || err == NULL || blocks == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (blocks->blockNo == 1 && blocks->rec_time_in_file_max != 0 && blocks->rec_time_min != 0 && PARAM_SET_isSetByName(set, "time-diff")) {
		int time_diff = 0;

		if (PARAM_SET_isSetByName(set, "time-disordered")) {
			res = PARAM_SET_getObj(set, "time-disordered", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, (void**)&time_diff);
			ERR_CATCH_MSG(err, res, "Error: Unable to extract time base as integer.");
		}

		if (blocks->rec_time_in_file_max > blocks->rec_time_min + time_diff) {
			char str_last_time[1024] = "<null>";
			char str_current_time[1024] = "<null>";

			/* Check if deviation in current range is accepted. */
			res = KT_VERIFICATION_FAILURE;
			print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);
			LOGKSI_uint64_toDateString(blocks->rec_time_in_file_max, str_last_time, sizeof(str_last_time));
			LOGKSI_uint64_toDateString(blocks->rec_time_min, str_current_time, sizeof(str_current_time));

			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Last log line (%s) from previous file is more recent than first log line (%s) from current file.\n", blocks->blockNo, str_last_time, str_current_time);

			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Most recent log line from previous file is more recent than least recent log line from current file:\n"
																			  "   + Previous log file:              %s\n"
																			  "   + Time for most recent log line:  %s\n"
																			  "   + Current log file:               %s\n"
																			  "   + Time for least recent log line: %s\n"
																			  ,files->previousLogFile , str_last_time, io_files_getCurrentLogFilePrintRepresentation(files), str_current_time);
			blocks->quietError = res;
			if (blocks->isContinuedOnFail) res = KT_OK;
			else ERR_TRCKR_ADD(err, res, "Error: Most recent log line from previous file is more recent than least recent log line from current file!");
			goto cleanup;
		}
	}

	res = KT_OK;

cleanup:

  return res;
}

static int handle_block_signing_time_check(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, BLOCK_INFO *blocks, IO_FILES *files) {
	int res = KT_UNKNOWN_ERROR;
	char *dummy = NULL;
	int checkDescSigkTime = 0;
	int warnSameSigTime = 0;
	int checkSigTimeDiff = 0;
	int hasFailed = 0;

	if (set == NULL || mp == NULL || err == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = PARAM_SET_getStr(set, "ignore-desc-block-time", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &dummy);
	checkDescSigkTime = !(res == PST_PARAMETER_NOT_FOUND || res == PST_OK);

	warnSameSigTime = PARAM_SET_isSetByName(set, "warn-same-block-time");
	checkSigTimeDiff = PARAM_SET_isSetByName(set, "block-time-diff");


	/* Check if previous signature is older than the current one. If not, rise the error. */
	if (checkDescSigkTime || warnSameSigTime || checkSigTimeDiff) {
		char buf[256];
		char strT0[256];
		char strT1[256];
		int logStdin = files->internal.inLog == NULL;
		char *currentLogFile = logStdin ? "stdin" : files->internal.inLog;
		char *previousLogFile = files->previousLogFile;


		/* When sigTime_0 is 0 it is the first signature and there is nothing to check.
		   If sigTime_1 is 0 the last block must have been failed and skipped. */
		if (blocks->sigTime_0 > 0 && blocks->sigTime_1 > 0) {
			char str_diff[256] = "<null>";
			uint64_t diff = 0;
			int diff_sign = 0;
			const char *str_diff_sign = "";

			diff = uint64_diff(blocks->sigTime_1, blocks->sigTime_0, &diff_sign);
			if (diff_sign < 0) str_diff_sign = "-";

			LOGKSI_uint64_toDateString(blocks->sigTime_0, strT0, sizeof(strT0));
			LOGKSI_uint64_toDateString(blocks->sigTime_1, strT1, sizeof(strT1));
			time_diff_to_string(diff, str_diff, sizeof(str_diff));

			print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: time difference relative to previous block: %s%s\n", blocks->blockNo, str_diff_sign, str_diff);
			print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: checking signing time with previous block... ", blocks->blockNo);


			if (checkSigTimeDiff) {
				int min_sign = 0;
				int max_sign = 0;
				int is_too_close = 0;
				int is_too_apart = 0;
				int is_too_apart_to_future = 0;
				MIN_MAX_INT tmp;


				res = PARAM_SET_getObj(set, "block-time-diff", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, (void**)&tmp);
				ERR_CATCH_MSG(err, res, "Error: Unable to extract time base as integer.");

				/* Artificially create another boundary as with single value min and max are equal. */
				if (tmp.count == 1) {
					if (tmp.min < 0) {
						tmp.max = 0;
					} else {
						tmp.min = 0;
					}
				}

				min_sign = tmp.min >= 0 ? 1 : -1;
				max_sign = tmp.max >= 0 ? 1 : -1;


				/* Two blocks can only be too close if both diff and tmp.min are positive (the "future" is not counted).  */
				is_too_close = tmp.count == 2 && tmp.min >= 0 && diff_sign > 0 && (uint64_signcmp(diff_sign, diff, min_sign, min_sign * tmp.min) == -1);
				/* Two blocks can only be too close. */
				is_too_apart = diff_sign > 0 && ((tmp.neg_inf == 0 && uint64_signcmp(diff_sign, diff, min_sign, min_sign * tmp.min) == -1) || (tmp.pos_inf == 0 && uint64_signcmp(diff_sign, diff, max_sign, max_sign * tmp.max) == 1));
				is_too_apart_to_future = (diff_sign < 0 && checkDescSigkTime) && tmp.neg_inf == 0 && (uint64_signcmp(diff_sign, diff, min_sign, min_sign * tmp.min) == -1);

				/* A precise Check for negative time diff is performed, disable extra check. */
				if (min_sign < 0) checkDescSigkTime = 0;


				if (is_too_close || is_too_apart || is_too_apart_to_future) {
					const char *str_range = NULL;
					const char *reason = is_too_close ? "close" : (is_too_apart_to_future ? "apart in future": "apart");
					char str_max_diff[256] = "<null>";
					char str_min_diff[256] = "<null>";
					char str_tmp_range[256] = "<null>";

					if (tmp.pos_inf == 1) {
						PST_strncpy(str_max_diff, "oo", sizeof(str_max_diff));
					} else {
						int offset = max_sign == -1 ? 1 : 0;
						str_max_diff[0] = '-';
						time_diff_to_string(max_sign * tmp.max, str_max_diff + offset, sizeof(str_max_diff) - offset);
					}

					if (tmp.neg_inf == 1) {
						PST_strncpy(str_min_diff, "-oo", sizeof(str_min_diff));
					} else {
						int offset = min_sign == -1 ? 1 : 0;
						str_min_diff[0] = '-';
						time_diff_to_string(min_sign * tmp.min, str_min_diff + offset, sizeof(str_min_diff) - offset);
					}


					if (tmp.count == 2) {
						PST_snprintf(str_tmp_range, sizeof(str_tmp_range), "%s - %s", str_min_diff, str_max_diff);
						str_range = str_tmp_range;
					} else {
						if (tmp.min == 0) PST_snprintf(str_tmp_range, sizeof(str_tmp_range), "0 - %s", str_max_diff);
						else PST_snprintf(str_tmp_range, sizeof(str_tmp_range), "%s - 0", str_min_diff);
						str_range = str_tmp_range;
					}

					if (!hasFailed) blocks->nofTotalFailedBlocks++;
					res = KT_VERIFICATION_FAILURE;
					hasFailed = 1;

					print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);


					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: signing times difference (%s%s) relative to previous block out of range (%s).\n", blocks->blockNo, str_diff_sign, str_diff, str_range);

					if (blocks->blockNo == 1) {
						if (is_too_apart_to_future) {
							print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Signing times from last block of previous file is more recent than expected relative to first block of current file:\n");
						} else {
							print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Signing times from last block of previous file and first block of current file are too %s:\n", reason);
						}
						print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3,     "   + Previous file: %s\n"
																								  "   + Sig time: %s\n"
																								  "   + Current file:  %s\n"
																								  "   + Sig time: %s\n"
																								  "   + Time diff:              %s%s\n"
																								  "   + Expected time diff:     %s\n",
																								  files->previousLogFile, strT0,
																								  io_files_getCurrentLogFilePrintRepresentation(files), strT1,
																								  str_diff_sign, str_diff,
																								  str_range);
					} else {
						if (is_too_apart_to_future) {
							print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Blocks %zu signing time is more recent than expected relative to block %zu:\n", blocks->blockNo - 1, blocks->blockNo, reason);
						} else {
							print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Blocks %zu and %zu signing times are too %s:\n", blocks->blockNo - 1, blocks->blockNo, reason);
						}
						print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3,     "   + Sig time for block %zu: %s\n"
																								  "   + Sig time for block %zu: %s\n"
																								  "   + Time diff:              %s%s\n"
																								  "   + Expected time diff:     %s\n",
																								  blocks->blockNo - 1, strT0,
																								  blocks->blockNo, strT1,
																								  str_diff_sign, str_diff,
																								  str_range);
					}

					blocks->quietError = res;
					if (blocks->isContinuedOnFail) res = KT_OK;
					else ERR_TRCKR_ADD(err, res, "Error: Abnormal signing time difference for consecutive blocks!");

					goto cleanup;
				}
			}


			if (blocks->sigTime_0 > blocks->sigTime_1 && checkDescSigkTime) {
				print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_2, 1);
				print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_1, 1);
				blocks->errSignTime = 1;

				if (blocks->blockNo == 1) {

					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Last block %s from file '%s' is more recent than first block %s from file '%s'\n", blocks->blockNo, strT0, previousLogFile, strT1, currentLogFile);
					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Last block %s from file '%s' is more recent than\n"
																						  "          first block %s from file '%s'\n", strT0, previousLogFile, strT1, currentLogFile);
				} else {
					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Block no. %3zu %s in %s '%s' is more recent than block no. %3zu %s\n",blocks->blockNo, blocks->blockNo - 1, strT0, (logStdin ? "log from" : "file"), currentLogFile, blocks->blockNo, strT1);
					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Block no. %3zu %s in %s '%s' is more recent than\n"
																						  "          block no. %3zu %s\n", blocks->blockNo - 1, strT0, (logStdin ? "log from" : "file"), currentLogFile, blocks->blockNo, strT1);
				}

				if (!hasFailed) blocks->nofTotalFailedBlocks++;
				print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, 1);
			}

			if (blocks->sigTime_0 == blocks->sigTime_1 && warnSameSigTime) {
				if (blocks->blockNo == 1) {
					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Warning: Last block from file '%s' and first block from file '%s' has same signing time %s.\n", blocks->blockNo, previousLogFile, currentLogFile, LOGKSI_uint64_toDateString(blocks->sigTime_1, buf, sizeof(buf)));
					print_debug_mp(mp, MP_ID_LOGFILE_WARNINGS, DEBUG_SMALLER | DEBUG_LEVEL_3, "Warning: Last block from file      '%s'\n"
						                                                   "         and first block from file '%s'\n"
																		   "         has same signing time %s.\n", previousLogFile, currentLogFile, LOGKSI_uint64_toDateString(blocks->sigTime_1, buf, sizeof(buf)));
				} else {
					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Warning: Block no. %3zu and %3zu in %s '%s' has same signing time %s.\n" , blocks->blockNo - 1, blocks->blockNo, (logStdin ? "log from" : "file"), currentLogFile, strT1);
					print_debug_mp(mp, MP_ID_LOGFILE_WARNINGS, DEBUG_SMALLER | DEBUG_LEVEL_3, "Warning: Block no. %3zu and %3zu in %s '%s' has same signing time %s.\n" , blocks->blockNo - 1, blocks->blockNo, (logStdin ? "log from" : "file"), currentLogFile, strT1);
				}
			}
		}

		print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_2, 0);

	}


	res = KT_OK;

cleanup:

	return res;
}


static int finalize_block(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;

	if (set == NULL || err == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (blocks->blockNo > blocks->sigNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: block signature data missing.", blocks->blockNo);
	}

	res = handle_record_time_check_between_files(set, mp, err, blocks, files);
	if (res != KT_OK) goto cleanup;

	if ((blocks->rec_time_in_file_min == 0 || blocks->rec_time_in_file_min > blocks->rec_time_min) && blocks->rec_time_min > 0) blocks->rec_time_in_file_min = blocks->rec_time_min;
	if (blocks->rec_time_in_file_max == 0 || blocks->rec_time_in_file_max < blocks->rec_time_max) blocks->rec_time_in_file_max = blocks->rec_time_max;

	res = handle_block_signing_time_check(set, mp, err, blocks, files);
	if (res != KT_OK) goto cleanup;

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_2, 0);
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, 0);

	if (blocks->blockNo > 0) {
		char strT1[256] = "<no signature data available>";
		char strExtTo[256] = "<null>";
		char inHash[256] = "<null>";
		char outHash[256] = "<null>";
		int isSignTask = 0;
		int isExtractTask = 0;
		int isExtendTask = 0;
		int shortIndentation = SIZE_OF_SHORT_INDENTENTION;
		int longIndentation = SIZE_OF_LONG_INDENTATION;

		if (blocks->sigTime_1 > 0) {
			LOGKSI_uint64_toDateString(blocks->sigTime_1, strT1, sizeof(strT1));
		}

		if (blocks->extendedToTime > 0) {
			LOGKSI_uint64_toDateString(blocks->extendedToTime, strExtTo, sizeof(strExtTo));
		}

		LOGKSI_DataHash_toString(blocks->inputHash, inHash, sizeof(inHash));
		LOGKSI_DataHash_toString(blocks->prevLeaf, outHash, sizeof(outHash));

		isSignTask = blocks->taskId == TASK_SIGN;
		isExtractTask = blocks->taskId == TASK_EXTRACT;
		isExtendTask = blocks->taskId == TASK_EXTEND;


		if (blocks->version != RECSIG11 && blocks->version != RECSIG12 &&
			((isSignTask && blocks->curBlockJustReSigned) || (isExtractTask && blocks->nofExtractPositionsInBlock) || (!isSignTask && !isExtractTask))) {
			print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, "\nSummary of block %zu:\n", blocks->blockNo);

			if (isSignTask || isExtractTask || isExtendTask) {
				shortIndentation = longIndentation;
			}

			if (!blocks->curBlockNotSigned) {
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", shortIndentation, "Sig time:", strT1);
				if (blocks->extendedToTime > 0) print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", shortIndentation, "Extended to:", strExtTo);
			} else {
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", shortIndentation, "Sig time:", "<unsigned>");
			}

			if (!isSignTask && !isExtractTask && !isExtendTask) {
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", shortIndentation, "Input hash:", inHash);
				if (blocks->signatureTLVReached) {
					print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", shortIndentation, "Output hash:", outHash);
				} else {
					print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", shortIndentation, "Output hash:", "<not valid value>");
				}
			}

			/* Print line numbers. */
			if (blocks->firstLineInBlock < blocks->nofTotalRecordHashes) {
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%zu - %zu (%zu)\n", longIndentation, "Lines:", blocks->firstLineInBlock, blocks->nofTotalRecordHashes, blocks->recordCount - blocks->nofMetaRecords);
			} else if (blocks->recordCount == 1 && blocks->nofMetaRecords == 1) {
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*sn/a\n", longIndentation, "Line:");
			} else if (blocks->firstLineInBlock == blocks->nofTotalRecordHashes) {
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%zu\n", longIndentation, "Line:", blocks->firstLineInBlock);
			} else {
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s<unknown>\n", longIndentation, "Line:");
			}

			if (blocks->rec_time_min > 0) {
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", longIndentation, "First record time:", LOGKSI_uint64_toDateString(blocks->rec_time_min, strT1, sizeof(strT1)));
			}

			if (blocks->rec_time_max > 0) {
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", longIndentation, "Last record time:", LOGKSI_uint64_toDateString(blocks->rec_time_max, strT1, sizeof(strT1)));
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", longIndentation, "Block duration:", time_diff_to_string(blocks->rec_time_max - blocks->rec_time_min, strT1, sizeof(strT1)));

			}

			if (blocks->nofMetaRecords > 0) print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%zu\n", longIndentation, "Count of meta-records:", blocks->nofMetaRecords);
			if (blocks->nofHashFails > 0) print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%zu\n", longIndentation, "Count of hash failures:", blocks->nofHashFails);
			if (blocks->nofExtractPositionsInBlock > 0) print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%zu\n", longIndentation, "Records extracted:", blocks->nofExtractPositionsInBlock);

			print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, "\n", outHash);
		}
	}

	/* Print Output hash of previous block. */
	if (blocks->prevLeaf != NULL && blocks->taskId == TASK_VERIFY && blocks->signatureTLVReached) {
		char buf[256];
		LOGKSI_DataHash_toString(blocks->prevLeaf, buf, sizeof(buf));
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: output hash: %s.\n", blocks->blockNo, buf);
	}

	if (blocks->unsignedRootHash) {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Warning: Block no. %3zu: unsigned root hash found.\n", blocks->blockNo);
	}

	if (blocks->finalTreeHashesNone) {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: Warning: all final tree hashes are missing.\n", blocks->blockNo);
		blocks->warningTreeHashes = 1;
	} else if (blocks->finalTreeHashesAll) {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: all final tree hashes are present.\n", blocks->blockNo);
	}

	res = KT_OK;

cleanup:

	MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);
	MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_ERRORS);
	MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_SUMMARY);

	return res;
}

static int init_next_block(BLOCK_INFO *blocks) {
	if (blocks == NULL) return KT_INVALID_ARGUMENT;

	blocks->blockNo++;
	blocks->recordCount = 0;
	blocks->nofRecordHashes = 0;
	blocks->nofTreeHashes = 0;
	blocks->finalTreeHashesSome = 0;
	blocks->finalTreeHashesNone = 0;
	blocks->finalTreeHashesAll = 0;
	blocks->finalTreeHashesLeaf = 0;
	blocks->unsignedRootHash = 0;
	blocks->keepRecordHashes = 0;
	blocks->keepTreeHashes = 0;
	blocks->firstLineInBlock = blocks->nofTotalRecordHashes + 1;
	blocks->nofMetaRecords = 0;
	blocks->curBlockNotSigned = 0;
	blocks->curBlockJustReSigned = 0;
	blocks->nofHashFails = 0;
	blocks->signatureTLVReached = 0;

	/* Previous and current (next) signature time. Note that 0 indicates not set. */
	blocks->sigTime_0 = blocks->sigTime_1;
	blocks->sigTime_1 = 0;
	blocks->rec_time_max = 0;
	blocks->rec_time_min = 0;
	blocks->extendedToTime = 0;
	return KT_OK;
}


static int process_block_header(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_DataHash *hash = NULL;
	KSI_DataHash *replacement = NULL;
	unsigned char i = 0;
	KSI_TlvElement *tlv = NULL;
	size_t algo;
	size_t j;
	KSI_DataHasher *hasher = NULL;

	if (err == NULL || ksi == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: processing block header... ", blocks->blockNo);



	res = tlv_element_parse_and_check_sub_elements(err, ksi, blocks->ftlv_raw, blocks->ftlv_len, blocks->ftlv.hdr_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse block header as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &algo);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing hash algorithm in block header.", blocks->blockNo);

	if (blocks->hasher == NULL || blocks->hashAlgo != algo) {
		res = KSI_DataHasher_open(ksi, algo, &hasher);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: could not open datahasher.", blocks->blockNo);
	}

	KSI_OctetString_free(blocks->randomSeed);
	blocks->randomSeed = NULL;
	res = tlv_element_get_octet_string(tlv, ksi, 0x02, &blocks->randomSeed);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing random seed in block header.", blocks->blockNo);

	res = tlv_element_get_hash(err, tlv, ksi, 0x03, &hash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse last hash of previous block.", blocks->blockNo);

	KSI_DataHash_free(blocks->inputHash);
	blocks->inputHash = KSI_DataHash_ref(hash);

	if (blocks->prevLeaf != NULL) {
		char description[1024];
		PST_snprintf(description, sizeof(description), "Output hash of block %zu differs from input hash of block %zu", blocks->blockNo - 1, blocks->blockNo);

		res = logksi_datahash_compare(err, mp, blocks, 0, blocks->prevLeaf, hash, description, "Last hash computed from previous block data:", "Input hash stored in current block header:");
		res = continue_on_hash_fail(res, set, mp, blocks, blocks->prevLeaf, hash, &replacement);
		if (res != KT_OK && blocks->isContinuedOnFail && blocks->taskId == TASK_VERIFY) {
			char debugMessage[1024] = "";

			if (blocks->lastBlockWasSkipped) {
				PST_snprintf(debugMessage, sizeof(debugMessage), " Failure may be caused by the error in the previous block %zu. Using input hash of the current block instead.", blocks->blockNo - 1);
				replacement = KSI_DataHash_ref(hash);
			}

			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "   + Verification is continued.%s\n", debugMessage);
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Verification is continued.%s\n", blocks->blockNo, debugMessage);
			res = KT_OK;
		} else {
			ERR_CATCH_MSG(err, res, "Error: %s.", description);
		}
	} else {
		replacement = KSI_DataHash_ref(hash);
	}

	if (files->files.outSig) {
		/* Set the offset at the beginning of new block, so it is possible to apply recovery procedures if there is a failure. */
		res = SMART_FILE_markConsistent(files->files.outSig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Unable to mark output log signature file consistent.", blocks->blockNo);

		res = SMART_FILE_write(files->files.outSig, blocks->ftlv_raw, blocks->ftlv_len, NULL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to copy block header.", blocks->blockNo);
	}

	blocks->hashAlgo = algo;
	if (hasher) {
		KSI_DataHasher_free(blocks->hasher);
		blocks->hasher = hasher;
		hasher = NULL;
	}
	KSI_DataHash_free(blocks->prevLeaf);
	blocks->prevLeaf = replacement;

	while (i < blocks->treeHeight) {
		KSI_DataHash_free(blocks->MerkleTree[i]);
		blocks->MerkleTree[i] = NULL;
		KSI_DataHash_free(blocks->notVerified[i]);
		blocks->notVerified[i] = NULL;
		i++;
	}
	blocks->treeHeight = 0;
	blocks->balanced = 0;
	KSI_DataHash_free(blocks->rootHash);
	blocks->rootHash = NULL;
	KSI_DataHash_free(blocks->metarecordHash);
	blocks->metarecordHash = NULL;
	free(blocks->metaRecord);
	blocks->metaRecord = NULL;

	KSI_DataHash_free(blocks->extractMask);
	blocks->extractMask = NULL;
	for (j = 0; j < blocks->nofExtractPositionsInBlock; j++) {
		for (i = 0; i < blocks->extractInfo[j].extractLevel; i++) {
			KSI_DataHash_free(blocks->extractInfo[j].extractChain[i].sibling);
			blocks->extractInfo[j].extractChain[i].sibling = NULL;
		}
		blocks->extractInfo[j].extractLevel = 0;
		KSI_DataHash_free(blocks->extractInfo[j].extractRecord);
		blocks->extractInfo[j].extractRecord = NULL;
		free(blocks->extractInfo[j].logLine);
		blocks->extractInfo[j].logLine = NULL;
		KSI_TlvElement_free(blocks->extractInfo[j].metaRecord);
		blocks->extractInfo[j].metaRecord = NULL;
	}
	free(blocks->extractInfo);
	blocks->extractInfo = NULL;
	blocks->nofExtractPositionsInBlock = 0;

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
	KSI_DataHash_free(hash);
	KSI_TlvElement_free(tlv);
	KSI_DataHasher_free(hasher);
	return res;
}

static int is_record_hash_expected(ERR_TRCKR *err, BLOCK_INFO *blocks) {
	int res;

	if (err == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Check if record hash is received between block header and block signature. */
	if (blocks->blockNo == blocks->sigNo) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: record hash without preceding block header found.", blocks->blockNo + 1);
	}
	/* Check if record hashes are present for previous records. */
	if (blocks->keepRecordHashes == 0 && blocks->nofRecordHashes > 0) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record hash for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));
	}
	/* Check if all tree hashes are present for previous records. */
	if (blocks->keepTreeHashes && blocks->nofTreeHashes != max_tree_hashes(blocks->nofRecordHashes)) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing tree hash(es) for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));
	}

	res = KT_OK;

cleanup:

	return res;
}

static int process_record_hash(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_DataHash *recordHash = NULL;
	KSI_DataHash *hash = NULL;
	KSI_DataHash *replacement = NULL;

	if (err == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	res = is_record_hash_expected(err, blocks);
	if (res != KT_OK) goto cleanup;

	blocks->keepRecordHashes = 1;
	blocks->nofRecordHashes++;

	res = LOGKSI_DataHash_fromImprint(err, ksi, blocks->ftlv_raw + blocks->ftlv.hdr_len, blocks->ftlv.dat_len, &recordHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse hash of logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));

	if (blocks->metarecordHash != NULL) {
		char description[1024];
		PST_snprintf(description, sizeof(description), "Metarecord hash mismatch in block %zu", blocks->blockNo);

		/* This is a metarecord hash. */
		res = logksi_datahash_compare(err, mp, blocks, 0, blocks->metarecordHash, recordHash, description, "Metarecord hash computed from metarecord:", "Metarecord hash stored in log signature file:");
		res = continue_on_hash_fail(res, set, mp, blocks, blocks->metarecordHash, recordHash, &replacement);
		if (!blocks->isContinuedOnFail || blocks->taskId != TASK_VERIFY) {
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: metarecord hashes not equal.", blocks->blockNo);
		}

		if (res != KT_OK) goto cleanup;
		res = block_info_add_record_hash_to_merkle_tree(blocks, err, ksi, 1, replacement);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);

		KSI_DataHash_free(blocks->metarecordHash);
		blocks->metarecordHash = NULL;
	} else {
		/* This is a logline record hash. */
		if (files->files.inLog) {
			res = block_info_calculate_hash_of_logline_and_store_logline_check_log_time(set, err, mp, blocks, files, &hash);
			if (res == KT_IO_ERROR) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: record hash no. %zu does not have a matching logline, end of logfile reached.", blocks->blockNo, get_nof_lines(blocks));
			} else if (res != KT_OK) goto cleanup;

			res = logksi_datahash_compare(err, mp, blocks, 1, hash, recordHash, NULL, "Record hash computed from logline:", "Record hash stored in log signature file:");
			res = continue_on_hash_fail(res, set, mp, blocks, hash, recordHash, &replacement);
			if (!blocks->isContinuedOnFail || blocks->taskId != TASK_VERIFY) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: record hashes not equal for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));
			}

			if (res != KT_OK) goto cleanup;
		} else {
			replacement = KSI_DataHash_ref(recordHash);
		}

		res = block_info_add_record_hash_to_merkle_tree(blocks, err, ksi, 0, replacement);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add hash to Merkle tree.", blocks->blockNo);
	}

	if (files->files.outSig) {
		res = SMART_FILE_write(files->files.outSig, blocks->ftlv_raw, blocks->ftlv_len, NULL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to copy record hash.", blocks->blockNo);
	}
	res = KT_OK;

cleanup:

	KSI_DataHash_free(replacement);
	KSI_DataHash_free(recordHash);
	KSI_DataHash_free(hash);
	return res;
}

static int max_final_hashes(BLOCK_INFO *blocks) {
	int finalHashes = 0;
	int i;
	if (blocks) {
		for (i = 0; i < blocks->treeHeight; i++) {
			if (blocks->MerkleTree[i]) {
				finalHashes++;
			}
		}
		finalHashes--;
	}
	return finalHashes;
}

static size_t nof_unverified_hashes(BLOCK_INFO *blocks) {
	size_t count = 0;
	size_t i;

	for (i = 0; i < blocks->treeHeight; i++) {
		if (blocks->notVerified[i]) {
			count++;
		}
	}

	return count;
}

static int is_tree_hash_expected(ERR_TRCKR *err, BLOCK_INFO *blocks) {
	int res;
	int i;

	if (err == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	/* Check if tree hash is received between block header and block signature. */
	if (blocks->blockNo == blocks->sigNo) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: tree hash without preceding block header found.", blocks->blockNo + 1);
	}
	/* Check if tree hashes are present for previous records. */
	if (blocks->keepTreeHashes == 0 && blocks->nofRecordHashes > 1) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing tree hash for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks) - 1);
	}
	/* Check if all record hashes are present for previous records. */
	if (blocks->keepRecordHashes && blocks->nofTreeHashes == max_tree_hashes(blocks->nofRecordHashes)) {
		/* All the tree hashes that can be computed from the received record hashes have been received.
		 * However, another tree hash was just received, so either the preceding record hash is missing or
		 * the tree hash is used in finalizing the unbalanced tree. */
		if (blocks->balanced) {
			/* The tree is balanced, so no finalizing is needed. Thus the tree hash is unexpected, probably due to a missing record hash. */
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record hash for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks) + 1);
		} else if (blocks->metarecordHash) {
			/* A metarecord hash is missing while the tree hash for the metarecord is present. */
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record hash for metarecord with index %zu.", blocks->blockNo, blocks->nofRecordHashes);
		} else {
			/* Assuming that no record hashes are missing, let's start the finalizing process. */
			blocks->finalTreeHashesSome = 1;
			/* Prepare tree hashes for verification of finalizing. */
			for (i = 0; i < blocks->treeHeight; i++) {
				blocks->notVerified[i] = KSI_DataHash_ref(blocks->MerkleTree[i]);
			}
		}
	}

	/* Check if all final tree hashes are present. */
	if (blocks->finalTreeHashesSome && blocks->nofTreeHashes == max_tree_hashes(blocks->nofRecordHashes) + max_final_hashes(blocks)) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unexpected final tree hash no. %zu.", blocks->blockNo, blocks->nofTreeHashes + 1);
	}

	res = KT_OK;

cleanup:

	return res;
}

static int process_tree_hash(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files, int *finalHash) {
	int res;
	KSI_DataHash *treeHash = NULL;
	KSI_DataHash *recordHash = NULL;
	KSI_DataHash *tmpRoot = NULL;
	KSI_DataHash *root = NULL;
	KSI_DataHash *replacement = NULL;
	unsigned char i;

	if (err == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	res = is_tree_hash_expected(err, blocks);
	if (res != KT_OK) goto cleanup;

	blocks->keepTreeHashes = 1;
	blocks->nofTreeHashes++;

	res = LOGKSI_DataHash_fromImprint(err, ksi, blocks->ftlv_raw + blocks->ftlv.hdr_len, blocks->ftlv.dat_len, &treeHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse tree hash.", blocks->blockNo);

	if (files->files.outSig) {
		res = SMART_FILE_write(files->files.outSig, blocks->ftlv_raw, blocks->ftlv_len, NULL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to copy tree hash.", blocks->blockNo);
	}

	if (!blocks->finalTreeHashesSome) {
		/* If the block contains tree hashes, but not record hashes:
		 * Calculate missing record hashes from the records in the logfile and
		 * build the Merkle tree according to the number of tree hashes encountered. */
		if (blocks->keepRecordHashes == 0 && blocks->nofTreeHashes > max_tree_hashes(blocks->nofRecordHashes)) {
			/* If the block is closed prematurely with a metarecord, process the current tree hash as a mandatory leaf hash.
			 * Subsequent tree hashes are either mandatory tree hashes corresponding to the metarecord hash or optional final tree hashes. */
			if (blocks->metarecordHash) {
				blocks->finalTreeHashesLeaf = 1;
			}
			blocks->nofRecordHashes++;
			if (files->files.inLog) {
				if (blocks->metarecordHash) {
					res = block_info_add_record_hash_to_merkle_tree(blocks, err, ksi, 1, blocks->metarecordHash);
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);

					KSI_DataHash_free(blocks->metarecordHash);
					blocks->metarecordHash = NULL;
				} else {
					res = block_info_calculate_hash_of_logline_and_store_logline_check_log_time(set, err, mp, blocks, files, &recordHash);
					if (res == KT_IO_ERROR) {
						ERR_CATCH_MSG(err, res, "Error: Block no. %zu: tree hash does not have a matching logline no. %zu, end of logfile reached.", blocks->blockNo, get_nof_lines(blocks));
					} else if (res != KT_OK) goto cleanup;

					res = block_info_add_record_hash_to_merkle_tree(blocks, err, ksi, 0, recordHash);
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add record hash to Merkle tree.", blocks->blockNo);
					KSI_DataHash_free(recordHash);
					recordHash = NULL;
				}
			} else {
				/* No log file available so build the Merkle tree from tree hashes alone. */
				res = block_info_add_leaf_hash_to_merkle_tree(blocks, ksi, treeHash, 0);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add leaf hash to Merkle tree.", blocks->blockNo);
			}
		}
		if (blocks->nofRecordHashes) {
			char description[1024];
			PST_snprintf(description, sizeof(description), "Tree hash mismatch in block %zu", blocks->blockNo);

			/* Find the corresponding tree hash from the Merkle tree. */
			for (i = 0; i < blocks->treeHeight; i++) {
				if (blocks->notVerified[i] != NULL) break;
			}
			if (i == blocks->treeHeight) {
				res = KT_VERIFICATION_FAILURE;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unexpected tree hash for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));
			}

			res = logksi_datahash_compare(err, mp, blocks, 0, blocks->notVerified[i], treeHash, description, "Tree hash computed from record hashes:", "Tree hash stored in log signature file:");
			res = continue_on_hash_fail(res, set, mp, blocks, blocks->notVerified[i], treeHash, &replacement);
			if (!blocks->isContinuedOnFail || blocks->taskId != TASK_VERIFY) {
				if (blocks->keepRecordHashes) {
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: tree hashes not equal for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));
				}

				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: tree hashes not equal.", blocks->blockNo);
			}

			if (res != KT_OK) goto cleanup;

			KSI_DataHash_free(blocks->notVerified[i]);
			blocks->notVerified[i] = NULL;
		}
		if (blocks->finalTreeHashesLeaf && !nof_unverified_hashes(blocks)) {
			/* This was the last mandatory tree hash. From this point forward all tree hashes must be interpreted as optional final tree hashes. */
			blocks->finalTreeHashesSome = 1;
			for (i = 0; i < blocks->treeHeight; i++) {
				blocks->notVerified[i] = KSI_DataHash_ref(blocks->MerkleTree[i]);
			}
		}
	} else {
		if (blocks->nofRecordHashes) {
			char description[1024];
			PST_snprintf(description, sizeof(description), "Tree hash mismatch in block %zu", blocks->blockNo);

			if (finalHash != NULL) *finalHash = 1;
			print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: interpreting tree hash no. %3zu as a final hash... ", blocks->blockNo, blocks->nofTreeHashes);
			/* Find the corresponding tree hash from the Merkle tree. */
			i = 0;
			while (i < blocks->treeHeight) {
				if (root == NULL) {
					root = KSI_DataHash_ref(blocks->notVerified[i]);
					KSI_DataHash_free(blocks->notVerified[i]);
					blocks->notVerified[i] = NULL;
					i++;
					continue;
				}
				if (blocks->notVerified[i]) {
					res = block_info_calculate_new_tree_hash(blocks, blocks->notVerified[i], root, i + 2, &tmpRoot);
					if (res != KT_OK) goto cleanup;

					KSI_DataHash_free(blocks->notVerified[i]);
					blocks->notVerified[i] = KSI_DataHash_ref(tmpRoot);
					break;
				}
				i++;
			}
			if (i == blocks->treeHeight) {
				res = KT_VERIFICATION_FAILURE;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unexpected tree hash for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));
			}

			res = logksi_datahash_compare(err, mp, blocks, 0, blocks->notVerified[i], treeHash, description, "Tree hash computed from record hashes:", "Tree hash stored in log signature file:");
			res = continue_on_hash_fail(res, set, mp, blocks, blocks->notVerified[i], treeHash, &replacement);
			if (!blocks->isContinuedOnFail || blocks->taskId != TASK_VERIFY) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: tree hashes not equal for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));
			}

			if (res != KT_OK) goto cleanup;
		}
	}

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
	KSI_DataHash_free(treeHash);
	KSI_DataHash_free(recordHash);
	KSI_DataHash_free(tmpRoot);
	KSI_DataHash_free(root);
	KSI_DataHash_free(replacement);
	return res;
}

static const char *meta_data_value_to_string(PARAM_SET* set, const KSI_OctetString *oct, char *buf, size_t buf_len) {
	int res = KT_UNKNOWN_ERROR;
	size_t i = 0;
	const unsigned char *data = NULL;
	size_t data_len = 0;
	size_t count = 0;
	const char *ret = NULL;

	if (set == NULL || oct == NULL || buf == NULL || buf_len == 0) return NULL;

	if (PARAM_SET_isSetByName(set, "hex-to-str")) {
		res = KSI_OctetString_extract(oct, &data, &data_len);
		if (res != KSI_OK) return NULL;

		buf[count++] = '\'';
		for (i = 0; i < data_len && count + 2 < buf_len; i++) {
			char c = data[i];

			if (isprint(c)) {
				buf[count] = c;
				count++;
			} else {
				count += PST_snprintf(buf + count, buf_len - count, "\\%02x", c);
			}
		}
		buf[count++] = '\'';
		buf[count] = '\0';

		ret = buf;
	} else {
		ret = KSI_OctetString_toString(oct, 0, buf, buf_len);
	}

	return ret;
}


static int process_metarecord(PARAM_SET* set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *meta_record_pair = NULL;
	KSI_Utf8String *meta_key = NULL;
	KSI_OctetString *meta_value = NULL;
	size_t metarecord_index = 0;
	char buf[0xffff + 3];

	if (err == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	res = tlv_element_parse_and_check_sub_elements(err, ksi, blocks->ftlv_raw, blocks->ftlv_len, blocks->ftlv.hdr_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse metarecord as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &metarecord_index);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing metarecord index.", blocks->blockNo);


	res = KSI_TlvElement_getElement(tlv, 0x02, &meta_record_pair);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Mandatory TLV 911.02 (Meta record pair) is missing.", blocks->blockNo);

	res = KSI_TlvElement_getUtf8String(meta_record_pair, ksi, 0x01, &meta_key);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Unable to get TLV 911.02.01 (Meta record key).", blocks->blockNo);

	res = KSI_TlvElement_getOctetString(meta_record_pair, ksi, 0x02, &meta_value);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Unable to get TLV 911.02.02 (Meta record value).", blocks->blockNo);

	print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Meta-record key  : '%s'.\n", blocks->blockNo, KSI_Utf8String_cstr(meta_key));
	print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Meta-record value: %s.\n", blocks->blockNo, meta_data_value_to_string(set, meta_value, buf, sizeof(buf)));


	if (files->files.inLog) {
		/* If the block contains metarecords but not the corresponding record hashes:
		 * Calculate missing metarecord hash from the last metarecord and
		 * build the Merkle tree according to the record count in the signature data. */
		if (blocks->metarecordHash != NULL) {
			/* Add the previous metarecord to Merkle tree. */
			blocks->nofRecordHashes++;
			res = block_info_add_record_hash_to_merkle_tree(blocks, err, ksi, 1, blocks->metarecordHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);
		}

		/*
		 * If there are some record hashes missing, read loglines from logfile and
		 * calculate corresponding record hash values and add them to merkle tree.
		 * After that it is possible to add metarecord itself to the Merkle tree.
		 */
		while (blocks->nofRecordHashes < metarecord_index) {
			blocks->nofRecordHashes++;
			res = block_info_calculate_hash_of_logline_and_store_logline_check_log_time(set, err, mp, blocks, files, &hash);
			if (res == KT_IO_ERROR) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: at least %zu loglines expected up to metarecord index %zu, end of logfile reached.", blocks->blockNo, get_nof_lines(blocks), metarecord_index);
			} else if (res != KT_OK) goto cleanup;

			res = block_info_add_record_hash_to_merkle_tree(blocks, err, ksi, 0, hash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);
			KSI_DataHash_free(hash);
			hash = NULL;
		}
	}

	KSI_DataHash_free(blocks->metarecordHash);
	blocks->metarecordHash = NULL;
	res = block_info_calculate_hash_of_metarecord_and_store_metarecord(blocks, tlv, &blocks->metarecordHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate metarecord hash with index %zu.", blocks->blockNo, metarecord_index);

	if (files->files.outSig) {
		res = SMART_FILE_write(files->files.outSig, blocks->ftlv_raw, blocks->ftlv_len, NULL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to copy metarecord hash.", blocks->blockNo);
	}

	res = KT_OK;

cleanup:

	KSI_DataHash_free(hash);
	KSI_TlvElement_free(meta_record_pair);
	KSI_Utf8String_free(meta_key);
	KSI_OctetString_free(meta_value);
	KSI_TlvElement_free(tlv);
	return res;
}

static int is_block_signature_expected(ERR_TRCKR *err, BLOCK_INFO *blocks) {
	int res;
	size_t maxTreeHashes;
	size_t maxFinalHashes;

	if (err == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	maxTreeHashes = max_tree_hashes(blocks->recordCount);
	maxFinalHashes = max_final_hashes(blocks);

	if (blocks->keepRecordHashes) {
		/* Check if record hash is present for the most recent metarecord (if any). */
		if (blocks->metarecordHash) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record hash for metarecord with index %zu.", blocks->blockNo, blocks->nofRecordHashes);
		}

		/* Check if all record hashes are present in the current block. */
		if (blocks->nofRecordHashes < blocks->recordCount) {
			res = KT_VERIFICATION_FAILURE;

			ERR_TRCKR_ADD(err, res, "Error: Block no. %zu: expected %zu record hashes, but found %zu.", blocks->blockNo, blocks->recordCount, blocks->nofRecordHashes);
			ERR_TRCKR_ADD(err, res, "Error: Block no. %zu: there are too few record hashes for this block.", blocks->blockNo);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record hash for logline no. %zu.", blocks->blockNo, get_nof_lines(blocks) + 1);
		}

		if (blocks->nofRecordHashes > blocks->recordCount) {
			res = KT_VERIFICATION_FAILURE;

			ERR_TRCKR_ADD(err, res, "Error: Block no. %zu: expected %zu record hashes, but found %zu.", blocks->blockNo, blocks->recordCount, blocks->nofRecordHashes);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: there are too many record hashes for this block.", blocks->blockNo);
		}
	}

	if (blocks->keepTreeHashes) {
		if (!blocks->keepRecordHashes && !blocks->balanced && !blocks->finalTreeHashesSome) {
			/* If LOGSIG12 format is used, metarecords are mandatory for closing unbalanced blocks. */
			if (blocks->version == LOGSIG12) {
				res = KT_VERIFICATION_FAILURE;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete block is closed without a metarecord.", blocks->blockNo);
			}
		}
		/* Check if all mandatory tree hashes are present in the current block. */
		if (blocks->nofTreeHashes < maxTreeHashes) {
			res = KT_VERIFICATION_FAILURE;
			if (blocks->metaRecord) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing tree hash(es) for metarecord with index %zu.", blocks->blockNo, blocks->nofRecordHashes - 1);
			} else {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing tree hash(es) for logline no. %zu.", blocks->blockNo, blocks->recordCount + blocks->nofTotalRecordHashes);
			}
		}
		/* Check if the block contains too few final tree hashes. */
		if (blocks->nofTreeHashes < maxTreeHashes + maxFinalHashes) {
			/* Check if none of the final tree hashes have yet been received. (Final tree hashes must all be present or all missing.) */
			if (blocks->nofTreeHashes == maxTreeHashes) {
				/* Check if there is reason to expect final tree hashes. */
				if (blocks->finalTreeHashesSome || blocks->keepRecordHashes) {
					/* All final tree hashes are missing, but at least they are being expected -> this is OK and can be repaired. */
					blocks->finalTreeHashesNone = 1;
				} else {
					/* If LOGSIG12 format is used, metarecords are mandatory for closing unbalanced blocks. */
					if (blocks->version == LOGSIG12) {
						/* All of the final tree hashes are missing, but they are not being expected either (e.g. missing metarecord). This should never happen. */
						res = KT_VERIFICATION_FAILURE;
						ERR_CATCH_MSG(err, res, "Error: Block no. %zu: all final tree hashes are missing and block is closed without a metarecord.", blocks->blockNo);
					}
				}
			} else {
				/* If some final tree hashes are present, they must all be present. */
				res = KT_VERIFICATION_FAILURE;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: found %zu final tree hashes instead of %zu.", blocks->blockNo, blocks->nofTreeHashes - maxTreeHashes, maxFinalHashes);
			}
		}
		/* Check if the block contains too many optional tree hashes. */
		if (blocks->nofTreeHashes > maxTreeHashes + maxFinalHashes) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: found %zu final tree hashes instead of %zu.", blocks->blockNo, blocks->nofTreeHashes - maxTreeHashes, maxFinalHashes);
		}
		if (blocks->nofTreeHashes == maxTreeHashes + maxFinalHashes) {
			blocks->finalTreeHashesAll = 1;
		}
	}

	res = KT_OK;

cleanup:

	return res;
}

static int check_log_signature_client_id(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, BLOCK_INFO *blocks, KSI_Signature *sig) {
	int res = KT_UNKNOWN_ERROR;
	char strClientId[0xffff] = "<client id not available>";

	if (set == NULL || mp == NULL || err == NULL || blocks == NULL || sig == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Verify KSI signatures Client ID. */
	if (blocks->client_id_match != NULL && blocks->taskId == TASK_VERIFY) {
		print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
		print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: Verifying Client ID... ", blocks->blockNo);

		LOGKSI_signerIdentityToString(sig, strClientId, sizeof(strClientId));

		res = REGEXP_processString(blocks->client_id_match, strClientId, NULL);
		if (res != REGEXP_NO_MATCH && res != REGEXP_OK) {
			ERR_TRCKR_ADD(err, res, "Error: Unexpected regular expression error: %i!", res);
			goto cleanup;
		}

		/* Verify that match is full match! */
		if (res == REGEXP_OK) {
			char match[0xffff] = "";

			res = REGEXP_getMatchingGroup(blocks->client_id_match, 0, match, sizeof(match));
			if (res != REGEXP_OK) {
				ERR_TRCKR_ADD(err, res, "Error: Unexpected regular expression error: %i!", res);
				goto cleanup;
			}

			if (strcmp(strClientId, match) != 0) res = REGEXP_NO_MATCH;
		}

		if (res != REGEXP_OK) {
			blocks->nofTotalFailedBlocks++;
			res = KT_VERIFICATION_FAILURE;
			blocks->quietError = res;
			print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Failed to match KSI signatures client ID for block %zu:\n"
																				  "   + Client ID:       '%s'\n"
																				  "   + Regexp. pattern: '%s'\n", blocks->blockNo, strClientId, REGEXP_getPattern(blocks->client_id_match));

			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Client ID mismatch '%s'.\n", blocks->blockNo, strClientId);
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Not matching pattern '%s'.\n", blocks->blockNo, REGEXP_getPattern(blocks->client_id_match));
		if (blocks->isContinuedOnFail) res = KT_OK;
		else ERR_TRCKR_ADD(err, res, "Error: Failed to match KSI signatures client ID for block %zu!", blocks->blockNo);
		goto cleanup;
		}
	}

	if (PARAM_SET_isSetByName(set, "warn-client-id-change")) {
		if (blocks->client_id_last[0] == '\0') {
			LOGKSI_signerIdentityToString(sig, blocks->client_id_last, sizeof(blocks->client_id_last));
		} else {
			LOGKSI_signerIdentityToString(sig, strClientId, sizeof(strClientId));

			if (strcmp(blocks->client_id_last, strClientId) != 0) {
				print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Warning: Client ID is not constant. Expecting '%s', but is '%s'.\n", blocks->blockNo, blocks->client_id_last, strClientId);
				print_debug_mp(mp, MP_ID_LOGFILE_WARNINGS, DEBUG_SMALLER | DEBUG_LEVEL_3, " o Warning: Client ID in block %zu is not constant:\n"
																						  "   + Expecting: '%s'\n"
																						  "   + But is:    '%s'.\n\n", blocks->blockNo, blocks->client_id_last, strClientId);
			}
		}
	}

	res = KT_OK;

cleanup:
	return res;
}

static int process_block_signature(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, KSI_PublicationsFile *pubFile, SIGNATURE_PROCESSORS *processors, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *verificationResult = NULL;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvSig = NULL;
	KSI_TlvElement *tlvUnsig = NULL;
	KSI_TlvElement *tlvRfc3161 = NULL;
	KSI_TlvElement *recChain = NULL;
	KSI_TlvElement *hashStep = NULL;
	KSI_Integer *t0 = NULL;
	size_t j;

	KSI_VerificationContext_init(&context, ksi);

	if (set == NULL || err == NULL || ksi == NULL || processors == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (MULTI_PRINTER_hasDataByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES)) {
		print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "}\n");
		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES);
	}

	blocks->sigNo++;
	if (blocks->sigNo > blocks->blockNo) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: block signature data without preceding block header found.", blocks->sigNo);
	}

	blocks->signatureTLVReached = 1;

	print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: processing block signature data... ", blocks->blockNo);

	res = tlv_element_parse_and_check_sub_elements(err, ksi, blocks->ftlv_raw, blocks->ftlv_len, blocks->ftlv.hdr_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse block signature as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &blocks->recordCount);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record count in block signature.", blocks->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x906, &tlvRfc3161);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract RFC3161 element in block signature.", blocks->blockNo);

	if (tlvRfc3161 != NULL) {
		/* Convert the RFC3161 timestamp into KSI signature and replace it in the TLV. */
		res = convert_signature(ksi, tlvRfc3161->ptr + tlvRfc3161->ftlv.hdr_len, tlvRfc3161->ftlv.dat_len, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to convert RFC3161 element in block signature.", blocks->blockNo);

		res = KSI_TlvElement_removeElement(tlv, 0x906, NULL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to remove RFC3161 timestamp from block signature.", blocks->blockNo);
		res = tlv_element_set_signature(tlv, ksi, 0x905, sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to insert KSI signature in block signature.", blocks->blockNo);
		KSI_Signature_free(sig);
		sig = NULL;

		blocks->warningLegacy = 1;
	}

	/* Try to extract KSI signature or unsigned block marker. */
	res = KSI_TlvElement_getElement(tlv, 0x905, &tlvSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract KSI signature element in block signature.", blocks->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x02, &tlvUnsig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract unsigned block marker.", blocks->blockNo);

	/* If block is unsigned, return verification error. If signature data is missing, return format error. */
	if (tlvUnsig != NULL) {
		res = KT_VERIFICATION_FAILURE;
		blocks->curBlockNotSigned = 1;
		blocks->quietError = res;
		print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);
		print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Block %zu is unsigned!\n", blocks->blockNo);
		print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Block is unsigned!\n", blocks->blockNo);
		/* Don't use ERR_CATCH_MSG when --continue-on-fail is set, as the amount of errors
		   produced will easily exceed the limits of ERR_TRCKR. */
		if (!blocks->isContinuedOnFail || blocks->taskId != TASK_VERIFY) {
			ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion: Make sure that block signature is actually the original output\n"
											 "                and KSI signature is not replaced with unsigned marker!\n"
											 "                If that's correct, use logksi sign to sign unsigned blocks.\n");
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu is unsigned and missing KSI signature in block signature.", blocks->blockNo);
		}

		goto cleanup;
	} else if (tlvSig == NULL) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing KSI signature (and unsigned block marker) in block signature.", blocks->blockNo);
	}


	res = is_block_signature_expected(err, blocks);
	if (res != KT_OK) goto cleanup;

	if (files->files.inLog) {
		/* If the block contains metarecords but not the corresponding record hashes:
		 * Calculate missing metarecord hash from the last metarecord and
		 * build the Merkle tree with the metarecord hash. */
		if (blocks->metarecordHash) {
			/* Add the previous metarecord to Merkle tree. */
			blocks->nofRecordHashes++;
			res = block_info_add_record_hash_to_merkle_tree(blocks, err, ksi, 1, blocks->metarecordHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add metarecord hash to Merkle tree.", blocks->blockNo);
		}

		/* If the block contains neither record hashes nor tree hashes:
		 * Calculate missing record hashes from the records in the logfile and
		 * build the Merkle tree according to the record count in the signature data. */
		if (blocks->keepRecordHashes == 0 && blocks->keepTreeHashes == 0) {
			while (blocks->nofRecordHashes < blocks->recordCount) {
				blocks->nofRecordHashes++;
				res = block_info_calculate_hash_of_logline_and_store_logline_check_log_time(set, err, mp, blocks, files, &hash);
				if (res == KT_IO_ERROR) {
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: at least %zu loglines expected, end of logfile reached.", blocks->blockNo, get_nof_lines(blocks));
				} else if (res != KT_OK) goto cleanup;

				res = block_info_add_record_hash_to_merkle_tree(blocks, err, ksi, 0, hash);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add hash to Merkle tree.", blocks->blockNo);
				KSI_DataHash_free(hash);
				hash = NULL;
			}
		}
	}

	/* If no record hashes were computed or encountered, previous leaf hashes must not be compared. */
	if (blocks->nofRecordHashes == 0) {
		KSI_DataHash_free(blocks->prevLeaf);
		blocks->prevLeaf = NULL;
	}

	/* If we have any record hashes directly from log signature file or indirectly from log file,
	 * their count must match the record count in block signature. */
	if (blocks->nofRecordHashes && blocks->nofRecordHashes != blocks->recordCount) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: expected %zu record hashes, but found %zu.", blocks->blockNo, blocks->recordCount, blocks->nofRecordHashes);
	}
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);


	blocks->nofTotalRecordHashes += blocks->nofRecordHashes;

	if (blocks->firstLineInBlock < blocks->nofTotalRecordHashes) {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: lines processed %zu - %zu (%zu)\n", blocks->blockNo, blocks->firstLineInBlock, blocks->nofTotalRecordHashes, blocks->recordCount - blocks->nofMetaRecords);
	} else if (blocks->recordCount == 1 && blocks->nofMetaRecords == 1) {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: line processed n/a\n", blocks->blockNo);
	} else if (blocks->firstLineInBlock == blocks->nofTotalRecordHashes) {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: line processed %zu\n", blocks->blockNo,  blocks->firstLineInBlock);
	} else {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: line processed <unknown>\n", blocks->blockNo);
	}


	print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_LEVEL_3, "Block no. %3zu: verifying KSI signature... ", blocks->blockNo);


	res = block_info_calculate_root_hash(blocks, ksi, (KSI_DataHash**)&context.documentHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get root hash for verification.", blocks->blockNo);

	context.docAggrLevel = block_info_get_aggregation_level(blocks);

	if (processors->verify_signature) {

		res = LOGKSI_Signature_parseWithPolicy(err, ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_EMPTY, NULL, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature.", blocks->blockNo);

		/* Verify KSI signature. */
		res = processors->verify_signature(set, mp, err, ksi, blocks, files, sig, (KSI_DataHash*)context.documentHash, context.docAggrLevel, &verificationResult);
		if (res != KSI_OK) {
			blocks->nofTotalFailedBlocks++;
			blocks->quietError = res;

			print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Verification of block %zu KSI signature failed!\n", blocks->blockNo);
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Verification of KSI signature failed!\n", blocks->blockNo);

			if (!blocks->isContinuedOnFail || blocks->taskId != TASK_VERIFY) {
				ERR_TRCKR_ADD(err, res, "Error: Block no. %zu: KSI signature verification failed.", blocks->blockNo);
			}

			goto cleanup;
		}

		/* TODO: add dumping of verification results. */
		KSI_PolicyVerificationResult_free(verificationResult);
		verificationResult = NULL;

	} else if (processors->extend_signature) {
		time_t t = 0;

		res = LOGKSI_Signature_parseWithPolicy(err, ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_INTERNAL, &context, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature.", blocks->blockNo);

		print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);

		res = processors->extend_signature(set, mp, err, ksi, blocks, files, sig, pubFile, &context, &ext);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extend KSI signature.", blocks->blockNo);

		res = KSI_Signature_getPublicationInfo(ext, NULL, NULL, &t, NULL, NULL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get publication time from KSI signature.", blocks->blockNo);

		blocks->extendedToTime = t;

		res = tlv_element_set_signature(tlv, ksi, 0x905, ext);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize extended KSI signature.", blocks->blockNo);

		res = KSI_TlvElement_serialize(tlv, blocks->ftlv_raw, SOF_FTLV_BUFFER, &blocks->ftlv_len, 0);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize extended block signature.", blocks->blockNo);

		if (blocks->warningLegacy) {
			int convertLegacy = PARAM_SET_isSetByName(set, "enable-rfc3161-conversion");

			if (files->internal.bOverwrite && !convertLegacy) {
				res = KT_RFC3161_EXT_IMPOSSIBLE;
				ERR_CATCH_MSG(err, res, "Error: Overwriting of legacy log signature file not enabled. Run 'logksi extend' with '--enable-rfc3161-conversion' to convert RFC3161 timestamps to KSI signatures.");
			}
			blocks->warningLegacy = 0;
		}

		res = SMART_FILE_write(files->files.outSig, blocks->ftlv_raw, blocks->ftlv_len, NULL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to write extended signature to extended log signature file.", blocks->blockNo);

		KSI_DataHash_free((KSI_DataHash*)context.documentHash);
		context.documentHash = NULL;
		KSI_VerificationContext_clean(&context);
	} else if (processors->extract_signature) {
		res = LOGKSI_Signature_parseWithPolicy(err, ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_INTERNAL, &context, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature.", blocks->blockNo);

		if (blocks->nofExtractPositionsInBlock) {
			res = SMART_FILE_write(files->files.outProof, tlvSig->ptr, tlvSig->ftlv.dat_len + tlvSig->ftlv.hdr_len, NULL);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to write KSI signature to integrity proof file.", blocks->blockNo);
		}


		for (j = 0; j < blocks->nofExtractPositionsInBlock; j++) {
			unsigned char buf[0xFFFF + 4];
			size_t len = 0;
			size_t i;

			if (blocks->extractInfo[j].extractOffset && blocks->extractInfo[j].extractOffset <= blocks->nofRecordHashes) {
				size_t rowNumber = blocks->nofTotalRecordHashes - blocks->nofRecordHashes + blocks->extractInfo[j].extractOffset;

				print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_2, res);
				print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: extracting log records (line %3zu)... ", blocks->blockNo, rowNumber);
				print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_EQUAL | DEBUG_LEVEL_2, "Extracting log record from block %3zu (line %3zu)... ", blocks->blockNo, rowNumber);

				res = KSI_TlvElement_new(&recChain);
				ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to create record chain.", blocks->extractInfo[j].extractPos);
				recChain->ftlv.tag = 0x0907;

				if (blocks->extractInfo[j].logLine) {
					res = SMART_FILE_write(files->files.outLog, (unsigned char*)blocks->extractInfo[j].logLine, strlen(blocks->extractInfo[j].logLine), NULL);
					ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to write log record to log records file.", blocks->extractInfo[j].extractPos);
				} else if (blocks->extractInfo[j].metaRecord){
					res = KSI_TlvElement_setElement(recChain, blocks->extractInfo[j].metaRecord);
					ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to add metarecord to record chain.", blocks->extractInfo[j].extractPos);
				}
				res = tlv_element_set_hash(recChain, ksi, 0x01, blocks->extractInfo[j].extractRecord);
				ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to add record hash to record chain.", blocks->extractInfo[j].extractPos);

				for (i = 0; i < blocks->extractInfo[j].extractLevel; i++) {
					if (blocks->extractInfo[j].extractChain[i].sibling) {
						res = KSI_TlvElement_new(&hashStep);
						ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to create hash step no. %zu.", blocks->extractInfo[j].extractPos, i + 1);

						if (blocks->extractInfo[j].extractChain[i].dir == LEFT_LINK) {
							hashStep->ftlv.tag = 0x02;
						}
						else {
							hashStep->ftlv.tag = 0x03;
						}
						if (blocks->extractInfo[j].extractChain[i].corr) {
							res = tlv_element_set_uint(hashStep, ksi, 0x01, blocks->extractInfo[j].extractChain[i].corr);
							ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to add level correction to hash step no. %zu.", blocks->extractInfo[j].extractPos, i + 1);
						}
						res = tlv_element_set_hash(hashStep, ksi, 0x02, blocks->extractInfo[j].extractChain[i].sibling);
						ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to add sibling hash to hash step no. %zu.", blocks->extractInfo[j].extractPos, i + 1);
						res = KSI_TlvElement_appendElement(recChain, hashStep);
						ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to add hash step no. %zu.", blocks->extractInfo[j].extractPos, i + 1);

						KSI_TlvElement_free(hashStep);
						hashStep = NULL;
					}
				}
				res = KSI_TlvElement_serialize(recChain, buf, sizeof(buf), &len, 0);
				ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to serialize record chain.", blocks->extractInfo[j].extractPos);

				res = SMART_FILE_write(files->files.outProof, buf, len, NULL);
				ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to write record chain to integrity proof file.", blocks->extractInfo[j].extractPos);

				KSI_TlvElement_free(recChain);
				recChain = NULL;
			}

		}

		print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_2, res);
		print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, res);
	}

	{
		KSI_Integer *t1 = NULL;
		char sigTimeStr[256] = "<null>";
		res = KSI_Signature_getSigningTime(sig, &t1);
		ERR_CATCH_MSG(err, res, NULL);

		blocks->sigTime_1 = KSI_Integer_getUInt64(t1);

		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: signing time: (%llu) %s\n", blocks->blockNo, blocks->sigTime_1, LOGKSI_signature_sigTimeToString(sig, sigTimeStr, sizeof(sigTimeStr)));
	}

	/* Verify KSI signatures Client ID. */
	res = check_log_signature_client_id(set, mp, err, blocks, sig);
	if (res != KT_OK) goto cleanup;

	res = check_log_record_embedded_time_against_ksi_signature_time(set, mp, err, blocks);
	if (res != KT_OK) goto cleanup;

	blocks->lastBlockWasSkipped = 0;
	res = KT_OK;

cleanup:
	if (processors->extract_signature) print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_2, res);
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);

	KSI_Signature_free(sig);
	KSI_Signature_free(ext);
	KSI_DataHash_free((KSI_DataHash*)context.documentHash);
	KSI_DataHash_free(hash);
	KSI_VerificationContext_clean(&context);
	KSI_PolicyVerificationResult_free(verificationResult);
	KSI_TlvElement_free(tlvSig);
	KSI_TlvElement_free(tlvUnsig);
	KSI_TlvElement_free(tlvRfc3161);
	KSI_TlvElement_free(tlv);
	KSI_TlvElement_free(hashStep);
	KSI_TlvElement_free(recChain);
	KSI_Integer_free(t0);
	return res;
}

static int process_ksi_signature(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, SIGNATURE_PROCESSORS *processors, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_Signature *sig = NULL;
	KSI_PolicyVerificationResult *verificationResult = NULL;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlvSig = NULL;
	KSI_DataHasher *hasher = NULL;
	KSI_HashAlgorithm algo;

	if (set == NULL || err == NULL || ksi == NULL || processors == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	blocks->blockNo++;
	blocks->sigNo++;
	print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: processing KSI signature ... ", blocks->blockNo);

	blocks->signatureTLVReached = 1;

	res = tlv_element_parse_and_check_sub_elements(err, ksi, blocks->ftlv_raw, blocks->ftlv_len, blocks->ftlv.hdr_len, &tlvSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature as TLV element.", blocks->blockNo);

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
	print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_LEVEL_3, "Block no. %3zu: verifying KSI signature... ", blocks->blockNo);

	if (processors->verify_signature) {
		res = LOGKSI_Signature_parseWithPolicy(err, ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_EMPTY, NULL, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature.", blocks->blockNo);

		res = processors->verify_signature(set, mp, err, ksi, blocks, files, sig, NULL, 0, &verificationResult);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: KSI signature verification failed.", blocks->blockNo);
		/* TODO: add dumping of verification results. */
		KSI_PolicyVerificationResult_free(verificationResult);
		verificationResult = NULL;

		res = KSI_Signature_getDocumentHash(sig, &hash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get root hash from KSI signature.", blocks->blockNo);

		res = KSI_DataHash_getHashAlg(hash, &algo);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get algorithm ID from root hash.", blocks->blockNo);

		if (blocks->hasher == NULL || blocks->hashAlgo != algo) {
			res = KSI_DataHasher_open(ksi, algo, &hasher);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: could not open datahasher.", blocks->blockNo);
		}

		blocks->hashAlgo = algo;
		if (hasher) {
			KSI_DataHasher_free(blocks->hasher);
			blocks->hasher = hasher;
			hasher = NULL;
		}

		KSI_DataHash_free(blocks->rootHash);
		blocks->rootHash = KSI_DataHash_ref(hash);
	}

	blocks->lastBlockWasSkipped = 0;
	res = KT_OK;

	{
		KSI_Integer *t1 = NULL;
		char sigTimeStr[256] = "<null>";
		res = KSI_Signature_getSigningTime(sig, &t1);
		ERR_CATCH_MSG(err, res, NULL);

		blocks->sigTime_1 = KSI_Integer_getUInt64(t1);

		print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: signing time: (%llu) %s\n", blocks->blockNo, blocks->sigTime_1, LOGKSI_signature_sigTimeToString(sig, sigTimeStr, sizeof(sigTimeStr)));
	}

	/* Verify KSI signatures Client ID. */
	res = check_log_signature_client_id(set, mp, err, blocks, sig);
	if (res != KT_OK) goto cleanup;

	cleanup:

	KSI_Signature_free(sig);
	KSI_PolicyVerificationResult_free(verificationResult);
	KSI_TlvElement_free(tlvSig);
	KSI_DataHasher_free(hasher);
	return res;
}

static int process_hash_step(ERR_TRCKR *err, KSI_CTX *ksi, KSI_TlvElement *tlv, BLOCK_INFO *blocks, KSI_DataHash *inputHash, KSI_DataHash **outputHash) {
	int res;
	size_t correction = 0;
	KSI_DataHash *siblingHash = NULL;
	KSI_DataHash *tmp = NULL;

	if (tlv == NULL || blocks == NULL || inputHash == NULL || outputHash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = tlv_element_get_uint(tlv, ksi, 0x01, &correction);
	if (res == KT_INVALID_INPUT_FORMAT) {
		correction = 0;
		res = KT_OK;
	}
	if (res != KT_OK) goto cleanup;
	res = tlv_element_get_hash(err, tlv, ksi, 0x02, &siblingHash);
	if (res != KT_OK) goto cleanup;

	blocks->treeHeight += correction + 1;
	if (tlv->ftlv.tag == 0x02) {
		res = block_info_calculate_new_tree_hash(blocks, inputHash, siblingHash, blocks->treeHeight, &tmp);
	} else if (tlv->ftlv.tag == 0x03){
		res = block_info_calculate_new_tree_hash(blocks, siblingHash, inputHash, blocks->treeHeight, &tmp);
	} else {
		res = KT_INVALID_INPUT_FORMAT;
	}
	if (res != KT_OK) goto cleanup;

	*outputHash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(siblingHash);
	KSI_DataHash_free(tmp);
	return res;
}

static int process_record_chain(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	KSI_DataHash *recordHash = NULL;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvMetaRecord = NULL;
	KSI_DataHash *tmpHash = NULL;
	KSI_DataHash *root = NULL;
	KSI_DataHash *replacement = NULL;

	if (err == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	blocks->nofRecordHashes++;

	res = tlv_element_parse_and_check_sub_elements(err, ksi, blocks->ftlv_raw, blocks->ftlv_len, blocks->ftlv.hdr_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse record chain as TLV element.", blocks->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x911, &tlvMetaRecord);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract metarecord in record chain.", blocks->blockNo);

	KSI_DataHash_free(blocks->metarecordHash);
	blocks->metarecordHash = NULL;
	if (tlvMetaRecord != NULL) {
		res = block_info_calculate_hash_of_metarecord_and_store_metarecord(blocks, tlvMetaRecord, &hash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate metarecord hash.", blocks->blockNo);

		blocks->metarecordHash = KSI_DataHash_ref(hash);
	}

	res = tlv_element_get_hash(err, tlv, ksi, 0x01, &recordHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse hash of logline no. %zu.", blocks->blockNo, get_nof_lines(blocks));

	if (blocks->metarecordHash != NULL) {
		char description[1024];
		PST_snprintf(description, sizeof(description), "Metarecord hash mismatch in block %zu", blocks->blockNo);

		/* This is a metarecord hash. */
		res = logksi_datahash_compare(err, mp, blocks, 0, blocks->metarecordHash, recordHash, description, "Metarecord hash computed from metarecord:", "Metarecord hash stored in integrity proof file:");
		res = continue_on_hash_fail(res, set, mp, blocks, blocks->metarecordHash, recordHash, &replacement);
		if (!blocks->isContinuedOnFail) {
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: metarecord hashes not equal.", blocks->blockNo);
		}

		if (res != KT_OK) goto cleanup;
	} else {
		/* This is a logline record hash. */

		if (files->files.inLog) {
			res = block_info_calculate_hash_of_logline_and_store_logline_check_log_time(set, err, mp, blocks, files, &hash);
			if (res == KT_IO_ERROR) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: record hash no. %zu does not have a matching logline, end of logfile reached.", blocks->blockNo, get_nof_lines(blocks));
			} else if (res != KT_OK) goto cleanup;

			res = logksi_datahash_compare(err, mp, blocks, 1, hash, recordHash, NULL, "Record hash computed from logline:", "Record hash stored in integrity proof file:");
			res = continue_on_hash_fail(res, set, mp, blocks, hash, recordHash, &replacement);
			if (!blocks->isContinuedOnFail) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: record hashes not equal.", blocks->blockNo);
			}

			if (res != KT_OK) goto cleanup;
		} else {
			replacement = KSI_DataHash_ref(recordHash);
		}
	}

	if (tlv->subList) {
		int i;
		char description[1024];

		blocks->treeHeight = 0;
		root = KSI_DataHash_ref(replacement);

		for (i = 0; i < KSI_TlvElementList_length(tlv->subList); i++) {
			KSI_TlvElement *tmpTlv = NULL;

			res = KSI_TlvElementList_elementAt(tlv->subList, i, &tmpTlv);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get element %d from TLV.", blocks->blockNo, i);
			if (tmpTlv && (tmpTlv->ftlv.tag == 0x02 || tmpTlv->ftlv.tag == 0x03)) {
				res = process_hash_step(err, ksi, tmpTlv, blocks, root, &tmpHash);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to process hash step.", blocks->blockNo);

				KSI_DataHash_free(root);
				root = tmpHash;
				tmpHash = NULL;
			}
		}

		PST_snprintf(description, sizeof(description), "Root hash mismatch in block %zu", blocks->blockNo);

		res = logksi_datahash_compare(err, mp, blocks, 0, root, blocks->rootHash, description, "Root hash computed from hash chain:", "Root hash stored in KSI signature:");
		KSI_DataHash_free(replacement);
		replacement = NULL;
		res = continue_on_hash_fail(res, set, mp, blocks, root, blocks->rootHash, &replacement);
		if (!blocks->isContinuedOnFail) {
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: root hashes not equal.", blocks->blockNo);
		}

		if (res != KT_OK) goto cleanup;
	} else {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get sub TLVs from record chain.", blocks->blockNo);
	}
	res = KT_OK;

cleanup:

	KSI_DataHash_free(recordHash);
	KSI_DataHash_free(hash);
	KSI_DataHash_free(root);
	KSI_DataHash_free(tmpHash);
	KSI_DataHash_free(replacement);
	KSI_TlvElement_free(tlv);
	KSI_TlvElement_free(tlvMetaRecord);
	return res;
}

static int process_partial_block(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files, MULTI_PRINTER* mp) {
	int res;
	KSI_DataHash *hash = NULL;
	KSI_DataHash *rootHash = NULL;
	KSI_DataHash *replacement = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvNoSig = NULL;

	if (err == NULL || ksi == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: processing partial block data... ", blocks->blockNo);

	blocks->partNo++;
	if (blocks->partNo > blocks->blockNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: partial block data without preceding block header found.", blocks->sigNo);
	}

	res = tlv_element_parse_and_check_sub_elements(err, ksi, blocks->ftlv_raw, blocks->ftlv_len, blocks->ftlv.hdr_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse block signature as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &blocks->recordCount);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record count in blocks file.", blocks->blockNo);

	res = is_block_signature_expected(err, blocks);
	if (res != KT_OK) goto cleanup;

	res = KSI_TlvElement_getElement(tlv, 0x02, &tlvNoSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract 'no-sig' element in blocks file.", blocks->blockNo);

	res = tlv_element_get_hash(err, tlvNoSig, ksi, 0x01, &hash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse root hash.", blocks->blockNo);

	if (blocks->nofRecordHashes && blocks->nofRecordHashes != blocks->recordCount) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: expected %zu records in blocks file, but found %zu records.", blocks->blockNo, blocks->recordCount, blocks->nofRecordHashes);
	}

	/* If the blocks file contains hashes, re-compute and compare the root hash against the provided root hash. */
	if (blocks->nofRecordHashes) {
		char description[1024];
		PST_snprintf(description, sizeof(description), "Root hash mismatch in block %zu", blocks->blockNo);

		res = block_info_calculate_root_hash(blocks, ksi, &rootHash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate root hash.", blocks->blockNo);

		res = logksi_datahash_compare(err, mp, blocks, 0, rootHash, hash, description, "Root hash computed from record hashes:", "Unsigned root hash stored in block data file:");
		res = continue_on_hash_fail(res, set, mp, blocks, rootHash, hash, &replacement);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: root hashes not equal.", blocks->blockNo);
	} else {
		replacement = KSI_DataHash_ref(hash);
	}

	blocks->rootHash = replacement;

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
	KSI_DataHash_free(rootHash);
	KSI_DataHash_free(hash);
	KSI_TlvElement_free(tlv);
	KSI_TlvElement_free(tlvNoSig);
	return res;
}

static int process_partial_signature(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, SIGNATURE_PROCESSORS *processors, BLOCK_INFO *blocks, IO_FILES *files, int progress) {
	int res;
	KSI_Signature *sig = NULL;
	KSI_DataHash *hash = NULL;
	KSI_DataHash *rootHash = NULL;
	KSI_DataHash *missing = NULL;
	KSI_DataHash *replacement = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvSig = NULL;
	KSI_TlvElement *tlvNoSig = NULL;
	KSI_TlvElement *tlvRfc3161 = NULL;
	int insertHashes = 0;
	char description[1024];
	int sign_err = 0;

	if (err == NULL || ksi == NULL || processors == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (MULTI_PRINTER_hasDataByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES)) {
		print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "}\n");
		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES);
	}

	PST_snprintf(description, sizeof(description), "Root hash mismatch in block %zu", blocks->blockNo);
	print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: processing partial signature data... ", blocks->blockNo);

	blocks->sigNo++;
	if (blocks->sigNo > blocks->blockNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: block signature data without preceding block header found.", blocks->sigNo);
	}

	blocks->signatureTLVReached = 1;

	res = tlv_element_parse_and_check_sub_elements(err, ksi, blocks->ftlv_raw, blocks->ftlv_len, blocks->ftlv.hdr_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse block signature as TLV element.", blocks->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &blocks->recordCount);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record count in signatures file.", blocks->blockNo);

	res = is_block_signature_expected(err, blocks);
	if (res != KT_OK) goto cleanup;

	/* If no record hashes were computed or encountered, previous leaf hashes must not be compared. */
	if (blocks->nofRecordHashes == 0) {
		KSI_DataHash_free(blocks->prevLeaf);
		blocks->prevLeaf = NULL;
	}

	if (blocks->nofRecordHashes && blocks->nofRecordHashes != blocks->recordCount) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: expected %zu records in signatures file, but found %zu records in blocks file.", blocks->blockNo, blocks->recordCount, blocks->nofRecordHashes);
	}

	insertHashes = PARAM_SET_isSetByName(set, "insert-missing-hashes");
	if (blocks->finalTreeHashesNone && insertHashes) {
		if (blocks->keepRecordHashes || (!blocks->keepRecordHashes && blocks->finalTreeHashesSome)) {
			do {
				missing = NULL;
				res = block_info_merge_one_level(blocks, ksi, &missing);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing tree hash could not be computed.", blocks->blockNo);
				if (missing) {
					res = tlv_element_write_hash(missing, 0x903, files->files.outSig);
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing tree hash could not be written.", blocks->blockNo);
					KSI_DataHash_free(missing);
					blocks->outSigModified = 1;
				}
			} while (missing);
			blocks->finalTreeHashesNone = 0;
			blocks->finalTreeHashesAll = 1;
		}
	}

	res = KSI_TlvElement_getElement(tlv, 0x906, &tlvRfc3161);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract RFC3161 element in block signature.", blocks->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x905, &tlvSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract KSI signature element in signatures file.", blocks->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x02, &tlvNoSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract 'no-sig' element in signatures file.", blocks->blockNo);

	if (tlvSig != NULL || tlvRfc3161 != NULL) {
		KSI_DataHash *docHash = NULL;

		if (tlvSig != NULL) {
			res = LOGKSI_Signature_parseWithPolicy(err, ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_EMPTY, NULL, &sig);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature in signatures file.", blocks->blockNo);
		} else {
			/* Convert the RFC3161 timestamp into KSI signature. */
			res = convert_signature(ksi, tlvRfc3161->ptr + tlvRfc3161->ftlv.hdr_len, tlvRfc3161->ftlv.dat_len, &sig);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to convert RFC3161 element in block signature.", blocks->blockNo);
			blocks->warningLegacy = 1;
		}

		res = KSI_Signature_getDocumentHash(sig, &docHash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get root hash from KSI signature.", blocks->blockNo);

		/* Compare signed root hash with unsigned root hash. */
		if (blocks->rootHash) {
			res = logksi_datahash_compare(err, mp, blocks, 0, blocks->rootHash, docHash, description, "Unsigned root hash stored in block data file:", "Signed root hash stored in KSI signature:");
			res = continue_on_hash_fail(res, set, mp, blocks, blocks->rootHash, docHash, &replacement);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: root hashes not equal.", blocks->blockNo);
		} else if (blocks->nofRecordHashes) {
			/* Compute the root hash and compare with signed root hash. */
			res = block_info_calculate_root_hash(blocks, ksi, &rootHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate root hash.", blocks->blockNo);

			res = logksi_datahash_compare(err, mp, blocks, 0, rootHash, docHash, description, "Root hash computed from record hashes:", "Signed root hash stored in KSI signature:");
			res = continue_on_hash_fail(res, set, mp, blocks, rootHash, docHash, &replacement);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: root hashes not equal.", blocks->blockNo);
		}
	} else if (tlvNoSig != NULL) {
		blocks->noSigNo++;
		res = tlv_element_get_hash(err, tlvNoSig, ksi, 0x01, &hash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse root hash.", blocks->blockNo);

		/* Compare unsigned root hashes. */
		if (blocks->rootHash) {
			res = logksi_datahash_compare(err, mp, blocks, 0, blocks->rootHash, hash, description, "Unsigned root hash stored in block data file:", "Unsigned root hash stored in block signature file:");
			res = continue_on_hash_fail(res, set, mp, blocks, blocks->rootHash, hash, &replacement);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: root hashes not equal.", blocks->blockNo);
		} else if (blocks->nofRecordHashes) {
			/* Compute the root hash and compare with unsigned root hash. */
			res = block_info_calculate_root_hash(blocks, ksi, &rootHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate root hash.", blocks->blockNo);

			res = logksi_datahash_compare(err, mp, blocks, 0, rootHash, hash, description, "Root hash computed from record hashes:", "Unsigned root hash stored in block signature file:");
			res = continue_on_hash_fail(res, set, mp, blocks, rootHash, hash, &replacement);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: root hashes not equal.", blocks->blockNo);
		}

		if (processors->create_signature) {
			print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);

			if (progress) {
				print_debug("Progress: signing block %3zu of %3zu unsigned blocks. Estimated time remaining: %3zu seconds.\n", blocks->noSigNo, blocks->noSigCount, blocks->noSigCount - blocks->noSigNo + 1);
			}
			print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_LEVEL_3, "Block no. %3zu: creating missing KSI signature... ", blocks->blockNo);

			res = processors->create_signature(set, mp, err, ksi, blocks, files, hash, block_info_get_aggregation_level(blocks), &sig);
			if (res != KT_OK && blocks->isContinuedOnFail) {
				sign_err = KT_SIGNING_FAILURE;
				print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

				print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Failed to sign unsigned block %zu:\n"
																					  "   + %s (0x%02x)\n"
																					  "   + Signing is continued and unsigned block will be kept.\n", blocks->blockNo, LOGKSI_errToString(res), res);
				print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_2, "\n");

				print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Signing is continued and unsigned block will be kept.\n", blocks->blockNo);

				res = KSI_TlvElement_serialize(tlv, blocks->ftlv_raw, SOF_FTLV_BUFFER, &blocks->ftlv_len, 0);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize unsigned block.", blocks->blockNo);
			} else {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to sign root hash.", blocks->blockNo);

				blocks->curBlockJustReSigned = 1;
				blocks->outSigModified = 1;
				blocks->noSigCreated++;

				res = KSI_TlvElement_new(&tlvSig);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize KSI signature.", blocks->blockNo);
				tlvSig->ftlv.tag = 0x904;

				res = tlv_element_set_uint(tlvSig, ksi, 0x01, blocks->recordCount);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize KSI signature.", blocks->blockNo);

				res = tlv_element_set_signature(tlvSig, ksi, 0x905, sig);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize KSI signature.", blocks->blockNo);

				res = KSI_TlvElement_serialize(tlvSig, blocks->ftlv_raw, SOF_FTLV_BUFFER, &blocks->ftlv_len, 0);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize KSI signature.", blocks->blockNo);
			}
		} else {
			/* Missing signatures found during integration. */
			blocks->warningSignatures = 1;
			blocks->unsignedRootHash = 1;
		}
	} else {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: block signature missing in signatures file.", blocks->blockNo);
	}

	if (sig != NULL){
		KSI_Integer *t1 = NULL;
		char sigTimeStr[256];

		res = KSI_Signature_getSigningTime(sig, &t1);
		ERR_CATCH_MSG(err, res, NULL);

		blocks->sigTime_1 = KSI_Integer_getUInt64(t1);
		print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, res);
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: signing time: (%llu) %s\n", blocks->blockNo, blocks->sigTime_1, LOGKSI_signature_sigTimeToString(sig, sigTimeStr, sizeof(sigTimeStr)));
	} else {
		blocks->curBlockNotSigned = 1;
	}

	if (files->files.outSig) {
		print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
		print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: writing block signature to file... ", blocks->blockNo);

		res = SMART_FILE_write(files->files.outSig, blocks->ftlv_raw, blocks->ftlv_len, NULL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to write signature data log signature file.", blocks->blockNo);

		/* Move signature file offset value at the end of the files as complete signature is written to the file. */
		res = SMART_FILE_markConsistent(files->files.outSig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Unable to mark output log signature file consistent.", blocks->blockNo);
	}
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
	blocks->nofTotalRecordHashes += blocks->nofRecordHashes;

	if (blocks->firstLineInBlock < blocks->nofTotalRecordHashes) {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: lines processed %zu - %zu (%zu)\n", blocks->blockNo, blocks->firstLineInBlock, blocks->nofTotalRecordHashes, blocks->recordCount - blocks->nofMetaRecords);
	} else if (blocks->recordCount == 1 && blocks->nofMetaRecords == 1) {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: line processed n/a\n", blocks->blockNo);
	} else if (blocks->firstLineInBlock == blocks->nofTotalRecordHashes) {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: line processed %zu\n", blocks->blockNo,  blocks->firstLineInBlock);
	} else {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: line processed <unknown>\n", blocks->blockNo);
	}

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);

	KSI_Signature_free(sig);
	KSI_DataHash_free(hash);
	KSI_DataHash_free(rootHash);
	KSI_DataHash_free(missing);
	KSI_DataHash_free(replacement);
	KSI_TlvElement_free(tlvSig);
	KSI_TlvElement_free(tlvNoSig);
	KSI_TlvElement_free(tlvRfc3161);
	KSI_TlvElement_free(tlv);

	return (sign_err == 0) ? res : sign_err;
}

static int check_warnings(BLOCK_INFO *blocks) {
	if (blocks) {
		if (blocks->warningSignatures || blocks->warningTreeHashes || blocks->warningLegacy) {
			return 1;
		}
	}
	return 0;
}

static int finalize_log_signature(PARAM_SET* set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, KSI_DataHash* inputHash, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	unsigned char buf[2];
	char inHash[256] = "<null>";
	char outHash[256] = "<null>";
	int shortIndentation = 13;
	int longIndentation = 29;



	if (err == NULL || blocks == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}



	if (blocks->blockNo == 0) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: No blocks found.");
	}

	/* Finlize last block. */
	res = finalize_block(set, mp, err, ksi, blocks, files);
	ERR_CATCH_MSG(err, res, "Error: Unable to finalize last block.");

	print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Finalizing log signature... ");

	/* Log file must not contain more records than log signature file. */
	if (files->files.inLog) {
		size_t count = 0;
		SMART_FILE_read(files->files.inLog, buf, 1, &count);
		if (count > 0) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: end of log file contains unexpected records.", blocks->blockNo);
		}
	}

	/* Signatures file must not contain more blocks than blocks file. */
	if (files->files.partsSig) {
		size_t count = 0;
		SMART_FILE_read(files->files.partsSig, buf, 1, &count);
		if (count > 0) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: end of signatures file contains unexpected data.", blocks->blockNo);
		}
	}

	if (blocks->nofTotaHashFails && !PARAM_SET_isSetByName(set, "multiple_logs")) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: %zu hash comparison failures found.", blocks->nofTotaHashFails);
	}

	if (blocks->nofExtractPositionsFound < blocks->nofExtractPositions) {
		res = KT_INVALID_CMD_PARAM;
		ERR_CATCH_MSG(err, res, "Error: Extract position %zu out of range - not enough loglines.", blocks->extractPositions[blocks->nofExtractPositionsFound]);
	}

	/* Mark output signature file consistent. */
	if (files->files.outSig != NULL) {
		res = SMART_FILE_markConsistent(files->files.outSig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Unable to mark output log signature file consistent.", blocks->blockNo);
	}

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

	print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, "\nSummary of logfile:\n");

	print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of blocks:", blocks->blockNo);
	if (blocks->nofTotalFailedBlocks > 0) print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of failures:", blocks->nofTotalFailedBlocks);
	print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of record hashes:", blocks->nofTotalRecordHashes); /* Meta records not included. */

	if (blocks->noSigNo > 0) {
		if (blocks->taskId == TASK_SIGN) {
			print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of resigned blocks:", blocks->noSigCreated);
			if (blocks->noSigCreated < blocks->noSigNo) {
				print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of unsigned blocks:", blocks->noSigNo - blocks->noSigCreated);
			}
		} else {
			print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of unsigned blocks:", blocks->noSigNo);
		}
	}

	if (blocks->nofTotalMetarecors > 0) print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of meta-records:", blocks->nofTotalMetarecors); /* Meta records not included. */
	if (blocks->nofTotaHashFails > 0) print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of hash failures:", blocks->nofTotaHashFails);
	if (blocks->nofExtractPositions > 0) print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Records extracted:", blocks->nofExtractPositions);

	if (blocks->rec_time_in_file_min > 0 && blocks->rec_time_in_file_max) {
		char str_rec_time_min[1024] = "<null>";
		char str_rec_time_max[1024] = "<null>";
		char time_diff[1024] = "<null>";
		const char *sign = "";
		int calc_sign = 0;

		time_diff_to_string(uint64_diff(blocks->rec_time_in_file_max, blocks->rec_time_in_file_min, &calc_sign), time_diff, sizeof(time_diff));
		if (calc_sign < 0) sign = "-";

		LOGKSI_uint64_toDateString(blocks->rec_time_in_file_min, str_rec_time_min, sizeof(str_rec_time_min));
		LOGKSI_uint64_toDateString(blocks->rec_time_in_file_max, str_rec_time_max, sizeof(str_rec_time_max));

		print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%s\n", longIndentation, "First record time:", str_rec_time_min);
		print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%s\n", longIndentation, "Last record time:", str_rec_time_max);
		print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%s%s\n", longIndentation, "Log file duration:", sign, time_diff);
	}

	LOGKSI_DataHash_toString(inputHash, inHash, sizeof(inHash));
	LOGKSI_DataHash_toString(blocks->prevLeaf, outHash, sizeof(outHash));

	if (blocks->version != RECSIG11 && blocks->version != RECSIG12 && (blocks->taskId == TASK_VERIFY || blocks->taskId == TASK_INTEGRATE)) {
		print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%s\n", shortIndentation, "Input hash:", inHash);
		print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%s\n", shortIndentation, "Output hash:", outHash);
	}


	if (check_warnings(blocks)) {
		if (blocks && blocks->warningSignatures) {
			print_debug_mp(mp, MP_ID_LOGFILE_WARNINGS, DEBUG_LEVEL_0, "Warning: Unsigned root hashes found.\n         Run 'logksi sign' to perform signing recovery.\n");
		}

		if (blocks && blocks->warningTreeHashes) {
			print_debug_mp(mp, MP_ID_LOGFILE_WARNINGS, DEBUG_LEVEL_0, "Warning: Some tree hashes are missing from the log signature file.\n         Run 'logksi sign' with '--insert-missing-hashes' to repair the log signature.\n");
		}

		if (blocks && blocks->warningLegacy) {
			print_debug_mp(mp, MP_ID_LOGFILE_WARNINGS, DEBUG_LEVEL_0, "Warning: RFC3161 timestamp(s) found in log signature.\n         Run 'logksi extend' with '--enable-rfc3161-conversion' to convert RFC3161 timestamps to KSI signatures.\n");
		}
	}

	MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);
	MULTI_PRINTER_printByID(mp, MP_ID_LOGFILE_SUMMARY);

	return res;
}

static int count_blocks(ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, SMART_FILE *in) {
	int res;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvNoSig = NULL;

	if (err == NULL || in == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Do not count records, if input comes from stdin. */
	if (SMART_FILE_isStream(in)) {
		res = KT_OK;
		goto cleanup;
	}

	blocks->blockCount = 0;
	blocks->noSigCount = 0;
	blocks->noSigNo = 0;

	while (!SMART_FILE_isEof(in)) {
		res = LOGKSI_FTLV_smartFileRead(in, blocks->ftlv_raw, SOF_FTLV_BUFFER, &blocks->ftlv_len, &blocks->ftlv);
		if (res == KSI_OK) {
			switch (blocks->ftlv.tag) {
				case 0x901:
					blocks->blockCount++;
				break;

				case 0x904:
					res = tlv_element_parse_and_check_sub_elements(err, ksi, blocks->ftlv_raw, blocks->ftlv_len, blocks->ftlv.hdr_len, &tlv);
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse block signature as TLV element.", blocks->blockNo);
					res = KSI_TlvElement_getElement(tlv, 0x02, &tlvNoSig);
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract 'no-sig' element in signatures file.", blocks->blockNo);

					if (tlvNoSig) blocks->noSigCount++;

					KSI_TlvElement_free(tlvNoSig);
					tlvNoSig = NULL;
					KSI_TlvElement_free(tlv);
					tlv = NULL;
				break;

				default:
				/* Ignore hashes and other TLVs as we are just counting blocks. */
				break;
			}
		} else {
			if (blocks->ftlv_len > 0) {
				res = KT_INVALID_INPUT_FORMAT;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete data found in log signature file.", blocks->blockNo);
			} else {
				break;
			}
		}
	}

	res = KT_OK;

cleanup:

	if (in != NULL) SMART_FILE_rewind(in);

	KSI_TlvElement_free(tlvNoSig);
	KSI_TlvElement_free(tlv);

	return res;
}

static int process_log_signature_general_components_(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, KSI_PublicationsFile *pubFile, int withBlockSignature, BLOCK_INFO *blocks, IO_FILES *files, SIGNATURE_PROCESSORS *processors) {
	int res = KT_UNKNOWN_ERROR;
	int printHeader = 0;
	int isFinal = 0;

	if (set == NULL || err == NULL || ksi == NULL || blocks == NULL || files == NULL || (withBlockSignature && processors == NULL)) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	printHeader = MULTI_PRINTER_hasDataByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES);

	switch (blocks->ftlv.tag) {
		case 0x901:
			res = finalize_block(set, mp, err, ksi, blocks, files);
			if (res != KT_OK) goto cleanup;

			res = init_next_block(blocks);
			if (res != KT_OK) goto cleanup;

			res = process_block_header(set, mp, err, ksi, blocks, files);
			if (res != KT_OK) goto cleanup;
		break;

		case 0x902:
			if (printHeader == 0) print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "Block no. %3zu: {", blocks->blockNo);
			print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "r" );

			res = process_record_hash(set, mp,err, ksi, blocks, files);
			if (res != KT_OK) goto cleanup;
		break;

		case 0x903:
			if (printHeader == 0) print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "Block no. %3zu: {", blocks->blockNo);


			res = process_tree_hash(set, mp, err, ksi, blocks, files, &isFinal);

			if (isFinal) {
				print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, ":");
			} else {
				print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, ".");
			}

			if (res != KT_OK) goto cleanup;
		break;

		case 0x911:
			if (printHeader == 0) print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "Block no. %3zu: {", blocks->blockNo);
			print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "M");

			res = process_metarecord(set, mp, err, ksi, blocks, files);
			if (res != KT_OK) goto cleanup;
		break;

		default:
			if (withBlockSignature && blocks->ftlv.tag) {
				res = process_block_signature(set, mp, err, ksi, pubFile, processors, blocks, files);
				if (res != KT_OK) goto cleanup;
			} else {
				res = KT_INVALID_INPUT_FORMAT;
				goto cleanup;
			}
		break;
	}

	res = KT_OK;

cleanup:

	if (res != KT_OK) {
		if (MULTI_PRINTER_hasDataByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES)) {
			print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, " X\n");
			MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);
			MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES);
		}
	}

	return res;
}

static int process_log_signature(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	return process_log_signature_general_components_(set, mp, err, ksi, NULL, 0, blocks, files, NULL);
}

static int process_log_signature_with_block_signature(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, KSI_PublicationsFile *pubFile, BLOCK_INFO *blocks, IO_FILES *files, SIGNATURE_PROCESSORS *processors) {
	return process_log_signature_general_components_(set, mp, err, ksi, pubFile, 1, blocks, files, processors);
}

int logsignature_extend(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, KSI_PublicationsFile* pubFile, EXTENDING_FUNCTION extend_signature, IO_FILES *files) {
	int res;
	BLOCK_INFO blocks;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;
	KSI_DataHash *theFirstInputHashInFile = NULL;

	if (set == NULL || err == NULL || ksi == NULL || extend_signature == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	BLOCK_INFO_clearAll(&blocks);
	blocks.ftlv_raw = ftlv_raw;
	blocks.taskId = TASK_EXTEND;
	memset(&processors, 0, sizeof(processors));
	processors.extend_signature = extend_signature;

	blocks.isContinuedOnFail = PARAM_SET_isSetByName(set, "continue-on-fail");

	res = process_magic_number(set, mp, err, &blocks, files);
	if (res != KT_OK) goto cleanup;

	if (blocks.version == RECSIG11 || blocks.version == RECSIG12) {
		res = KT_VERIFICATION_SKIPPED;
		ERR_TRCKR_ADD(err, res, "Extending of excerpt file not yet implemented!");
		goto cleanup;
	}

	while (!SMART_FILE_isEof(files->files.inSig)) {
		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);

		res = LOGKSI_FTLV_smartFileRead(files->files.inSig, blocks.ftlv_raw, SOF_FTLV_BUFFER, &blocks.ftlv_len, &blocks.ftlv);
		if (res == KSI_OK) {
			switch (blocks.ftlv.tag) {
				case 0x901:
					if (theFirstInputHashInFile == NULL) theFirstInputHashInFile = KSI_DataHash_ref(blocks.inputHash);
				case 0x902:
				case 0x903:
				case 0x911:
				case 0x904:
					res = process_log_signature_with_block_signature(set, mp, err, ksi, pubFile, &blocks, files, &processors);
					if (res != KT_OK) goto cleanup;
				break;

				default:
					/* TODO: unknown TLV found. Either
					 * 1) Warn user and skip TLV
					 * 2) Copy TLV (maybe warn user)
					 * 3) Abort extending with an error
					 */
				break;
			}
		} else {
			if (blocks.ftlv_len > 0) {
				res = KT_INVALID_INPUT_FORMAT;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete data found in log signature file.", blocks.blockNo);
			} else {
				break;
			}
		}
	}

	res = finalize_log_signature(set, mp, err, ksi, theFirstInputHashInFile, &blocks, files);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	BLOCK_INFO_freeAndClearInternals(&blocks);
	KSI_DataHash_free(theFirstInputHashInFile);

	return res;
}

static const char *io_files_getCurrentLogFilePrintRepresentation(IO_FILES *files) {
	int logStdin = 0;

	if (files == NULL) return NULL;

	logStdin = files->internal.inLog == NULL;
	return logStdin ? "stdin" : files->internal.inLog;
}

static int skip_current_block_as_it_does_not_verify(BLOCK_INFO *blocks, MULTI_PRINTER* mp, IO_FILES *files, ERR_TRCKR *err, KSI_CTX *ksi, int *skip) {
	int res = KT_UNKNOWN_ERROR;
	KSI_TlvElement *tlv = NULL;
	size_t i = 0;
	char buf[1024];
	size_t logLinesToSkip = 0;


	if (blocks == NULL || ksi == NULL ||  skip == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* If skipping is not enabled, just exit. */
	if ((*skip) == 0) {
		res = KT_OK;
		goto cleanup;
	}

	switch (blocks->ftlv.tag) {
		case 0x901:
			*skip = 0;

			/* Normally this is incremented in process_block_signature or process_partial_signature.
			   If this has not happened it must be incremented here. */
			if (blocks->firstLineInBlock - 1 == blocks->nofTotalRecordHashes) {
				blocks->nofTotalRecordHashes += blocks->recordCount;
			}

			logLinesToSkip = blocks->recordCount - (blocks->nofRecordHashes - blocks->nofMetaRecords);

			if (logLinesToSkip > 0) {
				print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: Skipping %zu log lines.\n", blocks->blockNo, logLinesToSkip);

				for (i = 0; i < logLinesToSkip; i++) {
					res = SMART_FILE_gets(files->files.inLog, buf, sizeof(buf), NULL);
					if (res != SMART_FILE_OK) goto cleanup;
				}
			}
		break;

		case 0x904:
			res = tlv_element_parse_and_check_sub_elements(err, ksi, blocks->ftlv_raw, blocks->ftlv_len, blocks->ftlv.hdr_len, &tlv);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse block signature as TLV element.", blocks->blockNo);

			res = tlv_element_get_uint(tlv, ksi, 0x01, &blocks->recordCount);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record count in block signature.", blocks->blockNo);
			blocks->sigNo++;
		break;
	}

	res = KT_OK;

cleanup:

	KSI_TlvElement_free(tlv);

	return res;
}

int logsignature_verify(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash *firstLink, VERIFYING_FUNCTION verify_signature, IO_FILES *files, KSI_DataHash **lastLeaf, uint64_t* last_rec_time) {
	int res;

	KSI_DataHash *theFirstInputHashInFile = NULL;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;
	int isFirst = 1;
	int skipCurrentBlock = 0;
	int printHeader = 0;
	REGEXP *tmp_regxp = NULL;

	if (set == NULL || err == NULL || ksi == NULL || blocks == NULL || verify_signature == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	blocks->ftlv_raw = ftlv_raw;
	blocks->taskId = TASK_VERIFY;
	memset(&processors, 0, sizeof(processors));
	processors.verify_signature = verify_signature;

	blocks->isContinuedOnFail = PARAM_SET_isSetByName(set, "continue-on-fail");

	res = process_magic_number(set, mp, err, blocks, files);
	if (res != KT_OK) goto cleanup;

	if (PARAM_SET_isSetByName(set, "client-id")) {
		char *pattern = NULL;
		PARAM_SET_getStr(set, "client-id", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &pattern);

		res = REGEXP_new(pattern, &tmp_regxp);
		ERR_CATCH_MSG(err, res, "Error: Unable to parse regular expression for matching the client ID.");

		blocks->client_id_match = tmp_regxp;
		tmp_regxp = NULL;
	}


	while (!SMART_FILE_isEof(files->files.inSig)) {
		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);

		res = LOGKSI_FTLV_smartFileRead(files->files.inSig, blocks->ftlv_raw, SOF_FTLV_BUFFER, &blocks->ftlv_len, &blocks->ftlv);
		if (res == KSI_OK) {
			skip_current_block_as_it_does_not_verify(blocks, mp, files, err, ksi, &skipCurrentBlock);
			if (skipCurrentBlock) continue;

			switch (blocks->version) {
				case LOGSIG11:
				case LOGSIG12:
					switch (blocks->ftlv.tag) {
						case 0x904:
						case 0x901:
						case 0x902:
						case 0x903:
						case 0x911:
							res = process_log_signature_with_block_signature(set, mp, err, ksi, NULL, blocks, files, &processors);
							if (res != KT_OK) {
								/* In case of verification failure and --continue-on-fail option, verification is continued. */
								if ((res == KT_VERIFICATION_FAILURE || res == KSI_VERIFICATION_FAILURE) && blocks->isContinuedOnFail) {
									print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);
									print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_2, res);
									print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);

									blocks->quietError = KT_VERIFICATION_FAILURE;

									skipCurrentBlock = 1;
									blocks->lastBlockWasSkipped = 1;

									print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Skipping block %zu!\n", blocks->blockNo);
									print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Block is skipped!\n", blocks->blockNo);
									continue;
								}
								goto cleanup;
							}
						break;

						default:
							/* TODO: unknown TLV found. Either
							 * 1) Warn user and skip TLV
							 * 2) Copy TLV (maybe warn user)
							 * 3) Abort extending with an error
							 */
						break;
					}

					/* Addidional post processor for block header. */
					if (blocks->ftlv.tag == 0x901) {
						char buf[256];
						LOGKSI_DataHash_toString(blocks->prevLeaf, buf, sizeof(buf));
						print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_2, res);
						if (theFirstInputHashInFile == NULL) theFirstInputHashInFile = KSI_DataHash_ref(blocks->prevLeaf);

						print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: input hash: %s.\n", blocks->blockNo, buf);

						print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_EQUAL | DEBUG_LEVEL_2 , "Verifying block no. %3zu... ", blocks->blockNo);


						/* Check if the last leaf from the previous block matches with the current first block. */
						if (isFirst == 1 && firstLink != NULL) {
							print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: verifying inter-linking input hash... ", blocks->blockNo);
							isFirst = 0;
							if (!KSI_DataHash_equals(firstLink, blocks->prevLeaf)) {
								char buf_imp[1024];
								char buf_exp_imp[1024];
								char buf_fname[4096];
								char *prevBlockSource = "Unexpected and not initialized previous block source.";
								const char *firstBlockSource = io_files_getCurrentLogFilePrintRepresentation(files);

								res = KT_VERIFICATION_FAILURE;

								if (PARAM_SET_isSetByName(set, "input-hash") && files->previousLogFile[0] == '\0') {
									char *fname = NULL;
									PARAM_SET_getStr(set, "input-hash", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &fname);

									PST_snprintf(buf_fname, sizeof(buf_fname), "from --input-hash %s", fname);
									prevBlockSource = buf_fname;
								} else {
									prevBlockSource = files->previousLogFile;
								}

								ERR_TRCKR_ADD(err, res, "Error: Block no. %zu: The last leaf from the previous block (%s) does not match with the current first block (%s). Expecting '%s', but got '%s'.", blocks->blockNo, prevBlockSource, firstBlockSource, LOGKSI_DataHash_toString(firstLink, buf_exp_imp, sizeof(buf_exp_imp)), LOGKSI_DataHash_toString(blocks->prevLeaf, buf_imp, sizeof(buf_imp)));

								goto cleanup;
							}

							print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
						}

					}

				break;

				case RECSIG11:
				case RECSIG12:
					switch (blocks->ftlv.tag) {
						case 0x905:
						{
							char strT1[256];
							blocks->nofTotalRecordHashes += blocks->nofRecordHashes;
							if (MULTI_PRINTER_hasDataByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES)) {
								print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "}\n");
								MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES);
							}

							if ((blocks->rec_time_in_file_min == 0 || blocks->rec_time_in_file_min > blocks->rec_time_min) && blocks->rec_time_min > 0) blocks->rec_time_in_file_min = blocks->rec_time_min;
							if (blocks->rec_time_in_file_max == 0 || blocks->rec_time_in_file_max < blocks->rec_time_max) blocks->rec_time_in_file_max = blocks->rec_time_max;

							print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_2, res);
							if (MULTI_PRINTER_hasDataByID(mp, MP_ID_BLOCK_SUMMARY)) {
								print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%zu\n", SIZE_OF_LONG_INDENTATION, "Record count:", blocks->nofRecordHashes);
								if (blocks->rec_time_min > 0) {
									print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", SIZE_OF_LONG_INDENTATION, "First record time:", LOGKSI_uint64_toDateString(blocks->rec_time_min, strT1, sizeof(strT1)));
								}

								if (blocks->rec_time_max > 0) {
									print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", SIZE_OF_LONG_INDENTATION, "Last record time:", LOGKSI_uint64_toDateString(blocks->rec_time_max, strT1, sizeof(strT1)));
									print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", SIZE_OF_LONG_INDENTATION, "Block duration:", time_diff_to_string(blocks->rec_time_max - blocks->rec_time_min, strT1, sizeof(strT1)));
								}

								print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, "\n", SIZE_OF_LONG_INDENTATION, "Record count:", blocks->nofRecordHashes);


								MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);
								MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_ERRORS);
								MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_SUMMARY);
							}
							print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_EQUAL | DEBUG_LEVEL_2 , "Verifying block no. %3zu... ", blocks->blockNo + 1);
							res = process_ksi_signature(set, mp, err, ksi, &processors, blocks, files);
							if (res != KT_OK) goto cleanup;

							blocks->nofRecordHashes = 0;
							blocks->rec_time_min = 0;

							LOGKSI_uint64_toDateString(blocks->sigTime_1, strT1, sizeof(strT1));

							print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, "\nSummary of block %zu:\n", blocks->blockNo);
							print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", SIZE_OF_SHORT_INDENTENTION, "Sig time:", strT1);

							printHeader = 1;
						}
						break;

						case 0x907:
						{
						if (printHeader) {
							print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "Block no. %3zu: {", blocks->blockNo);
							printHeader = 0;
						}
							print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "r" );
							res = process_record_chain(set, mp, err, ksi, blocks, files);
							if (res != KT_OK) goto cleanup;

							res = check_log_record_embedded_time_against_ksi_signature_time(set, mp, err, blocks);
							if (res != KT_OK) goto cleanup;
						}
						break;

						default:
							/* TODO: unknown TLV found. Either
							 * 1) Warn user and skip TLV
							 * 2) Copy TLV (maybe warn user)
							 * 3) Abort extending with an error
							 */
						break;
					}
				break;

				default:
					/* TODO: unknown file header found. */
				break;
			}
		} else {
			if (blocks->ftlv_len > 0) {
				res = KT_INVALID_INPUT_FORMAT;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete data found in log signature file.", blocks->blockNo);
			} else {
				break;
			}
		}
	}

	if (blocks->version == RECSIG11 || blocks->version == RECSIG12) {
		char strT1[256];

		blocks->nofTotalRecordHashes += blocks->nofRecordHashes;

		print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%zu\n", SIZE_OF_LONG_INDENTATION, "Record count:", blocks->nofRecordHashes);

										if (blocks->rec_time_min > 0) {
									print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", SIZE_OF_LONG_INDENTATION, "First record time:", LOGKSI_uint64_toDateString(blocks->rec_time_min, strT1, sizeof(strT1)));
								}

								if (blocks->rec_time_max > 0) {
									print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", SIZE_OF_LONG_INDENTATION, "Last record time:", LOGKSI_uint64_toDateString(blocks->rec_time_max, strT1, sizeof(strT1)));
									print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", SIZE_OF_LONG_INDENTATION, "Block duration:", time_diff_to_string(blocks->rec_time_max - blocks->rec_time_min, strT1, sizeof(strT1)));
								}
										print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, "\n", SIZE_OF_LONG_INDENTATION, "Record count:", blocks->nofRecordHashes);

	}

	if (MULTI_PRINTER_hasDataByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES)) {
		print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "}\n");
		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES);
	}


	/* If requested, return last leaf of last block. */
	if (lastLeaf != NULL) {
		*lastLeaf = KSI_DataHash_ref(blocks->prevLeaf);
	}

	if (last_rec_time != NULL) {
		*last_rec_time = blocks->rec_time_max;
	}

	res = finalize_log_signature(set, mp, err, ksi, theFirstInputHashInFile, blocks, files);
	if (res != KT_OK) goto cleanup;

	if (blocks->errSignTime) {
		res = KT_VERIFICATION_FAILURE;
		ERR_TRCKR_ADD(err, res, "Error: Log block has signing time more recent than consecutive block!");
		goto cleanup;
	}

	res = KT_OK;

cleanup:

	if (blocks->quietError != KT_OK) {
		res = blocks->quietError;
		ERR_TRCKR_ADD(err, res, blocks->isContinuedOnFail ? "Error: Verification FAILED but was continued for further analysis." : "Error: Verification FAILED and was stopped.");
	}

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_2, res);

	if (MULTI_PRINTER_hasDataByID(mp, MP_ID_BLOCK_ERRORS)) {
		print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n");
	}

	MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);
	MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_ERRORS);

	REGEXP_free(tmp_regxp);
	KSI_DataHash_free(theFirstInputHashInFile);
	BLOCK_INFO_freeAndClearInternals(blocks);

	return res;
}

int logsignature_extract(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, IO_FILES *files) {
	int res;
	BLOCK_INFO blocks;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;
	KSI_DataHash *theFirstInputHashInFile = NULL;

	if (set == NULL || err == NULL || ksi == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	BLOCK_INFO_clearAll(&blocks);
	blocks.ftlv_raw = ftlv_raw;
	blocks.taskId = TASK_EXTRACT;
	memset(&processors, 0, sizeof(processors));
	processors.extract_signature = 1;

	res = PARAM_SET_getStr(set, "r", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &blocks.records);
	if (res != KT_OK) goto cleanup;

	blocks.isContinuedOnFail = PARAM_SET_isSetByName(set, "continue-on-fail");

	res = block_info_extract_verify_positions(err, blocks.records);
	if (res != KT_OK) goto cleanup;

	/* Initialize the first extract position. */
	res = block_info_extract_next_position(&blocks, err, blocks.records);
	if (res != KT_OK) goto cleanup;

	res = process_magic_number(set, mp, err, &blocks, files);
	if (res != KT_OK) goto cleanup;

	if (blocks.version == RECSIG11 || blocks.version == RECSIG12) {
		res = KT_VERIFICATION_SKIPPED;
		ERR_TRCKR_ADD(err, res, "Extracting from excerpt file not possible! Only log signature file can be extracted to produce excerpt file.");
		goto cleanup;
	}

	while (!SMART_FILE_isEof(files->files.inSig)) {
		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);

		res = LOGKSI_FTLV_smartFileRead(files->files.inSig, blocks.ftlv_raw, SOF_FTLV_BUFFER, &blocks.ftlv_len, &blocks.ftlv);
		if (res == KSI_OK) {
			switch (blocks.ftlv.tag) {
				case 0x901:
					if (theFirstInputHashInFile == NULL) theFirstInputHashInFile = KSI_DataHash_ref(blocks.inputHash);
				case 0x902:
				case 0x903:
				case 0x911:
				case 0x904:
					res = process_log_signature_with_block_signature(set, mp, err, ksi, NULL, &blocks, files, &processors);
					if (res != KT_OK) goto cleanup;
				break;

				default:
					/* TODO: unknown TLV found. Either
					 * 1) Warn user and skip TLV
					 * 2) Copy TLV (maybe warn user)
					 * 3) Abort extending with an error
					 */
				break;
			}
		} else {
			if (blocks.ftlv_len > 0) {
				res = KT_INVALID_INPUT_FORMAT;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete data found in log signature file.", blocks.blockNo);
			} else {
				break;
			}
		}
	}

	res = finalize_log_signature(set, mp, err, ksi, theFirstInputHashInFile, &blocks, files);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	BLOCK_INFO_freeAndClearInternals(&blocks);
	KSI_DataHash_free(theFirstInputHashInFile);

	return res;
}

int logsignature_integrate(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO* blocks, IO_FILES *files) {
	int res;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;
	KSI_DataHash *theFirstInputHashInFile = NULL;


	if (err == NULL || ksi == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	blocks->ftlv_raw = ftlv_raw;
	blocks->taskId = TASK_INTEGRATE;
	memset(&processors, 0, sizeof(processors));

	blocks->isContinuedOnFail = PARAM_SET_isSetByName(set, "continue-on-fail");

	res = process_magic_number(set, mp, err, blocks, files);
	if (res != KT_OK) goto cleanup;

	while (!SMART_FILE_isEof(files->files.partsBlk)) {
		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);

		res = LOGKSI_FTLV_smartFileRead(files->files.partsBlk, blocks->ftlv_raw, SOF_FTLV_BUFFER, &blocks->ftlv_len, &blocks->ftlv);
		if (res == KSI_OK) {
			switch (blocks->ftlv.tag) {
				case 0x901:
					if (theFirstInputHashInFile == NULL) theFirstInputHashInFile = KSI_DataHash_ref(blocks->inputHash);
				case 0x902:
				case 0x903:
				case 0x911:
					res = process_log_signature(set, mp, err, ksi, blocks, files);
					if (res != KT_OK) goto cleanup;
				break;
				case 0x904:
				{
					print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_EQUAL | DEBUG_LEVEL_2, "Integrating block no. %3zu: into log signature... ", blocks->blockNo);

					res = process_partial_block(set, err, ksi, blocks, files, mp);
					if (res != KT_OK) goto cleanup;

					res = LOGKSI_FTLV_smartFileRead(files->files.partsSig, blocks->ftlv_raw, SOF_FTLV_BUFFER, &blocks->ftlv_len, &blocks->ftlv);

					if (res != KT_OK) {
						if (blocks->ftlv_len > 0) {
							res = KT_INVALID_INPUT_FORMAT;
							ERR_TRCKR_ADD(err, res, "Error: Block no. %zu: incomplete data found in signatures file.", blocks->blockNo);
							ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature in signatures file.", blocks->blockNo);
						} else {
							res = KT_INVALID_INPUT_FORMAT;
							ERR_TRCKR_ADD(err, res, "Error: Block no. %zu: unexpected end of signatures file.", blocks->blockNo);
							ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature in signatures file.", blocks->blockNo);
						}
					}
					if (blocks->ftlv.tag != 0x904) {
						res = KT_INVALID_INPUT_FORMAT;
						ERR_TRCKR_ADD(err, res, "Error: Block no. %zu: unexpected TLV %04X read from block-signatures file.", blocks->blockNo, blocks->ftlv.tag);
						ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature in signatures file.", blocks->blockNo);
					}

					res = process_partial_signature(set, mp, err, ksi, &processors, blocks, files, 0);
					if (res != KT_OK) goto cleanup;
					print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_2, res);
				}
				break;

				default:
					/* TODO: unknown TLV found. Either
					 * 1) Warn user and skip TLV
					 * 2) Copy TLV (maybe warn user)
					 * 3) Abort extending with an error
					 */
				break;
			}
		} else {
			if (blocks->ftlv_len > 0) {
				res = KT_INVALID_INPUT_FORMAT;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete data found in blocks file.", blocks->blockNo);
			} else {
				break;
			}
		}
	}

	res = finalize_log_signature(set, mp, err, ksi, theFirstInputHashInFile, blocks, files);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_2, res);
	KSI_DataHash_free(theFirstInputHashInFile);

	return res;
}

static int wrapper_LOGKSI_createSignature(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files, KSI_DataHash *hash, KSI_uint64_t rootLevel, KSI_Signature **sig) {
	int res = KT_UNKNOWN_ERROR;
	int noErrTrckr = 0;

	if (set == NULL || err == NULL || ksi == NULL || blocks == NULL || files == NULL || hash == NULL || sig == NULL) {
		return KT_INVALID_ARGUMENT;
	}

	/* If --continue-on-fail is set, do not add errors to ERR_TRCKR as the amount of errors
	   will easily exceed its limits. */
	noErrTrckr = blocks->isContinuedOnFail;

	print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_EQUAL | DEBUG_LEVEL_2, "Signing Block no. %3zu... ", blocks->blockNo);
	res = LOGKSI_createSignature((noErrTrckr ? NULL : err), ksi, hash, rootLevel, sig);
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_2, res);

	return res;
}

int logsignature_sign(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, IO_FILES *files) {
	int res;
	int progress;
	BLOCK_INFO blocks;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;
	KSI_DataHash *theFirstInputHashInFile = NULL;
	int lastError = KT_OK;

	if (set == NULL || err == NULL || ksi == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	BLOCK_INFO_clearAll(&blocks);
	blocks.ftlv_raw = ftlv_raw;
	blocks.taskId = TASK_SIGN;
	memset(&processors, 0, sizeof(processors));
	processors.create_signature = wrapper_LOGKSI_createSignature;

	blocks.isContinuedOnFail = PARAM_SET_isSetByName(set, "continue-on-fail");

	res = process_magic_number(set, mp, err, &blocks, files);
	if (res != KT_OK) goto cleanup;

	if (blocks.version == RECSIG11 || blocks.version == RECSIG12) {
		res = KT_VERIFICATION_SKIPPED;
		ERR_TRCKR_ADD(err, res, "Signing of excerpt file not possible! Only log signature file can be signed.");
		goto cleanup;
	}

	if (SMART_FILE_isStream(files->files.inSig)) {
		progress = (PARAM_SET_isSetByName(set, "d")&& PARAM_SET_isSetByName(set, "show-progress"));
	} else {
		/* Impossible to estimate signing progress if input is from stdin. */
		progress = 0;
	}

	if (progress) {
		res = count_blocks(err, ksi, &blocks, files->files.inSig);
		if (res != KT_OK) goto cleanup;
		print_debug("Progress: %3zu of %3zu blocks need signing. Estimated signing time: %3zu seconds.\n", blocks.noSigCount, blocks.blockCount, blocks.noSigCount);
	}

	while (!SMART_FILE_isEof(files->files.inSig)) {
		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);

		res = LOGKSI_FTLV_smartFileRead(files->files.inSig, blocks.ftlv_raw, SOF_FTLV_BUFFER, &blocks.ftlv_len, &blocks.ftlv);
		if (res == KSI_OK) {
			switch (blocks.ftlv.tag) {
				case 0x901:
					if (theFirstInputHashInFile == NULL) theFirstInputHashInFile = KSI_DataHash_ref(blocks.inputHash);
				case 0x902:
				case 0x903:
				case 0x911:
					res = process_log_signature(set, mp, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x904:
				{
					res = process_partial_signature(set, mp, err, ksi, &processors, &blocks, files, progress);
					if (res == KT_SIGNING_FAILURE) {
						lastError = res;
						res = KT_OK;
					}

					if (res != KT_OK) goto cleanup;
				}
				break;

				default:
					/* TODO: unknown TLV found. Either
					 * 1) Warn user and skip TLV
					 * 2) Copy TLV (maybe warn user)
					 * 3) Abort extending with an error
					 */
				break;
			}
		} else {
			if (blocks.ftlv_len > 0) {
				res = KT_INVALID_INPUT_FORMAT;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete data found in log signature file.", blocks.blockNo);
			} else {
				break;
			}
		}
	}

	res = finalize_log_signature(set, mp, err, ksi, theFirstInputHashInFile, &blocks, files);
	if (res != KT_OK) goto cleanup;

	res = SMART_FILE_markConsistent(files->files.outSig);
	ERR_CATCH_MSG(err, res, "Error: Could not close output log signature file %s.", files->internal.outSig);

	res = KT_OK;

cleanup:
	/**
	 * + If there is error mark output file as inconsistent.
	 * + If there is no changes and output is not explicitly specified
	 *   and output file already exists, mark output file as inconsistent.
	 * + Inconsistent state discards temporary file created.
	 */
	if (files->files.outSig != NULL &&
										(res != KT_OK ||
										 (!blocks.outSigModified && !PARAM_SET_isSetByName(set, "o") && SMART_FILE_doFileExist(files->internal.outSig))
										)) {
		int tmp_res;
		tmp_res = SMART_FILE_markInconsistent(files->files.outSig);
		ERR_CATCH_MSG(err, tmp_res, "Error: Unable to mark output signature file as inconsistent.");
	}

	if (lastError != KT_OK) {
		res = lastError;
		ERR_TRCKR_ADD(err, res, "Error: Signing FAILED but was continued. All failed blocks are left unsigned!");
	}

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_2, res);
	BLOCK_INFO_freeAndClearInternals(&blocks);
	KSI_DataHash_free(theFirstInputHashInFile);

	return res;
}
