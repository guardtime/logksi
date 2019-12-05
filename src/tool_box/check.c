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

#include <string.h>
#include <stdlib.h>
#include <ksi/ksi.h>
#include <ksi/tlv_element.h>
#include "io_files.h"
#include "logksi_err.h"
#include "param_set/param_set.h"
#include "param_set/strn.h"
#include "api_wrapper.h"
#include "logksi.h"
#include "check.h"
#include <time.h>
#include "param_control.h"


/*
 * TODO:
 * TODO:
 * TODO:
 * TODO:
 * TODO:
 * TODO: Put me somewhere.
 */
const char *io_files_getCurrentLogFilePrintRepresentation(IO_FILES *files);


int check_log_line_embedded_time(PARAM_SET* set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi) {
	int res = KT_UNKNOWN_ERROR;
	uint64_t last_time = 0;
	const char *ret = NULL;

	if (set == NULL || err == NULL || mp == NULL || logksi == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	if (logksi->taskId == TASK_VERIFY && PARAM_SET_isSetByName(set, "time-form")) {
		char *format = NULL;
		struct tm tmp_time;
		time_t t = 0;

		res = PARAM_SET_getStr(set, "time-form", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &format);
		ERR_CATCH_MSG(err, res, "Error: Unable to get time format string.");

		ret = strptime(logksi->logLine, format, &tmp_time);
		if (ret == NULL) {
			res = KT_INVALID_INPUT_FORMAT;
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Unable to extract timestamp (%s) from log line %zu: %.*s.\n", logksi->blockNo, format, logksi_get_nof_lines(logksi), (strlen(logksi->logLine) - 1), logksi->logLine);
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Unable to extract time stamp from log line %zu in block %zu:\n"
																						  "   + Log line:    '%.*s'\n"
																						  "   + Time format: '%s'\n"
																						  ,  logksi_get_nof_lines(logksi), logksi->blockNo, (strlen(logksi->logLine) - 1), logksi->logLine, format);

			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract time stamp from the logline no. %zu.", logksi->blockNo, logksi_get_nof_lines(logksi))
		}


		if (PARAM_SET_isSetByName(set, "time-base")) {
			int timeBase = 0;

			res = PARAM_SET_getObj(set, "time-base", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, (void**)&timeBase);
			ERR_CATCH_MSG(err, res, "Error: Unable to extract time base as integer.");

			tmp_time.tm_year = timeBase - 1900;
		}

		t = KSI_CalendarTimeToUnixTime(&tmp_time);

		/* Check the order of log lines. */
		last_time = logksi->block.recTimeMax == 0 ? logksi->file.recTimeMax : logksi->block.recTimeMax;

		if (logksi->block.recTimeMin == 0 && logksi->file.recTimeMax == 0) {
			logksi->block.recTimeMin = t;
			logksi->block.recTimeMax = t;
		} else {
			if (logksi->block.recTimeMin == 0 || logksi->block.recTimeMin > t) logksi->block.recTimeMin = t;
			if (logksi->block.recTimeMax < t) logksi->block.recTimeMax = t;

			if (PARAM_SET_isSetByName(set, "time-diff")) {
				size_t line_nr_0 = logksi_get_nof_lines(logksi) - 1;
				size_t line_nr_1 = logksi_get_nof_lines(logksi);

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
					logksi->file.nofTotalFailedBlocks++;

					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Log line %zu (%s) is more recent than log line %zu (%s).\n", logksi->blockNo, line_nr_0, str_last_time, line_nr_1, str_current_time);
					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Log line %zu in block %zu is more recent than log line %zu:\n"
																						  "   + Time for log line %zu: %s\n"
																						  "   + Time for log line %zu: %s\n"
																						  ,  line_nr_0, logksi->blockNo, line_nr_1, line_nr_0, str_last_time, line_nr_1, str_current_time);
					logksi->quietError = res;
					if (logksi->isContinuedOnFail) res = KT_OK;

					else ERR_TRCKR_ADD(err, res, "Error: Log line %zu in block %zu is more recent than log line %zu!", line_nr_0, logksi->blockNo, line_nr_1);
					goto cleanup;
				}
			}
		}

	}

	res = KT_OK;

cleanup:

	return res;
}

int check_log_record_embedded_time_against_ksi_signature_time(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, LOGKSI *logksi) {
	int res = KT_UNKNOWN_ERROR;
	int checkLogRecordTime = 0;

	if (set == NULL || mp == NULL || err == NULL || logksi == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	checkLogRecordTime = PARAM_SET_isSetByName(set, "time-form,time-diff");

	if (checkLogRecordTime && logksi->block.sigTime_1 != 0 && logksi->block.recTimeMin != 0 && logksi->block.recTimeMax != 0) {
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

		diff_calc_most_recent = uint64_diff(logksi->block.sigTime_1, logksi->block.recTimeMax, &diff_calc_most_recent_sign);
		diff_calc_less_recent = uint64_diff(logksi->block.sigTime_1, logksi->block.recTimeMin, &diff_calc_less_recent_sign);
		isTimeDiffTooLarge_past = uint64_signcmp(diff_calc_less_recent_sign, diff_calc_less_recent, 1, allowed_deviation_pos) > 0;	/* Calculated deviation must be greater or equal to allowed deviation to fail. */
		isTimeDiffTooLarge_future = uint64_signcmp(diff_calc_most_recent_sign, diff_calc_most_recent, neg_sign, neg_sign * allowed_deviation_neg) < 0;	/* Calculated deviation must be smaller or equal to allowed deviation to fail. */
		isTimeDiffTooLarge = isTimeDiffTooLarge_past || isTimeDiffTooLarge_future;

		if (allowed_deviation_pos > 0 && allowed_deviation_neg == 0) {
			isSigTimeOlderThanRecTime = (logksi->block.sigTime_1 < logksi->block.recTimeMin) || (logksi->block.sigTime_1 < logksi->block.recTimeMax);
		}


		/* Format some strings for debugging output and error messages. */
		time_diff_to_string(diff_calc_less_recent, str_diff_calc_past, sizeof(str_diff_calc_past));
		time_diff_to_string(diff_calc_most_recent, str_diff_calc_future, sizeof(str_diff_calc_future));
		LOGKSI_uint64_toDateString(logksi->block.recTimeMin, str_rec_time_min, sizeof(str_rec_time_min));
		LOGKSI_uint64_toDateString(logksi->block.recTimeMax, str_rec_time_max, sizeof(str_rec_time_max));

		if (uint64_signcmp(diff_calc_most_recent_sign, diff_calc_most_recent, 1, 0) >= 0 && uint64_signcmp(diff_calc_less_recent_sign, diff_calc_less_recent, 1, 0) >= 0) {
			KSI_snprintf(str_diff_calc, sizeof(str_diff_calc), "%s%s", (diff_calc_less_recent_sign < 0 ? "-" : ""), str_diff_calc_past);
		} else if (uint64_signcmp(diff_calc_most_recent_sign, diff_calc_most_recent, 1, 0) <= 0 && uint64_signcmp(diff_calc_less_recent_sign, diff_calc_less_recent, 1, 0) <= 0) {
			KSI_snprintf(str_diff_calc, sizeof(str_diff_calc), "%s%s", (diff_calc_most_recent_sign < 0 ? "-" : ""), str_diff_calc_future);
		} else {
			KSI_snprintf(str_diff_calc, sizeof(str_diff_calc), "-%s - %s", str_diff_calc_future, str_diff_calc_past);
		}


		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: time extracted from least recent log line: %s\n", logksi->blockNo, str_rec_time_min);
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: time extracted from most recent log line:  %s\n", logksi->blockNo, str_rec_time_max);
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: block time window:  %s\n", logksi->blockNo, str_diff_calc);

		print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: checking if time embedded into log lines fits in specified time window relative to the KSI signature... ", logksi->blockNo);

		/* In case of failure leave a mark and format some more strings. */
		if (isSigTimeOlderThanRecTime || isTimeDiffTooLarge) {
			res = KT_VERIFICATION_FAILURE;
			logksi->file.nofTotalFailedBlocks++;
			print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

			LOGKSI_uint64_toDateString(logksi->block.sigTime_1, str_sigTime1, sizeof(str_sigTime1));

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
				print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: %s the log lines are more recent than KSI signature.\n", logksi->blockNo, (logksi->block.sigTime_1 < logksi->block.recTimeMin ? "All" : "Some of"));
				print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: %s the log lines in block %zu are more recent than KSI signature:\n"
																					  "   + Signing time:                              %s\n"
																					  "   + Time extracted from least recent log line: %s\n"
																					  "   + Time extracted from most recent log line:  %s\n"
																					  ,  (logksi->block.sigTime_1 < logksi->block.recTimeMin ? "All" : "Some of"), logksi->blockNo, str_sigTime1, str_rec_time_min, str_rec_time_max);
			logksi->quietError = res;
			if (logksi->isContinuedOnFail) res = KT_OK;
			else ERR_TRCKR_ADD(err, res, "Error: %s the log lines in block %zu are more recent than KSI signature!", (logksi->block.sigTime_1 < logksi->block.recTimeMin ? "All" : "Some of"), logksi->blockNo);
			goto cleanup;
		} else if (isTimeDiffTooLarge) {
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Log lines do not fit into expected time window (%s).\n", logksi->blockNo, str_allowed_diff);
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Log lines in block %zu do not fit into time window:\n"
																				  "   + Signing time:                              %s\n"
																				  "   + Time extracted from least recent log line: %s\n"
																				  "   + Time extracted from most recent log line:  %s\n"
																				  "   + Block time window:                         %s\n"
																				  "   + Expected time window:                      %s\n"
																				  , logksi->blockNo, str_sigTime1, str_rec_time_min, str_rec_time_max, str_diff_calc, str_allowed_diff);
			logksi->quietError = res;
			if (logksi->isContinuedOnFail) res = KT_OK;
			else ERR_TRCKR_ADD(err, res, "Error: Log lines in block %zu do not fit into time window!", logksi->blockNo);
			goto cleanup;
		}

		if (res != KT_OK) goto cleanup;
	}

	res = KT_OK;

cleanup:

	return res;
}

int check_log_signature_client_id(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, LOGKSI *logksi, KSI_Signature *sig) {
	int res = KT_UNKNOWN_ERROR;
	char strClientId[0xffff] = "<client id not available>";

	if (set == NULL || mp == NULL || err == NULL || logksi == NULL || sig == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Verify KSI signatures Client ID. */
	if (logksi->task.verify.client_id_match != NULL && logksi->taskId == TASK_VERIFY) {
		print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
		print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: Verifying Client ID... ", logksi->blockNo);

		LOGKSI_signerIdentityToString(sig, strClientId, sizeof(strClientId));

		res = REGEXP_processString(logksi->task.verify.client_id_match, strClientId, NULL);
		if (res != REGEXP_NO_MATCH && res != REGEXP_OK) {
			ERR_TRCKR_ADD(err, res, "Error: Unexpected regular expression error: %i!", res);
			goto cleanup;
		}

		/* Verify that match is full match! */
		if (res == REGEXP_OK) {
			char match[0xffff] = "";

			res = REGEXP_getMatchingGroup(logksi->task.verify.client_id_match, 0, match, sizeof(match));
			if (res != REGEXP_OK) {
				ERR_TRCKR_ADD(err, res, "Error: Unexpected regular expression error: %i!", res);
				goto cleanup;
			}

			if (strcmp(strClientId, match) != 0) res = REGEXP_NO_MATCH;
		}

		if (res != REGEXP_OK) {
			logksi->file.nofTotalFailedBlocks++;
			res = KT_VERIFICATION_FAILURE;
			logksi->quietError = res;
			print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Failed to match KSI signatures client ID for block %zu:\n"
																				  "   + Client ID:       '%s'\n"
																				  "   + Regexp. pattern: '%s'\n", logksi->blockNo, strClientId, REGEXP_getPattern(logksi->task.verify.client_id_match));

			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Client ID mismatch '%s'.\n", logksi->blockNo, strClientId);
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Not matching pattern '%s'.\n", logksi->blockNo, REGEXP_getPattern(logksi->task.verify.client_id_match));
		if (logksi->isContinuedOnFail) res = KT_OK;
		else ERR_TRCKR_ADD(err, res, "Error: Failed to match KSI signatures client ID for block %zu!", logksi->blockNo);
		goto cleanup;
		}
	}

	if (PARAM_SET_isSetByName(set, "warn-client-id-change")) {
		if (logksi->task.verify.client_id_last[0] == '\0') {
			LOGKSI_signerIdentityToString(sig, logksi->task.verify.client_id_last, sizeof(logksi->task.verify.client_id_last));
		} else {
			LOGKSI_signerIdentityToString(sig, strClientId, sizeof(strClientId));

			if (strcmp(logksi->task.verify.client_id_last, strClientId) != 0) {
				print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Warning: Client ID is not constant. Expecting '%s', but is '%s'.\n", logksi->blockNo, logksi->task.verify.client_id_last, strClientId);
				print_debug_mp(mp, MP_ID_LOGFILE_WARNINGS, DEBUG_SMALLER | DEBUG_LEVEL_3, " o Warning: Client ID in block %zu is not constant:\n"
																						  "   + Expecting: '%s'\n"
																						  "   + But is:    '%s'.\n\n", logksi->blockNo, logksi->task.verify.client_id_last, strClientId);
			}
		}
	}

	res = KT_OK;

cleanup:
	return res;
}

int handle_block_signing_time_check(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files) {
	int res = KT_UNKNOWN_ERROR;
	char *dummy = NULL;
	int checkDescSigkTime = 0;
	int warnSameSigTime = 0;
	int checkSigTimeDiff = 0;
	int hasFailed = 0;

	if (set == NULL || mp == NULL || err == NULL || logksi == NULL) {
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
		if (logksi->sigTime_0 > 0 && logksi->block.sigTime_1 > 0) {
			char str_diff[256] = "<null>";
			uint64_t diff = 0;
			int diff_sign = 0;
			const char *str_diff_sign = "";

			diff = uint64_diff(logksi->block.sigTime_1, logksi->sigTime_0, &diff_sign);
			if (diff_sign < 0) str_diff_sign = "-";

			LOGKSI_uint64_toDateString(logksi->sigTime_0, strT0, sizeof(strT0));
			LOGKSI_uint64_toDateString(logksi->block.sigTime_1, strT1, sizeof(strT1));
			time_diff_to_string(diff, str_diff, sizeof(str_diff));

			print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: time difference relative to previous block: %s%s\n", logksi->blockNo, str_diff_sign, str_diff);
			print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: checking signing time with previous block... ", logksi->blockNo);


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

					if (!hasFailed) logksi->file.nofTotalFailedBlocks++;
					res = KT_VERIFICATION_FAILURE;
					hasFailed = 1;

					print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);


					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: signing times difference (%s%s) relative to previous block out of range (%s).\n", logksi->blockNo, str_diff_sign, str_diff, str_range);

					if (logksi->blockNo == 1) {
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
							print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Blocks %zu signing time is more recent than expected relative to block %zu:\n", logksi->blockNo - 1, logksi->blockNo, reason);
						} else {
							print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Blocks %zu and %zu signing times are too %s:\n", logksi->blockNo - 1, logksi->blockNo, reason);
						}
						print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3,     "   + Sig time for block %zu: %s\n"
																								  "   + Sig time for block %zu: %s\n"
																								  "   + Time diff:              %s%s\n"
																								  "   + Expected time diff:     %s\n",
																								  logksi->blockNo - 1, strT0,
																								  logksi->blockNo, strT1,
																								  str_diff_sign, str_diff,
																								  str_range);
					}

					logksi->quietError = res;
					if (logksi->isContinuedOnFail) res = KT_OK;
					else ERR_TRCKR_ADD(err, res, "Error: Abnormal signing time difference for consecutive blocks!");

					goto cleanup;
				}
			}


			if (logksi->sigTime_0 > logksi->block.sigTime_1 && checkDescSigkTime) {
				print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_2, 1);
				print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_1, 1);
				logksi->task.verify.errSignTime = 1;

				if (logksi->blockNo == 1) {

					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Last block %s from file '%s' is more recent than first block %s from file '%s'\n", logksi->blockNo, strT0, previousLogFile, strT1, currentLogFile);
					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Last block %s from file '%s' is more recent than\n"
																						  "          first block %s from file '%s'\n", strT0, previousLogFile, strT1, currentLogFile);
				} else {
					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Block no. %3zu %s in %s '%s' is more recent than block no. %3zu %s\n",logksi->blockNo, logksi->blockNo - 1, strT0, (logStdin ? "log from" : "file"), currentLogFile, logksi->blockNo, strT1);
					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Block no. %3zu %s in %s '%s' is more recent than\n"
																						  "          block no. %3zu %s\n", logksi->blockNo - 1, strT0, (logStdin ? "log from" : "file"), currentLogFile, logksi->blockNo, strT1);
				}

				if (!hasFailed) logksi->file.nofTotalFailedBlocks++;
				print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, 1);
			}

			if (logksi->sigTime_0 == logksi->block.sigTime_1 && warnSameSigTime) {
				if (logksi->blockNo == 1) {
					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Warning: Last block from file '%s' and first block from file '%s' has same signing time %s.\n", logksi->blockNo, previousLogFile, currentLogFile, LOGKSI_uint64_toDateString(logksi->block.sigTime_1, buf, sizeof(buf)));
					print_debug_mp(mp, MP_ID_LOGFILE_WARNINGS, DEBUG_SMALLER | DEBUG_LEVEL_3, "Warning: Last block from file      '%s'\n"
						                                                   "         and first block from file '%s'\n"
																		   "         has same signing time %s.\n", previousLogFile, currentLogFile, LOGKSI_uint64_toDateString(logksi->block.sigTime_1, buf, sizeof(buf)));
				} else {
					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Warning: Block no. %3zu and %3zu in %s '%s' has same signing time %s.\n" , logksi->blockNo - 1, logksi->blockNo, (logStdin ? "log from" : "file"), currentLogFile, strT1);
					print_debug_mp(mp, MP_ID_LOGFILE_WARNINGS, DEBUG_SMALLER | DEBUG_LEVEL_3, "Warning: Block no. %3zu and %3zu in %s '%s' has same signing time %s.\n" , logksi->blockNo - 1, logksi->blockNo, (logStdin ? "log from" : "file"), currentLogFile, strT1);
				}
			}
		}

		print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_2, 0);

	}


	res = KT_OK;

cleanup:

	return res;
}

int handle_record_time_check_between_files(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files) {
	int res = KT_UNKNOWN_ERROR;

	if (set == NULL || mp == NULL || err == NULL || logksi == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (logksi->blockNo == 1 && logksi->file.recTimeMax != 0 && logksi->block.recTimeMin != 0 && PARAM_SET_isSetByName(set, "time-diff")) {
		int time_diff = 0;

		if (PARAM_SET_isSetByName(set, "time-disordered")) {
			res = PARAM_SET_getObj(set, "time-disordered", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, (void**)&time_diff);
			ERR_CATCH_MSG(err, res, "Error: Unable to extract time base as integer.");
		}

		if (logksi->file.recTimeMax > logksi->block.recTimeMin + time_diff) {
			char str_last_time[1024] = "<null>";
			char str_current_time[1024] = "<null>";

			/* Check if deviation in current range is accepted. */
			res = KT_VERIFICATION_FAILURE;
			print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);
			LOGKSI_uint64_toDateString(logksi->file.recTimeMax, str_last_time, sizeof(str_last_time));
			LOGKSI_uint64_toDateString(logksi->block.recTimeMin, str_current_time, sizeof(str_current_time));

			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Last log line (%s) from previous file is more recent than first log line (%s) from current file.\n", logksi->blockNo, str_last_time, str_current_time);

			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Most recent log line from previous file is more recent than least recent log line from current file:\n"
																			  "   + Previous log file:              %s\n"
																			  "   + Time for most recent log line:  %s\n"
																			  "   + Current log file:               %s\n"
																			  "   + Time for least recent log line: %s\n"
																			  ,files->previousLogFile , str_last_time, io_files_getCurrentLogFilePrintRepresentation(files), str_current_time);
			logksi->quietError = res;
			if (logksi->isContinuedOnFail) res = KT_OK;
			else ERR_TRCKR_ADD(err, res, "Error: Most recent log line from previous file is more recent than least recent log line from current file!");
			goto cleanup;
		}
	}

	res = KT_OK;

cleanup:

  return res;
}





/**
 * a > b ret 1
 * a == b ret 0
 * a < b ret -1
 */
int uint64_signcmp(int sa, uint64_t a, int sb, uint64_t b) {
	sa = sa >= 0 ? 1 : -1;
	sb = sb >= 0 ? 1 : -1;

	if (sa == sb && a == b) return 0;
	else if (sa > sb || (sa == sb && ((sa == 1 && a > b) || (sa == -1 && a < b)))) return 1;

	return -1;
}

uint64_t uint64_diff(uint64_t a, uint64_t b, int *sign) {
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

char* time_diff_to_string(uint64_t time_diff, char *buf, size_t buf_len) {
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