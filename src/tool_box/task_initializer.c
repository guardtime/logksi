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

#include "task_initializer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <ksi/compatibility.h>
#include <ksi/ksi.h>
#include <ksi/net.h>

#include "param_set/param_set.h"
#include "param_set/task_def.h"
#include "param_set/strn.h"
#include "tool_box/param_control.h"
#include "tool_box.h"
#include "printer.h"
#include "debug_print.h"
#include "conf_file.h"
#include "logksi_err.h"
#include "obj_printer.h"
#include "api_wrapper.h"
#include "smart_file.h"

static int isKSIUserInfoInsideUrl(const char *url, char *buf_u, char *buf_k, size_t buf_len);
static int extract_user_info_from_url_if_needed(PARAM_SET *set, const char *flag_name, const char *usr_name, const char *key_name);

int TASK_INITIALIZER_check_analyze_report(PARAM_SET *set, TASK_SET *task_set, double task_set_sens, double task_dif, TASK **task) {
	int res;
	char buf[0xffff];
	TASK *pTask = NULL;


	if (set == NULL || task_set == NULL || task == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	/**
	 * Check for typos and unknown parameters.
	 */
	if (PARAM_SET_isTypoFailure(set)) {
			print_errors("%s\n", PARAM_SET_typosToString(set, NULL, buf, sizeof(buf)));
			res = KT_INVALID_CMD_PARAM;
			goto cleanup;
	} else if (PARAM_SET_isUnknown(set)){
			print_errors("%s\n", PARAM_SET_unknownsToString(set, "Error: ", buf, sizeof(buf)));
			res = KT_INVALID_CMD_PARAM;
			goto cleanup;
	}

	/**
	 * Check for invalid values.
	 */
	if (!PARAM_SET_isFormatOK(set)) {
		PARAM_SET_invalidParametersToString(set, NULL, getParameterErrorString, buf, sizeof(buf));
		print_errors("%s", buf);
		res = KT_INVALID_CMD_PARAM;
		goto cleanup;
	}

	/**
	 * Analyze task set and Extract the task if consistent one exists, print help
	 * messaged otherwise.
	 */
	res = TASK_SET_analyzeConsistency(task_set, set, task_set_sens);
	if (res != PST_OK) goto cleanup;

	res = TASK_SET_getConsistentTask(task_set, &pTask);
	if (res != PST_OK && res != PST_TASK_ZERO_CONSISTENT_TASKS && res !=PST_TASK_MULTIPLE_CONSISTENT_TASKS) goto cleanup;
	*task = pTask;


	/**
	 * If task is not present report errors.
	 */
	if (pTask == NULL) {
		int ID;
		if (TASK_SET_isOneFromSetTheTarget(task_set, task_dif, &ID)) {
			print_errors("%s", TASK_SET_howToRepair_toString(task_set, set, ID, NULL, buf, sizeof(buf)));
		} else {
			print_errors("%s", TASK_SET_suggestions_toString(task_set, 3, buf, sizeof(buf)));
		}

		res = KT_INVALID_CMD_PARAM;
		goto cleanup;
	}


	res = KT_OK;

cleanup:

	/* pTask is just a reference. There is no need to free it. */

	return res;
}

int TASK_INITIALIZER_getServiceInfo(PARAM_SET *set, int argc, char **argv, char **envp) {
	int res;
	PARAM_SET *conf_env = NULL;
	PARAM_SET *conf_file = NULL;
	char buf[0xffff];
	char *conf_file_name = NULL;

	res = CONF_createSet(&conf_env);
	if (res != KT_OK) goto cleanup;

	res = CONF_createSet(&conf_file);
	if (res != KT_OK) goto cleanup;

	/**
	 * Include conf from environment.
     */
	res = CONF_fromEnvironment(conf_env, "KSI_CONF", envp, PRIORITY_KSI_CONF, 1);
	res = conf_report_errors(conf_env, CONF_getEnvNameContent(), res);
	if (res != KT_OK) goto cleanup;

	/**
	 * Read conf from command line.
     */
	res = PARAM_SET_parseCMD(set, argc, argv, "CMD", PRIORITY_CMD);
	if (res != PST_OK) {
		print_errors("Error: Unable to parse command-line %x.\n", res);
		goto cleanup;
	}

	/**
	 * Include configuration file.
     */
	if (PARAM_SET_isSetByName(set, "conf")) {
		res = PARAM_SET_getStr(set, "conf", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &conf_file_name);
		if (res != PST_OK && res != PST_PARAMETER_INVALID_FORMAT) goto cleanup;

		if (conf_file_name != NULL && res == PST_OK) {
			res = PARAM_SET_readFromFile(conf_file, conf_file_name, conf_file_name, PRIORITY_KSI_CONF_FILE);
			if (res != PST_OK && res != PST_INVALID_FORMAT) goto cleanup;

			res = CONF_convertFilePaths(conf_file, conf_file_name, "{W}{V}{P}{X}{S}", conf_file_name, PRIORITY_KSI_CONF_FILE);
			if (res != PST_OK) goto cleanup;
		}

		if (CONF_isInvalid(conf_file)) {
			print_errors("configuration file '%s' is invalid:\n", conf_file_name);
			print_errors("%s\n", CONF_errorsToString(conf_file, "  ", buf, sizeof(buf)));
			res = KT_INVALID_CONF;
			goto cleanup;
		}
	}


	/**
	 * Merge conf files to the set.
     */
	res = PARAM_SET_IncludeSet(set, conf_env);
	if (res != PST_OK) goto cleanup;

	res = PARAM_SET_IncludeSet(set, conf_file);
	if (res != PST_OK) goto cleanup;

	/**
	 * Check for embedded user info from the URLs. Parameters are stored in layers
	 * at specified priority. If there are URL (S and X), the most important URL
	 * values are extracted and it is checked if user info at the given priority level
	 * exists. If not, user info is extracted from URLs if present and appended to
	 * the same priority level as URLs.
     */
	res = extract_user_info_from_url_if_needed(set, "S", "aggr-user", "aggr-key");
	if (res != KT_OK) goto cleanup;

	res = extract_user_info_from_url_if_needed(set, "X", "ext-user", "ext-key");
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	PARAM_SET_free(conf_env);
	PARAM_SET_free(conf_file);

	return res;
}

static int isKSIUserInfoInsideUrl(const char *url, char *buf_u, char *buf_k, size_t buf_len) {
	int res = KT_UNKNOWN_ERROR;
	char *ret = NULL;
	char buf[1024];
	char *scheme = NULL;
	int result = 0;

	if (url == NULL || *url == '\0' || buf_u == NULL || buf_k == NULL || buf_len == 0) goto cleanup;;

	res = KSI_UriSplitBasic(url, &scheme, NULL, NULL, NULL);
	if (res != KSI_OK) goto cleanup;

	/**
	 * The user info embedded in the url is extracted ONLY when the url scheme
	 * contains prefix ksi+. In the other cases the user info is interpreted as
	 * specified by the given protocol.
     */
	if (scheme == NULL || strstr(scheme, "ksi+") == NULL) goto cleanup;

	ret = STRING_extractAbstract(url, "://", "@", buf, sizeof(buf), find_charAfterStrn, find_charBeforeStrn, NULL);
	if (ret != buf) goto cleanup;;

	ret = STRING_extract(buf, NULL, ":", buf_u, buf_len);
	if (ret != buf_u) goto cleanup;;

	if (buf_u[0] == ':') buf_u[0] = '\0';

	ret = STRING_extract(buf, ":", NULL, buf_k, buf_len);
	if (ret != buf_k) goto cleanup;;

	result = 1;

cleanup:

	KSI_free(scheme);

	return result;
}

static int extract_user_info_from_url_if_needed(PARAM_SET *set, const char *flag_name, const char *usr_name, const char *key_name) {
	int res;
	char *url = NULL;
	char usr[1024];
	char key[1024];
	char src[1024];
	char *dummy = NULL;
	PARAM_ATR atr;

	if (set == NULL || flag_name == NULL || usr_name == NULL || key_name == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}
	/**
	 * Extract the url withe the greatest priority for further examination.
	 */
	res = PARAM_SET_getStr(set, flag_name, NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &url);
	if (res != PST_OK && res != PST_PARAMETER_EMPTY && res != PST_PARAMETER_INVALID_FORMAT && res != PST_PARAMETER_NOT_FOUND) {
		goto cleanup;
	} else if (res == PST_PARAMETER_EMPTY || res == PST_PARAMETER_INVALID_FORMAT || res == PST_PARAMETER_NOT_FOUND) {
		res = KT_OK;
		goto cleanup;
	}

	/**
	 * If there is a user info embedded into url, check if there is a need to
	 * extract the values and append to the set.
     */
	if (isKSIUserInfoInsideUrl(url, usr, key, sizeof(usr))) {
		res = PARAM_SET_getAtr(set, flag_name, NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &atr);
		if (res != PST_OK) goto cleanup;

		KSI_snprintf(src, sizeof(src), "%s.%s.url_user_info",
				atr.source == NULL ? "" : atr.source,
				flag_name);

		/**
		 * Check if the user at the given priority level exists.
		 */
		res = PARAM_SET_getStr(set, usr_name, NULL, atr.priority, PST_INDEX_LAST, &dummy);
		if (res == PST_PARAMETER_VALUE_NOT_FOUND || res == PST_PARAMETER_EMPTY) {
			res = PARAM_SET_add(set, usr_name, usr, src, atr.priority);
			if (res != PST_OK) goto cleanup;
		} else if (res != PST_OK && res != PST_PARAMETER_EMPTY && res != PST_PARAMETER_EMPTY) {
			goto cleanup;
		}

		/**
		 * Check if the key at the given priority level exists.
		 */
		res = PARAM_SET_getStr(set, key_name, NULL, atr.priority, PST_INDEX_LAST, &dummy);
		if (res == PST_PARAMETER_VALUE_NOT_FOUND || res == PST_PARAMETER_EMPTY) {
			res = PARAM_SET_add(set, key_name, key, src, atr.priority);
			if (res != PST_OK) goto cleanup;
		} else if (res != PST_OK && res != PST_PARAMETER_EMPTY && res != PST_PARAMETER_EMPTY) {
			goto cleanup;
		}
	}

	res = KT_OK;

cleanup:

	return res;
}

int TASK_INITIALIZER_getPrinter(PARAM_SET *set, MULTI_PRINTER **mp) {
	int res = KT_UNKNOWN_ERROR;
	int debugLevel = 0;
	MULTI_PRINTER *tmp = NULL;


	if (set == NULL || mp == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Create multi-printer. */
	res = PARAM_SET_getValueCount(set, "d", NULL, PST_PRIORITY_HIGHEST, &debugLevel);
	if (res != KT_OK) goto cleanup;

	res = MULTI_PRINTER_new(debugLevel, 100000, &tmp);
	if (res != KT_OK) goto cleanup;


	/* Create initial channels. */
	res = MULTI_PRINTER_openChannel(tmp, MP_ID_BLOCK, 0, print_debug);
	if (res != KT_OK) goto cleanup;

	/* Make error buffer extra large (~16 MiB) to fit block internal errors. */
	res = MULTI_PRINTER_openChannel(tmp, MP_ID_BLOCK_ERRORS, 0x1000000, print_errors);
	if (res != KT_OK) goto cleanup;

	res = MULTI_PRINTER_openChannel(tmp, MP_ID_LOGFILE_WARNINGS, 0, print_errors);
	if (res != KT_OK) goto cleanup;

	res = MULTI_PRINTER_openChannel(tmp, MP_ID_BLOCK_PARSING_TREE_NODES, 0, print_debug);
	if (res != KT_OK) goto cleanup;

	res = MULTI_PRINTER_openChannel(tmp, MP_ID_BLOCK_SUMMARY, 1024, print_debug);
	if (res != KT_OK) goto cleanup;

	res = MULTI_PRINTER_openChannel(tmp, MP_ID_LOGFILE_SUMMARY, 1024, print_debug);
	if (res != KT_OK) goto cleanup;

	*mp = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	MULTI_PRINTER_free(tmp);

	return res;
}

static int read_next_file(const char *row, const char *delimiter, char *fname_buf, size_t fname_buf_len, const char **next) {
	int res = KT_UNKNOWN_ERROR;
	size_t i = 0;
	size_t n = 0;
	int isEscape = 0;
	int isQuote = 0;
	int isQuoteX2 = 0;
	int lastNotWhiteChar = 0;

	for(i = 0; row[i] != '\0'; i++) {
		char c = row[i];

		if (!isEscape) {
			if (c == '\\') {
				isEscape = 1;
				continue;
			}
			if (!isQuoteX2 && c == '\'') {
				isQuote = isQuote ? 0 : 1;
				continue;
			}
			if (!isQuote && c == '"') {
				isQuoteX2 = isQuoteX2 ? 0 : 1;
				continue;
			}
		}

		/* Check if is delimiter! */
		if ((delimiter != NULL) && !isEscape && !isQuote && !isQuoteX2) {
			if (strchr(delimiter, c) != NULL) {
				if (n > 0) {
					break;
				}
				continue;
			}
		}

		if (n >= fname_buf_len - 1) {
			res = KT_INDEX_OVF;
			goto cleanup;
		}

		if(!isEscape && n == 0 && isspace(c)) continue;

		if (!isspace(c)) {
			lastNotWhiteChar = n;
		}

		fname_buf[n] = c;
		n++;
		if (isEscape) isEscape = 0;

	}

	fname_buf[lastNotWhiteChar + 1] = '\0';
	*next = (row[i] == '\0') ? NULL : row + (i + 1);
	res = KT_OK;

cleanup:
	return res;
}

int extract_input_files_from_file(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err) {
	int res = KT_UNKNOWN_ERROR;
	SMART_FILE *logFileList = NULL;
	char *delimiter = " \t";

	if (set == NULL) return KT_INVALID_ARGUMENT;

	res = PARAM_SET_getStr(set, "log-file-list-delimiter", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &delimiter);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	if (delimiter != NULL) {
		if (strcmp(delimiter, "new-line") == 0) delimiter = NULL;
		else if (strcmp(delimiter, "space") == 0) delimiter = " \t";
	}

	if (PARAM_SET_isSetByName(set, "log-file-list")) {
		char *fname = NULL;
		res = PARAM_SET_getStr(set, "log-file-list", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &fname);
		if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

		res = SMART_FILE_open(fname, "rbs", &logFileList);
		ERR_CATCH_MSG(err, res, "Error: Could not open input log file list '%s'!", fname);

		if (strcmp(fname, "-") == 0) {
			fname = "<stdin>";
		}

		while(1) {
			char buf_file_name[0x1000] = "";
			size_t rowLen = 0;
			const char *next = NULL;


			res = SMART_FILE_readLineSkipEmpty(logFileList, buf_file_name, sizeof(buf_file_name), NULL, &rowLen);
			if (SMART_FILE_isEof(logFileList)) break;
			ERR_CATCH_MSG(err, res, "Error: Could no read input file from input log file list '%s'!", fname);
			next = buf_file_name;
			while(next != NULL) {
				char buf_file_name2[0x1000] = "";
				res = read_next_file(next, delimiter, buf_file_name2, sizeof(buf_file_name2), &next);
				ERR_CATCH_MSG(err, res, "Error: Could no read input file from input log file list '%s'!", fname);
				if (buf_file_name2[0] == '\0') continue;

				if (!SMART_FILE_doFileExist(buf_file_name2)) {
					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_LEVEL_0,
						"Error: Log file (from --log-file-list %s) '%s' does not exist!\n", fname, buf_file_name2);
					continue;
				} else if (SMART_FILE_isFileType(buf_file_name2, SMART_FILE_TYPE_DIR)) {
					print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_LEVEL_0,
						"Error: Log file (from --log-file-list %s) '%s' can not be a directory!\n", fname, buf_file_name2);
					continue;
				}

				res = PARAM_SET_add(set, "input" , buf_file_name2, NULL, PRIORITY_CMD);
				ERR_CATCH_MSG(err, res, "Error: Could no include input log file '%s' to list!", buf_file_name2);
			}
		}

		if (MULTI_PRINTER_hasDataByID(mp, MP_ID_BLOCK_ERRORS)) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Unable to include input log files from log file list %s!", fname);
		}

	}

	res = KT_OK;

cleanup:

	SMART_FILE_close(logFileList);

	return res;
}

static int get_remote_aggr_conf(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ctx, int *remote_max_lvl, KSI_HashAlgorithm *remote_algo) {
	#define TREE_DEPTH_INVALID (-1)
	int res = KT_UNKNOWN_ERROR;
	KSI_Config *config = NULL;
	KSI_Integer *conf_id = NULL;
	KSI_Integer *conf_lvl = NULL;
	int dump = 0;
	const char *suggestion_useDump = "  * Suggestion: Use --dump-conf for more information.";
	const char *suggestion_useH    = "  * Suggestion: Use -H to override aggregator configuration hash function.";


	if (set == NULL || err == NULL || ctx == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = LOGKSI_Aggregator_getConf(err, ctx, &config);
	ERR_CATCH_MSG(err, res, "Error: Unable to receive remote configuration.");

	dump = PARAM_SET_isSetByName(set, "dump-conf");
	if (dump) {
		OBJPRINT_aggregatorConfDump(config, print_result);
	}

	res = KSI_Config_getAggrAlgo(config, &conf_id);
	ERR_CATCH_MSG(err, res, "Error: Unable to get aggregator algorithm id configuration.");

	res = KSI_Config_getMaxLevel(config, &conf_lvl);
	ERR_CATCH_MSG(err, res, "Error: Unable to get aggregator maximum level configuration.");

	if (remote_max_lvl) {
		if (conf_lvl) {
			size_t lvl = KSI_Integer_getUInt64(conf_lvl);

			if (lvl > 0xff) {
				ERR_CATCH_MSG(err, (res = KT_INVALID_CONF), "Error: Remote configuration tree depth is out of range.\n");
				if (!dump) ERR_TRCKR_addAdditionalInfo(err, "%s\n", suggestion_useDump);
				*remote_max_lvl = TREE_DEPTH_INVALID;
			} else {
				*remote_max_lvl = (int)lvl;
			}
		} else {
			*remote_max_lvl = TREE_DEPTH_INVALID;
		}
	}

	if (remote_algo) {
		if (conf_id) {
			int H = PARAM_SET_isSetByName(set, "H");
			KSI_HashAlgorithm alg_id = (KSI_HashAlgorithm)KSI_Integer_getUInt64(conf_id);

			if (!KSI_isHashAlgorithmSupported(alg_id)) {
				if (!H) {
					ERR_TRCKR_ADD(err, (res = KT_INVALID_CONF), "Error: Remote configuration algorithm is not supported.");
					if (!dump) ERR_TRCKR_addAdditionalInfo(err, "%s\n", suggestion_useDump);
					ERR_TRCKR_addAdditionalInfo(err, "%s\n", suggestion_useH);
					goto cleanup;
				}
			} else if (!KSI_isHashAlgorithmTrusted(alg_id)) {
				if (!H) {
					ERR_TRCKR_addWarning(err, "  * Warning: Remote configuration algorithm is not trusted.\n");
					if (!dump) ERR_TRCKR_addAdditionalInfo(err, "%s\n", suggestion_useDump);
					ERR_TRCKR_addAdditionalInfo(err, "%s\n", suggestion_useH);
				}
			}
			*remote_algo = alg_id;
		} else {
			*remote_algo = KSI_HASHALG_INVALID_VALUE;
		}
	}

cleanup:
	KSI_Config_free(config);

	return res;
#undef TREE_DEPTH_INVALID
}

static int is_set_by_name_at_pri(PARAM_SET *set, const char *name, int pri) {
	int count = 0;
	int res = PST_UNKNOWN_ERROR;
	res = PARAM_SET_getValueCount(set, name, NULL, pri, &count);
	if (res != PST_OK) return 0;
	return count > 0;
}

int apply_aggregator_conf(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi) {
	int res = KT_UNKNOWN_ERROR;
	KSI_HashAlgorithm remote_algo = KSI_HASHALG_INVALID_VALUE;
	int remote_max_lvl = -1;
	int user_max_lvl = -1;
	char buf[32] = "";
	int priority = 0;
	char *dummy = NULL;

	if (set == NULL || err == NULL || ksi == NULL) return KT_INVALID_ARGUMENT;

	res = get_remote_aggr_conf(set, err, ksi, &remote_max_lvl, &remote_algo);
	if (res != KT_OK) goto cleanup;

	if (PARAM_SET_isSetByName(set, "dump-conf")) goto cleanup;

	res = PARAM_SET_getObj(set, "max-lvl", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, (void*)&user_max_lvl);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY && res != PST_PARAMETER_VALUE_NOT_FOUND) goto cleanup;

	if (user_max_lvl == -1 || user_max_lvl > remote_max_lvl) {
		PST_snprintf(buf, sizeof(buf), "%i", remote_max_lvl);
		res = PARAM_SET_add(set, "max-lvl", buf, "remote-conf", PRIORITY_CMD);
		if (res != KT_OK) goto cleanup;
	}

	for (priority = PRIORITY_DEFAULT; priority < PRIORITY_COUNT; priority++) {
		if (is_set_by_name_at_pri(set, "apply-remote-conf", priority)) {
			if (!is_set_by_name_at_pri(set, "H", priority)) {
				res = PARAM_SET_add(set, "H", KSI_getHashAlgorithmName(remote_algo), "remote-conf", priority);
				if (res != KT_OK) goto cleanup;
			}
		}
	}

	/* libparamset bug:
	   To set some internal magic, affected by inserting new values,
	   to initial state query some values from the beginning.
	 */
	PARAM_SET_getStr(set, "max-lvl", NULL, PST_PRIORITY_NONE, 0, &dummy);
	PARAM_SET_getStr(set, "H", NULL, PST_PRIORITY_NONE, 0, &dummy);

	res = KT_OK;
cleanup:

	return res;
}