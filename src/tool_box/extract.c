/*
 * Copyright 2013-2017 Guardtime, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ksi/ksi.h>
#include <ksi/compatibility.h>
#include <ksi/policy.h>
#include <param_set/param_set.h>
#include <param_set/task_def.h>
#include <param_set/parameter.h>
#include <param_set/strn.h>
#include "tool_box/ksi_init.h"
#include "tool_box/param_control.h"
#include "tool_box/task_initializer.h"
#include "smart_file.h"
#include "err_trckr.h"
#include "api_wrapper.h"
#include "printer.h"
#include "debug_print.h"
#include "obj_printer.h"
#include "conf_file.h"
#include "tool.h"
#include "rsyslog.h"
#include "io_files.h"

static int generate_tasks_set(PARAM_SET *set, TASK_SET *task_set);
static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err);

static int generate_filenames(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files);
static int open_log_and_signature_files(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files);
static int rename_temporary_and_backup_files(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files);
static void close_log_and_signature_files(ERR_TRCKR *err, int res, IO_FILES *files);

#define PARAMS "{input}{log-from-stdin}{sig-from-stdin}{o}{out-log}{out-proof}{r}{d}{log}{h|help}{hex-to-str}{ksig}"

int extract_run(int argc, char **argv, char **envp) {
	int res;
	char buf[2048];
	PARAM_SET *set = NULL;
	TASK_SET *task_set = NULL;
	TASK *task = NULL;
	KSI_CTX *ksi = NULL;
	ERR_TRCKR *err = NULL;
	SMART_FILE *logfile = NULL;
	int d = 0;
	KSI_Signature *sig = NULL;
	IO_FILES files;
	int count = 0;
	MULTI_PRINTER *mp = NULL;

	IO_FILES_init(&files);

	/**
	 * Extract command line parameters and also add configuration specific parameters.
	 */
	res = PARAM_SET_new(
			CONF_generate_param_set_desc(PARAMS, "", buf, sizeof(buf)),
			&set);
	if (res != KT_OK) goto cleanup;

	res = TASK_SET_new(&task_set);
	if (res != PST_OK) goto cleanup;

	res = generate_tasks_set(set, task_set);
	if (res != PST_OK) goto cleanup;

	res = TASK_INITIALIZER_getServiceInfo(set, argc, argv, envp);
	if (res != PST_OK) goto cleanup;

	res = TASK_INITIALIZER_check_analyze_report(set, task_set, 0.2, 0.1, &task);
	if (res != KT_OK) goto cleanup;

	res = TASK_INITIALIZER_getPrinter(set, &mp);
	ERR_CATCH_MSG(err, res, "Error: Unable to create Multi printer!");

	res = TOOL_init_ksi(set, &ksi, &err, &logfile);
	if (res != KT_OK) goto cleanup;

	d = PARAM_SET_isSetByName(set, "d");

	res = check_pipe_errors(set, err);
	if (res != KT_OK) goto cleanup;

	res = PARAM_SET_getValueCount(set, "input", NULL, PST_PRIORITY_NONE, &count);
	if (res != KT_OK) goto cleanup;

	res = generate_filenames(set, err, &files);
	if (res != KT_OK) goto cleanup;

	res = open_log_and_signature_files(set, err, &files);
	if (res != KT_OK) goto cleanup;


	print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_EQUAL | DEBUG_LEVEL_1, "Extracting records... ");
	res = logsignature_extract(set, mp, err, ksi, &files);
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_1, res);
	if (res != KT_OK) goto cleanup;

	res = rename_temporary_and_backup_files(set, err, &files);
	if (res != KT_OK) goto cleanup;

cleanup:

	close_log_and_signature_files(err, res, &files);

	MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);
	if (MULTI_PRINTER_hasDataByID(mp, MP_ID_LOGFILE_WARNINGS)) {
		print_debug("\n");
		MULTI_PRINTER_printByID(mp, MP_ID_LOGFILE_WARNINGS);
	}
	LOGKSI_KSI_ERRTrace_save(ksi);

	if (res != KT_OK) {
		if (ERR_TRCKR_getErrCount(err) == 0) {ERR_TRCKR_ADD(err, res, NULL);}
		LOGKSI_KSI_ERRTrace_LOG(ksi);

		print_errors("\n");
		ERR_TRCKR_print(err, d);
	}

	SMART_FILE_close(logfile);
	PARAM_SET_free(set);
	TASK_SET_free(task_set);
	KSI_Signature_free(sig);
	ERR_TRCKR_free(err);
	KSI_CTX_free(ksi);
	MULTI_PRINTER_free(mp);

	return LOGKSI_errToExitCode(res);
}

char *extract_help_toString(char *buf, size_t len) {
	int res;
	char *ret = NULL;
	PARAM_SET *set;
	size_t count = 0;
	char tmp[1024];

	if (buf == NULL || len == 0) return NULL;


	/* Create set with documented parameters. */
	res = PARAM_SET_new(CONF_generate_param_set_desc(PARAMS "{logsig}", "", tmp, sizeof(tmp)), &set);
	if (res != PST_OK) goto cleanup;

	res = CONF_initialize_set_functions(set, "");
	if (res != PST_OK) goto cleanup;

	/* Temporary name change for formatting help text. */
	PARAM_SET_setPrintName(set, "input", "<logfile>", NULL);
	PARAM_SET_setHelpText(set, "input", NULL, "Log file from where to extract log records.");

	/* Note that logsig is not a real parameter, but a dummy parameter to be used to format help! */
	PARAM_SET_setPrintName(set, "logsig", "<logfile.logsig>", NULL);
	PARAM_SET_setHelpText(set, "logsig", NULL, "Log signature file from where to extract the KSI signature for integrity proof. If omitted, the log signature file name is derived by adding either '.logsig' or '.gtsig' to '<logfile>'. It is expected to be found in the same folder as the '<logfile>'.");

	PARAM_SET_setHelpText(set, "log-from-stdin", NULL, "The log file is read from stdin. Cannot be used with '--sig-from-stdin'. If '--log-from-stdin' is used, the log signature file name must be specified explicitly.");
	PARAM_SET_setHelpText(set, "sig-from-stdin", NULL, "The log signature file is read from stdin. Cannot be used with '--log-from-stdin'. If '--sig-from-stdin' is used, the log file name must be specified explicitly.");
	PARAM_SET_setHelpText(set, "o", "<outfile>", "Names of the output files will be derived from '<outfile>' by adding the appropriate suffixes. Name of the excerpt file will be '<outfile>.excerpt'. Name of the integrity proof file will be '<outfile>.excerpt.logsig'. If '<outfile>' is not specified, names of the output files will be derived from '<logfile>'. '<outfile>' must be specified if the log file is read from stdin.");
	PARAM_SET_setHelpText(set, "out-log", "<log.records>", "Name of the output log records file. '-' can be used to redirect the file to stdout. If '<log.records>' is not specified, the name is derived from either '<outfile>' or '<logfile>'.");
	PARAM_SET_setHelpText(set, "out-proof", "<integrity.proof>", "Name of the output integrity proof file. '-' can be used to redirect the file to stdout. If '<integrity.proof>' is not specified, the name is derived from either '<outfile>' or '<logfile>'.");
	PARAM_SET_setHelpText(set, "r", "<records>", "Positions of log records to be extraced, given as a list of ranges. Example: -r 12-18,21,88-192");
	PARAM_SET_setHelpText(set, "ksig", NULL, "Extracts pure KSI signatures and corresponding log lines into separate files instead of single integrity proof file and single log records file.");
	PARAM_SET_setHelpText(set, "d", NULL, "Print detailed information about processes and errors to stderr. To make output more verbose use -dd or -ddd.");
	PARAM_SET_setHelpText(set, "log", "<file>", "Write libksi log to the given file. Use '-' as file name to redirect the log to stdout.");


	/* Format synopsis and parameters. */
	count += PST_snhiprintf(buf + count, len - count, 80, 0, 0, NULL, ' ', "Usage:\\>1\n\\>8"
	"logksi extract <logfile> [<logfile.logsig>] [-o <outfile>] -r <records> [more_options]\\>1\n\\>8"
	"logksi extract --log-from-stdin <logfile.logsig> -o <outfile> -r <records> [more_options]\\>1\n\\>8"
	"logksi extract --sig-from-stdin <logfile> [-o <outfile>] -r <records> [more_options]"
	"\\>\n\n\n");

	ret = PARAM_SET_helpToString(set, "input,logsig,log-from-stdin,sig-from-stdin,o,out-log,out-proof,r,ksig,d,log", 1, 13, 80, buf + count, len - count);

cleanup:
	if (res != PST_OK || ret == NULL) {
		PST_snprintf(buf + count, len - count, "\nError: There were failures while generating help by PARAM_SET.\n");
	}
	PARAM_SET_free(set);
	return buf;
}

const char *extract_get_desc(void) {
	return "Extracts log records and corresponding hash chains.";
}

static int generate_tasks_set(PARAM_SET *set, TASK_SET *task_set) {
	int res;

	if (set == NULL || task_set == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/**
	 * Configure parameter set, control, repair and object extractor function.
	 */
	PARAM_SET_addControl(set, "{log}{out-log}{out-proof}{o}", isFormatOk_path, NULL, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{input}", isFormatOk_inputFile, NULL, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{log-from-stdin}{sig-from-stdin}{d}{hex-to-str}{ksig}", isFormatOk_flag, NULL, NULL, NULL);
	PARAM_SET_addControl(set, "{r}", isFormatOk_string, NULL, NULL, NULL);

	PARAM_SET_setParseOptions(set, "input", PST_PRSCMD_COLLECT_LOOSE_VALUES | PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS);
	PARAM_SET_setParseOptions(set, "d", PST_PRSCMD_HAS_NO_VALUE | PST_PRSCMD_NO_TYPOS);
	PARAM_SET_setParseOptions(set, "r", PST_PRSCMD_HAS_VALUE | PST_PRSCMD_NO_TYPOS);
	PARAM_SET_setParseOptions(set, "log-from-stdin,sig-from-stdin,d,ksig", PST_PRSCMD_HAS_NO_VALUE);


	/*						ID		DESC									MAN							ATL		FORBIDDEN							IGN	*/
	TASK_SET_add(task_set,	0,		"Extract records and hash chains, "
									"log and signature from file.",			"input,r",					NULL,	"log-from-stdin,sig-from-stdin",	NULL);
	TASK_SET_add(task_set,	1,		"Extract records and hash chains, "
									"log from stdin, signature from file",	"input,log-from-stdin,r",	NULL,	"sig-from-stdin",					NULL);
	TASK_SET_add(task_set,	2,		"Extract records and hash chains, "
									"log from file, signature from stdin.",	"input,sig-from-stdin,r",	NULL,	"log-from-stdin",					NULL);

	res = KT_OK;

cleanup:

	return res;
}

static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err) {
	int res;

	res = get_pipe_out_error(set, err, NULL, "log,out-log,out-proof", NULL);
	if (res != KT_OK) goto cleanup;

	res = get_pipe_in_error(set, err, NULL, NULL, "log-from-stdin,sig-from-stdin");
	if (res != KT_OK) goto cleanup;

	/* Make sure that user can not send multiple KSI signatures or separate log lines to stdout. */
	if (PARAM_SET_isSetByName(set, "ksig")) {
		char *rec = NULL;
		char *out_log = NULL;
		char *out_proof = NULL;

		PARAM_SET_getStr(set, "r", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &rec);
		PARAM_SET_getStr(set, "out-log", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &out_log);
		PARAM_SET_getStr(set, "out-proof", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &out_proof);

		if (rec != NULL && (out_log != NULL || out_proof != NULL)) {
			int hasComma = (strchr(rec, ',') != NULL);
			int hasHyphen = (strchr(rec, '-') != NULL);
			int hasStdoutLog = 0;
			int hasStdoutSig = 0;

			if (out_log != NULL) {
				hasStdoutLog = (strcmp(out_log, "-") == 0);
			}

			if (out_proof != NULL) {
				hasStdoutSig = (strcmp(out_proof, "-") == 0);
			}

			if ((hasStdoutLog || hasStdoutSig) && (hasComma || hasHyphen)) {
				ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: Multiple different simultaneous outputs to stdout (--ksig, %s -, -r %s).",
					hasStdoutLog ? "--out-log" : "--out-proof",
					rec);
				ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  To redirect KSI signature or logline to stdout only 1 record can be extracted (e.g. -r n)\n", rec);
				goto cleanup;
			}
		}
	}

cleanup:
	return res;
}

static int generate_filenames(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files) {
	int res;
	IO_FILES tmp;
	char *legacy_name = NULL;
	int count = 0;

	memset(&tmp.internal, 0, sizeof(tmp.internal));

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	files->user.bStdinLog = PARAM_SET_isSetByName(set, "log-from-stdin");
	files->user.bStdinSig = PARAM_SET_isSetByName(set, "sig-from-stdin");

	res = PARAM_SET_getValueCount(set, "input", NULL, PST_PRIORITY_NONE, &count);
	if (res != KT_OK) goto cleanup;

	/* Either log or signature is from stdin, but not both. */
	if (files->user.bStdinLog) {
		res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_NONE, 0, &files->user.inSig);
		if (res != KT_OK) goto cleanup;
	} else if (files->user.bStdinSig) {
		res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_NONE, 0, &files->user.inLog);
		if (res != KT_OK) goto cleanup;
	} else {
		res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_NONE, 0, &files->user.inLog);
		if (res != KT_OK) goto cleanup;
		if (count > 1) {
			res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_NONE, 1, &files->user.inSig);
			if (res != KT_OK) goto cleanup;
		}
	}

	res = PARAM_SET_getStr(set, "out-log", NULL, PST_PRIORITY_NONE, 0, &files->user.outLog);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = PARAM_SET_getStr(set, "out-proof", NULL, PST_PRIORITY_NONE, 0, &files->user.outProof);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_NONE, 0, &files->user.outBase);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	/* Log file is specified. */
	if (files->user.inLog) {
		res = duplicate_name(files->user.inLog, &tmp.internal.inLog);
		ERR_CATCH_MSG(err, res, "Error: Could not duplicate input log file name.");
		/* If input log signature file name is not specified, it is generated from the input log file name. */
		if (files->user.inSig == NULL) {
			/* Generate input log signature file name. */
			res = concat_names(files->user.inLog, ".logsig", &tmp.internal.inSig);
			ERR_CATCH_MSG(err, res, "Error: Could not generate input log signature file name.");
			if (!SMART_FILE_doFileExist(tmp.internal.inSig)) {
				res = concat_names(files->user.inLog, ".gtsig", &legacy_name);
				ERR_CATCH_MSG(err, res, "Error: Could not generate input log signature file name.");
				if (SMART_FILE_doFileExist(legacy_name)) {
					KSI_free(tmp.internal.inSig);
					tmp.internal.inSig = legacy_name;
					legacy_name = NULL;
				}
			}
		}
	}

	if (files->user.inSig) {
		res = duplicate_name(files->user.inSig, &tmp.internal.inSig);
		ERR_CATCH_MSG(err, res, "Error: Could not duplicate input log signature file name.");
	}

	if (PARAM_SET_isSetByName(set, "ksig")) {
		if (files->user.outLog) {
			res = duplicate_name(files->user.outLog, &tmp.internal.outLineBase);
			ERR_CATCH_MSG(err, res, "Error: Could not duplicate output log line file name base.");
		}
		if (files->user.outProof) {
			res = duplicate_name(files->user.outProof, &tmp.internal.outKSIBase);
			ERR_CATCH_MSG(err, res, "Error: Could not duplicate output KSI signature file name base.");
		}

		if (files->user.outBase) {
			if (tmp.internal.outKSIBase == NULL && tmp.internal.outLineBase == NULL && strcmp(files->user.outBase, "-") == 0) {
				res = KT_INVALID_CMD_PARAM;
				ERR_TRCKR_ADD(err, res, "Error: Both output files cannot be redirected to stdout.");
				ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  Use only '--out-log -' or '--out-proof -' to redirect desired output to stdout.\n");
				goto cleanup;
			}

			if (tmp.internal.outKSIBase == NULL) res = duplicate_name(files->user.outBase, &tmp.internal.outKSIBase);
			ERR_CATCH_MSG(err, res, "Error: Could not duplicate output KSI signature file name base.");
			if (tmp.internal.outLineBase == NULL) res = duplicate_name(files->user.outBase, &tmp.internal.outLineBase);
			ERR_CATCH_MSG(err, res, "Error: Could not duplicate output KSI signature file name base.");
		}

		if (tmp.internal.outKSIBase == NULL || tmp.internal.outLineBase == NULL) {
			if (files->user.inLog == NULL) {
				res = KT_INVALID_CMD_PARAM;
				ERR_CATCH_MSG(err, res, "Error: Output output file name base for KSI signature must be specified if log file is read from stdin.");
			}

			if (tmp.internal.outKSIBase == NULL) res = duplicate_name(files->user.inLog, &tmp.internal.outKSIBase);
			ERR_CATCH_MSG(err, res, "Error: Could not duplicate output KSI signature file name base.");
			if (tmp.internal.outLineBase == NULL) res = duplicate_name(files->user.inLog, &tmp.internal.outLineBase);
			ERR_CATCH_MSG(err, res, "Error: Could not duplicate output KSI signature file name base.");
		}
	} else {
		if (files->user.outLog) {
			res = duplicate_name(files->user.outLog, &tmp.internal.outLog);
			ERR_CATCH_MSG(err, res, "Error: Could not duplicate output log records file name.");
		} else if (files->user.outBase) {
			if (!strcmp(files->user.outBase, "-")) {
				res = KT_INVALID_CMD_PARAM;
				ERR_TRCKR_ADD(err, res, "Error: Both output files cannot be redirected to stdout.");
				ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  Use ONLY '--out-log -' OR '--out-proof -' to redirect desired output to stdout.\n");
				goto cleanup;
			} else {
				res = concat_names(files->user.outBase, ".excerpt", &tmp.internal.outLog);
				ERR_CATCH_MSG(err, res, "Error: Could not generate output log records file name.");
			}
		} else {
			if (files->user.inLog) {
				res = concat_names(files->user.inLog, ".excerpt", &tmp.internal.outLog);
				ERR_CATCH_MSG(err, res, "Error: Could not generate output log records file name.");
			} else {
				res = KT_INVALID_CMD_PARAM;
				ERR_CATCH_MSG(err, res, "Error: Output log records file name must be specified if log file is read from stdin.");
			}
		}

		if (files->user.outProof) {
			res = duplicate_name(files->user.outProof, &tmp.internal.outProof);
			ERR_CATCH_MSG(err, res, "Error: Could not duplicate output integrity proof file name.");
		} else if (files->user.outBase) {
			res = concat_names(files->user.outBase, ".excerpt.logsig", &tmp.internal.outProof);
			ERR_CATCH_MSG(err, res, "Error: Could not generate output log records file name.");
		} else {
			if (files->user.inLog) {
				res = concat_names(files->user.inLog, ".excerpt.logsig", &tmp.internal.outProof);
				ERR_CATCH_MSG(err, res, "Error: Could not generate output integrity proof file name.");
			} else {
				res = KT_INVALID_CMD_PARAM;
				ERR_CATCH_MSG(err, res, "Error: Output integrity proof file name must be specified if log file is read from stdin.");
			}
		}
	}

	files->internal = tmp.internal;
	memset(&tmp.internal, 0, sizeof(tmp.internal));
	res = KT_OK;

cleanup:

	KSI_free(legacy_name);
	logksi_internal_filenames_free(&tmp.internal);

	return res;
}

static int open_log_and_signature_files(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files) {
	int res = KT_IO_ERROR;
	IO_FILES tmp;

	memset(&tmp.files, 0, sizeof(tmp.files));

	if (set == NULL || err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	if (files->user.bStdinLog) {
		res = SMART_FILE_open("-", "rbs", &tmp.files.inLog);
		ERR_CATCH_MSG(err, res, "Error: Could not open input log stream.");
	} else {
		res = SMART_FILE_open(files->internal.inLog, "rb", &tmp.files.inLog);
		ERR_CATCH_MSG(err, res, "Error: Could not open input log file '%s'.", files->internal.inLog);
	}

	if (files->user.bStdinSig) {
		res = SMART_FILE_open("-", "rbs", &tmp.files.inSig);
		ERR_CATCH_MSG(err, res, "Error: Could not open input sig file.");
	} else {
		res = SMART_FILE_open(files->internal.inSig, "rb", &tmp.files.inSig);
		ERR_CATCH_MSG(err, res, "Error: Could not open input sig file '%s'.", files->internal.inSig);
	}

	if (!PARAM_SET_isSetByName(set, "ksig")) {
		res = SMART_FILE_open(files->internal.outLog, "wbTs", &tmp.files.outLog);
		ERR_CATCH_MSG(err, res, "Error: Could not create temporary output log records file.");

		res = SMART_FILE_open(files->internal.outProof, "wbTs", &tmp.files.outProof);
		ERR_CATCH_MSG(err, res, "Error: Could not create temporary output log records file.");
	}

	files->files = tmp.files;
	memset(&tmp.files, 0, sizeof(tmp.files));

	res = KT_OK;

cleanup:

	logksi_files_close(&tmp.files);
	return res;
}

static int rename_temporary_and_backup_files(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files) {
	int res;

	if (set == NULL || err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (PARAM_SET_isSetByName(set, "ksig")) {
		res = KT_OK;
		goto cleanup;
	}

	res = SMART_FILE_markConsistent(files->files.outLog);
	ERR_CATCH_MSG(err, res, "Error: Could not close output log file %s.", files->internal.outLog);
	logksi_file_close(&files->files.outLog);

	res = SMART_FILE_markConsistent(files->files.outProof);
	ERR_CATCH_MSG(err, res, "Error: Could not close output log signature file %s.", files->internal.outProof);
	logksi_file_close(&files->files.outProof);

	res = KT_OK;

cleanup:

	return res;
}

static void close_log_and_signature_files(ERR_TRCKR *err, int res, IO_FILES *files) {
	if (files) {
		logksi_files_close(&files->files);
		logksi_internal_filenames_free(&files->internal);
	}
}
