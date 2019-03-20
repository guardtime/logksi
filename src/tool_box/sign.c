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

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <ksi/ksi.h>
#include <ksi/compatibility.h>
#include "param_set/param_set.h"
#include "param_set/task_def.h"
#include "param_set/parameter.h"
#include "api_wrapper.h"
#include "tool_box/param_control.h"
#include "tool_box/ksi_init.h"
#include "tool_box/task_initializer.h"
#include "debug_print.h"
#include "smart_file.h"
#include "err_trckr.h"
#include "printer.h"
#include "obj_printer.h"
#include "conf_file.h"
#include "tool.h"
#include "param_set/parameter.h"
#include "../tool_box.h"
#include "param_set/param_set_obj_impl.h"
#include "param_set/strn.h"
#include "rsyslog.h"
#include "blocks_info.h"
#include "io_files.h"

static int generate_tasks_set(PARAM_SET *set, TASK_SET *task_set);
static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err);
static int generate_filenames(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files);
static int open_input_and_output_files(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files);
static int rename_temporary_and_backup_files(ERR_TRCKR *err, IO_FILES *files);
static void close_input_and_output_files(ERR_TRCKR *err, int res, IO_FILES *files);

int sign_run(int argc, char** argv, char **envp) {
	int res;
	char buf[2048];
	PARAM_SET *set = NULL;
	TASK_SET *task_set = NULL;
	TASK *task = NULL;
	KSI_CTX *ksi = NULL;
	ERR_TRCKR *err = NULL;
	SMART_FILE *logfile = NULL;
	int d = 0;
	IO_FILES files;
	MULTI_PRINTER *mp = NULL;
	int noProgress = 1;
	IO_FILES_init(&files);

	/**
	 * Extract command line parameters.
	 */
	res = PARAM_SET_new(
			CONF_generate_param_set_desc("{input}{o}{sig-from-stdin}{insert-missing-hashes}{d}{show-progress}{log}{conf}{h|help}", "S", buf, sizeof(buf)),
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

	res = TOOL_init_ksi(set, &ksi, &err, &logfile);
	if (res != KT_OK) goto cleanup;

	PARAM_SET_getValueCount(set, "d", NULL, PST_PRIORITY_HIGHEST, &d);

	res = TASK_INITIALIZER_getPrinter(set, &mp);
	ERR_CATCH_MSG(err, res, "Error: Unable to create Multi printer!");

	res = check_pipe_errors(set, err);
	if (res != KT_OK) goto cleanup;

	res = generate_filenames(set, err, &files);
	if (res != KT_OK) goto cleanup;

	res = open_input_and_output_files(set, err, &files);
	if (res != KT_OK) goto cleanup;

	if (d > 1) PARAM_SET_clearParameter(set, "show-progress");

	noProgress = !PARAM_SET_isSetByName(set, "show-progress");


	if (noProgress) print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_EQUAL | DEBUG_LEVEL_1, "Signing... ");
	res = logsignature_sign(set, mp, err, ksi, &files);
	if (noProgress) print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_1, res);
	if (res != KT_OK) goto cleanup;

	res = rename_temporary_and_backup_files(err, &files);
	if (res != KT_OK) goto cleanup;

cleanup:

	/* If there is an error while closing files, report it only if everything else was OK. */
	close_input_and_output_files(err, res, &files);

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
	TASK_SET_free(task_set);
	PARAM_SET_free(set);
	ERR_TRCKR_free(err);
	KSI_CTX_free(ksi);
	MULTI_PRINTER_free(mp);


	return LOGKSI_errToExitCode(res);
}

char *sign_help_toString(char*buf, size_t len) {
	KSI_snprintf(buf, len,
		"Usage:\n"
		" %s sign <logfile> [-o <out.logsig>] -S <URL> [--aggr-user <user> --aggr-key <key>]\n"
		"          [more_options]\n"
		" %s sign --sig-from-stdin [-o <out.logsig>] -S <URL> [--aggr-user <user> --aggr-key <key>]\n"
		"          [more_options]\n"
		"\n"
		" <logfile>\n"
		"           - Name of the log file whose log signature file's unsigned blocks are to be signed.\n"
		"             Name of the log signature file is derived by adding either '.logsig' or '.gtsig' to '<logfile>'.\n"
		"             If specified, the '--sig-from-stdin' switch cannot be used.\n"
		" --sig-from-stdin\n"
		"             The log signature file is read from stdin.\n"
		" -o <out.logsig>\n"
		"           - Name of the signed output log signature file. An existing log signature file is overwritten.\n"
		"             If not specified, the log signature is saved to '<logfile>.logsig' while a backup of '<logfile>.logsig'\n"
		"             is saved in '<logfile>.logsig.bak'.\n"
		"             Use '-' to redirect the signed log signature binary stream to stdout.\n"
		"             If input is read from stdin and output is not specified, stdout is used for output.\n"
		" -S <URL>\n"
		"           - Signing service (KSI Aggregator) URL.\n"
		" --aggr-user <user>\n"
		"           - Username for signing service.\n"
		" --aggr-key <key>\n"
		"           - HMAC key for signing service.\n"
		" --aggr-hmac-alg <alg>\n"
		"           - Hash algorithm to be used for computing HMAC on outgoing messages\n"
		"             towards KSI aggregator. If not set, default algorithm is used.\n"
		" -d\n"
		"           - Print detailed information about processes and errors to stderr.\n"
		"             To make output more verbose use -dd or -ddd.\n"
		" --show-progress\n"
		"           - Print signing progress. Only valid with '-d' and debug level 1.\n"
		" --conf <file>\n"
		"           - Read configuration options from the given file. It must be noted\n"
		"             that configuration options given explicitly on command line will\n"
		"             override the ones in the configuration file.\n"
		" --log <file>\n"
		"           - Write libksi log to the given file. Use '-' as file name to redirect the log to stdout.\n",
		TOOL_getName(),
		TOOL_getName()
	);

	return buf;
}

const char *sign_get_desc(void) {
	return "Signs unsigned blocks in a log signature file.";
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
	res = CONF_initialize_set_functions(set, "S");
	if (res != KT_OK) goto cleanup;

	PARAM_SET_addControl(set, "{conf}", isFormatOk_inputFile, isContentOk_inputFileRestrictPipe, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{o}{log}", isFormatOk_path, NULL, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{input}", isFormatOk_path, NULL, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{sig-from-stdin}{insert-missing-hashes}{d}{show-progress}", isFormatOk_flag, NULL, NULL, NULL);


	PARAM_SET_setParseOptions(set, "input", PST_PRSCMD_COLLECT_LOOSE_VALUES | PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS);
	PARAM_SET_setParseOptions(set, "d", PST_PRSCMD_HAS_NO_VALUE | PST_PRSCMD_NO_TYPOS);
	PARAM_SET_setParseOptions(set, "sig-from-stdin,insert-missing-hashes,show-progress", PST_PRSCMD_HAS_NO_VALUE);

	/*					  ID	DESC										MAN					ATL		FORBIDDEN		IGN	*/
	TASK_SET_add(task_set, 0,	"Sign data from file.",						"input,S",			NULL,	"sig-from-stdin",			NULL);
	TASK_SET_add(task_set, 1,	"Sign data from standard input.",			"sig-from-stdin,S",	NULL,	"input",			NULL);

cleanup:

	return res;
}

static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err) {
	int res;

	res = get_pipe_out_error(set, err, "o", "log", NULL);
	if (res != KT_OK) goto cleanup;

	res = get_pipe_in_error(set, err, "input", NULL, NULL);
	if (res != KT_OK) goto cleanup;

cleanup:
	return res;
}

static int generate_filenames(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files) {
	int res;
	IO_FILES tmp;
	char *legacy_name = NULL;

	memset(&tmp.internal, 0, sizeof(tmp.internal));

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files->user.inLog);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files->user.outSig);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	/* Get input signature file name. */
	if (files->user.inLog == NULL) {
		/* If not specified, the input signature is read from stdin. */
		/* If log file is not specified and o is not specified get input signature from stdin. */
		if (PARAM_SET_isSetByName(set, "sig-from-stdin")) {
			res = duplicate_name("-", &tmp.internal.inSig);
			ERR_CATCH_MSG(err, res, "Error: Could not duplicate output log signature file name.");
		}
	} else {
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

	/* Get Output signature file name. */
	if (files->user.outSig == NULL && tmp.internal.inSig != NULL) {
		res = duplicate_name(tmp.internal.inSig, &tmp.internal.outSig);
		ERR_CATCH_MSG(err, res, "Error: Could not duplicate input log signature file name.");
	} else {
		res = duplicate_name(files->user.outSig, &tmp.internal.outSig);
		ERR_CATCH_MSG(err, res, "Error: Could not duplicate output log signature file name.");
	}

	files->internal = tmp.internal;
	memset(&tmp.internal, 0, sizeof(tmp.internal));
	res = KT_OK;

cleanup:

	KSI_free(legacy_name);
	logksi_internal_filenames_free(&tmp.internal);

	return res;
}

static int open_input_and_output_files(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files) {
	int res;
	IO_FILES tmp;
	int overWrite = 0;

	memset(&tmp.files, 0, sizeof(tmp.files));

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	overWrite = PARAM_SET_isSetByName(set, "o");

	if (files->internal.inSig) {
		res = SMART_FILE_open(files->internal.inSig, "rbs", &tmp.files.inSig);
		if (res != KT_OK) goto cleanup;
	} else {
		res = SMART_FILE_open("-", "rbs", &tmp.files.inSig);	/* A buffered (nameless temporary file) stream. */
		if (res != KT_OK) goto cleanup;
	}

	res = SMART_FILE_open(files->internal.outSig, overWrite ? "wbTs" : "wbBTs", &tmp.files.outSig);
	ERR_CATCH_MSG(err, res, "Error: Could not create temporary output log signature file.");

	files->files = tmp.files;
	memset(&tmp.files, 0, sizeof(tmp.files));

	res = KT_OK;

cleanup:

	logksi_files_close(&tmp.files);
	return res;
}

static int rename_temporary_and_backup_files(ERR_TRCKR *err, IO_FILES *files) {
	int res;

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Close input file first, so it is possible to make a backup of it or overwrite it. */
	logksi_file_close(&files->files.inSig);
	logksi_file_close(&files->files.outSig);

	res = KT_OK;

cleanup:

	return res;
}

static void close_input_and_output_files(ERR_TRCKR *err, int res, IO_FILES *files) {
	if (files) {
		logksi_files_close(&files->files);
		logksi_internal_filenames_free(&files->internal);
	}
}
