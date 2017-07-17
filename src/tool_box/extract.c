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
#include "param_set/param_set.h"
#include "param_set/task_def.h"
#include "param_set/parameter.h"
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

static int generate_tasks_set(PARAM_SET *set, TASK_SET *task_set);

static int generate_filenames(ERR_TRCKR *err, IO_FILES *files);
static int open_log_and_signature_files(ERR_TRCKR *err, IO_FILES *files);
static void close_log_and_signature_files(IO_FILES *files);

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

	memset(&files, 0, sizeof(files));

	/**
	 * Extract command line parameters and also add configuration specific parameters.
	 */
	res = PARAM_SET_new(
			CONF_generate_param_set_desc("{input}{r}{d}{log}{h|help}", "", buf, sizeof(buf)),
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

	d = PARAM_SET_isSetByName(set, "d");

	res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_NONE, 0, &files.user.log);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = generate_filenames(err, &files);
	if (res != KT_OK) goto cleanup;

	res = open_log_and_signature_files(err, &files);
	if (res != KT_OK) goto cleanup;

	res = logsignature_extract(set, err, ksi, &files);
	if (res != KT_OK) goto cleanup;

cleanup:

	close_log_and_signature_files(&files);

	print_progressResult(res);
	LOGKSI_KSI_ERRTrace_save(ksi);

	if (res != KT_OK) {
		if (ERR_TRCKR_getErrCount(err) == 0) {ERR_TRCKR_ADD(err, res, NULL);}
		LOGKSI_KSI_ERRTrace_LOG(ksi);

		print_errors("\n");
		if (d) ERR_TRCKR_printExtendedErrors(err);
		else  ERR_TRCKR_printErrors(err);
	}

	SMART_FILE_close(logfile);
	PARAM_SET_free(set);
	TASK_SET_free(task_set);
	KSI_Signature_free(sig);
	ERR_TRCKR_free(err);
	KSI_CTX_free(ksi);

	return LOGKSI_errToExitCode(res);
}

char *extract_help_toString(char *buf, size_t len) {
	KSI_snprintf(buf, len,
		"Usage:\n"
		" %s extract <logfile> -r <records> [more_options]\n"
		"\n"
		" <logfile>\n"
		"           - Log file from where to extract log records.\n"
		" -r <records>\n"
		"             Positions of log records to be extraced, given as a list of ranges.\n"
		"             Example: -r 12-18,21,88-192\n"
		"             Note: the list must be enclosed in double quotes if spaces are used as separators.\n"
		" -d        - Print detailed information about processes and errors to stderr.\n"
		" --log <file>\n"
		"           - Write libksi log to the given file. Use '-' as file name to redirect the log to stdout.\n",
		TOOL_getName()
	);

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
	PARAM_SET_addControl(set, "{log}", isFormatOk_path, NULL, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{input}", isFormatOk_inputFile, isContentOk_inputFile, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{d}", isFormatOk_flag, NULL, NULL, NULL);
	PARAM_SET_addControl(set, "{r}", isFormatOk_string, NULL, NULL, NULL);

	PARAM_SET_setParseOptions(set, "input", PST_PRSCMD_COLLECT_LOOSE_VALUES | PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS);
	PARAM_SET_setParseOptions(set, "d", PST_PRSCMD_HAS_NO_VALUE | PST_PRSCMD_NO_TYPOS);

	/*						ID		DESC									MAN				ATL		FORBIDDEN	IGN	*/
	TASK_SET_add(task_set,	0,		"Extract records and hash chains.",		"input,r",		NULL,	NULL,		NULL);

	res = KT_OK;

cleanup:

	return res;
}

static int generate_filenames(ERR_TRCKR *err, IO_FILES *files) {
	int res;
	IO_FILES tmp;

	memset(&tmp.internal, 0, sizeof(tmp.internal));

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = duplicate_name(files->user.log, &tmp.internal.log);
	ERR_CATCH_MSG(err, res, "Error: could not duplicate input log file name.");

	res = concat_names(files->user.log, ".logsig", &tmp.internal.inSig);
	ERR_CATCH_MSG(err, res, "Error: could not generate input log signature file name.");

	res = concat_names(files->user.log, ".part.logsig", &tmp.internal.outProof);
	ERR_CATCH_MSG(err, res, "Error: could not generate output integrity proof file name.");

	res = concat_names(files->user.log, ".part", &tmp.internal.outLog);
	ERR_CATCH_MSG(err, res, "Error: could not generate output log records file name.");

	files->internal = tmp.internal;
	memset(&tmp.internal, 0, sizeof(tmp.internal));
	res = KT_OK;

cleanup:

	logksi_internal_filenames_free(&tmp.internal);

	return res;
}

static int open_log_and_signature_files(ERR_TRCKR *err, IO_FILES *files) {
	int res = KT_IO_ERROR;
	IO_FILES tmp;

	memset(&tmp.files, 0, sizeof(tmp.files));

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = logksi_file_check_and_open(err, files->internal.log, &tmp.files.log);
	if (res != KT_OK) goto cleanup;

	res = logksi_file_check_and_open(err, files->internal.inSig, &tmp.files.inSig);
	if (res != KT_OK) goto cleanup;

	res = logksi_file_create(files->internal.outProof, &tmp.files.outProof);
	ERR_CATCH_MSG(err, res, "Error: could not open output integrity proof file %s.", files->internal.outProof);

	res = logksi_file_create(files->internal.outLog, &tmp.files.outLog);
	ERR_CATCH_MSG(err, res, "Error: could not open output log records file %s.", files->internal.outLog);

	files->files = tmp.files;
	memset(&tmp.files, 0, sizeof(tmp.files));

	res = KT_OK;

cleanup:

	logksi_files_close(&tmp.files);
	return res;
}

static void close_log_and_signature_files(IO_FILES *files) {
	if (files) {
		logksi_files_close(&files->files);
		logksi_internal_filenames_free(&files->internal);
	}
}
