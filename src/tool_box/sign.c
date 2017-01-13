/*
 * Copyright 2013-2016 Guardtime, Inc.
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

static int generate_tasks_set(PARAM_SET *set, TASK_SET *task_set);
static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err);
static int open_input_and_output_files(ERR_TRCKR *err, IO_FILES *files);
static void close_input_and_output_files(int result, IO_FILES *files);

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

	memset(&files, 0, sizeof(files));

	/**
	 * Extract command line parameters.
	 */
	res = PARAM_SET_new(
			CONF_generate_param_set_desc("{sign}{input}{o}{d}{log}{conf}{h|help}", "S", buf, sizeof(buf)),
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

	res = check_pipe_errors(set, err);
	if (res != KT_OK) goto cleanup;

	res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files.inLogName);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files.outSigName);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = open_input_and_output_files(err, &files);
	if (res != KT_OK) goto cleanup;

	res = logsignature_sign(set, err, ksi, &files);
	if (res != KT_OK) goto cleanup;

cleanup:

	close_input_and_output_files(res, &files);

	print_progressResult(res);
	KSITOOL_KSI_ERRTrace_save(ksi);

	if (res != KT_OK) {
		if (ERR_TRCKR_getErrCount(err) == 0) {ERR_TRCKR_ADD(err, res, NULL);}
		KSITOOL_KSI_ERRTrace_LOG(ksi);

		print_errors("\n");
		if (d) 	ERR_TRCKR_printExtendedErrors(err);
		else 	ERR_TRCKR_printErrors(err);
	}

	SMART_FILE_close(logfile);
	TASK_SET_free(task_set);
	PARAM_SET_free(set);
	ERR_TRCKR_free(err);
	KSI_CTX_free(ksi);

	return KSITOOL_errToExitCode(res);
}

char *sign_help_toString(char*buf, size_t len) {
	size_t count = 0;

	count += KSI_snprintf(buf + count, len - count,
		"Usage:\n"
		" %s sign -S <URL> [--aggr-user <user> --aggr-key <key>]\n"
		"          [more_options] [<logfile>] [-o <out.logsig>]\n"
		"\n"
		"\n"
		" <logfile>\n"
		"           - File path to the log file to be signed. If not specified,\n"
		"             the log signature is read from stdin.\n"
		" -o <out.logsig>\n"
		"           - Output file path for the signed log signature file. Use '-' to redirect the signed\n"
		"             log signature binary stream to stdout. If not specified, the log signature is saved\n"
		"             to <in.logsig> while a backup of <in.logsig> is saved in <in.logsig>.bak.\n"
		"             If specified, existing file is always overwritten.\n"
		"             If both input and outpur or not specified, stdin and stdout are used resepectively.\n"
		" -S <URL>  - Signing service (KSI Aggregator) URL.\n"
		" --aggr-user <str>\n"
		"           - Username for signing service.\n"
		" --aggr-key <str>\n"
		"           - HMAC key for signing service.\n"

		" -d        - Print detailed information about processes and errors to stderr.\n"
		" --conf <file>\n"
		"           - Read configuration options from given file. It must be noted\n"
		"             that configuration options given explicitly on command line will\n"
		"             override the ones in the configuration file.\n"
		" --log <file>\n"
		"           - Write libksi log to given file. Use '-' as file name to redirect\n"
		"             log to stdout.\n\n"
		, TOOL_getName()
	);

	return buf;
}

const char *sign_get_desc(void) {
	return "Signs the given input with KSI.";
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
	PARAM_SET_addControl(set, "{input}", isFormatOk_inputHash, isContentOk_inputHash, convertRepair_path, extract_inputHash);
	PARAM_SET_addControl(set, "{d}", isFormatOk_flag, NULL, NULL, NULL);


	PARAM_SET_setParseOptions(set, "input", PST_PRSCMD_COLLECT_LOOSE_VALUES | PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS);

	/*					  ID	DESC										MAN					ATL		FORBIDDEN		IGN	*/
	TASK_SET_add(task_set, 0,	"Sign data.",								"S,input",				NULL,	NULL,		NULL);

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

static int get_derived_name(char *org, const char *extension, char **derived) {
	int res;
	char *buf = NULL;

	if (org == NULL || extension == NULL || derived == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}
	buf = (char*)KSI_malloc(strlen(org) + strlen(extension) + 1);
	if (buf == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}
	sprintf(buf, "%s%s", org, extension);
	*derived = buf;
	res = KT_OK;

cleanup:

	return res;
}


static int get_backup_name(char *org, char **backup) {
	int res = KT_OUT_OF_MEMORY;
	char *buf = NULL;

	buf = (char*)KSI_malloc(strlen(org) + strlen(".bak") + 1);
	if (buf == NULL) goto cleanup;
	sprintf(buf, "%s%s", org, ".bak");
	*backup = buf;
	res = KT_OK;

cleanup:

	return res;
}

static int get_temp_name(char **name) {
	int res = KT_OUT_OF_MEMORY;
	char *buf = NULL;

	buf = (char*)KSI_malloc(strlen("stdout.tmp") + 1);
	if (buf == NULL) goto cleanup;
	strcpy(buf, "stdout.tmp");
	*name = buf;
	res = KT_OK;

cleanup:

	return res;
}

static int open_input_and_output_files(ERR_TRCKR *err, IO_FILES *files) {
	int res = KT_IO_ERROR;
	IO_FILES tmp;
	char *buf = NULL;

	memset(&tmp, 0, sizeof(tmp));

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Default input file is stdin. */
	if (files->inLogName == NULL) {
		/* Default output file is a temporary file that is copied to stdout on success. */
		if (files->outSigName == NULL || !strcmp(files->outSigName, "-")) {
			res = get_temp_name(&tmp.tempSigName);
			ERR_CATCH_MSG(err, res, "Error: out of memory.");
			tmp.outSigName = tmp.tempSigName;
		} else {
			tmp.outSigName = files->outSigName;
		}
	} else {
		res = get_derived_name(files->inLogName, ".logsig", &tmp.derivedSigName);
		ERR_CATCH_MSG(err, res, "Error: out of memory.");

		/* Default output file is the same as input, but a backup of the input file is retained. */
		if (files->outSigName == NULL || !strcmp(tmp.derivedSigName, files->outSigName)) {
			res = get_backup_name(tmp.derivedSigName, &buf);
			ERR_CATCH_MSG(err, res, "Error: out of memory.");
			remove(buf);
			res = (rename(tmp.derivedSigName, buf) == 0) ? KT_OK : KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: could not rename file %s to %s.", tmp.derivedSigName, buf);
			tmp.backupSigName = buf;
			buf = NULL;
			tmp.inSigName = tmp.backupSigName;
			tmp.outSigName = tmp.derivedSigName;
		} else if (!strcmp(files->outSigName, "-")) {
			res = get_temp_name(&tmp.tempSigName);
			ERR_CATCH_MSG(err, res, "Error: out of memory.");
			tmp.inSigName = tmp.derivedSigName;
			tmp.outSigName = tmp.tempSigName;
		} else {
			tmp.inSigName = tmp.derivedSigName;
			tmp.outSigName = files->outSigName;
		}
	}

	if (tmp.inSigName) {
		tmp.inSigFile = fopen(tmp.inSigName, "rb");
		res = (tmp.inSigFile == NULL) ? KT_IO_ERROR : KT_OK;
		ERR_CATCH_MSG(err, res, "Error: could not open file %s.", tmp.inSigName);
	} else {
		tmp.inSigFile = stdin;
	}

	if (tmp.outSigName) {
		tmp.outSigFile = fopen(tmp.outSigName, "wb");
		res = (tmp.outSigFile == NULL) ? KT_IO_ERROR : KT_OK;
		ERR_CATCH_MSG(err, res, "Error: could not create file %s.", tmp.outSigName);
	} else {
		tmp.outSigFile = stdout;
	}

	tmp.inLogName = files->inLogName;
	tmp.outSigName = files->outSigName;
	*files = tmp;
	memset(&tmp, 0, sizeof(tmp));
	res = KT_OK;

cleanup:

	if (tmp.inSigFile == stdin) tmp.inSigFile = NULL;
	if (tmp.outSigFile == stdout) tmp.outSigFile = NULL;

	if (tmp.backupSigName) {
		if (tmp.inSigFile) fclose(tmp.inSigFile);
		tmp.inSigFile = NULL;
		rename(tmp.backupSigName, tmp.inSigName);
		KSI_free(tmp.backupSigName);
	}
	if (tmp.tempSigName) {
		if (tmp.outSigFile) fclose(tmp.outSigFile);
		tmp.outSigFile = NULL;
		KSI_free(tmp.tempSigName);
	}
	KSI_free(buf);

	if (tmp.derivedSigName) {
		KSI_free(tmp.derivedSigName);
	}

	if (tmp.inSigFile) fclose(tmp.inSigFile);
	if (tmp.outSigFile) fclose(tmp.outSigFile);

	return res;
}

static void close_input_and_output_files(int result, IO_FILES *files) {
	char buf[1024];
	size_t count = 0;

	if (files == NULL) return;

	if (files->inSigFile == stdin) files->inSigFile = NULL;
	if (files->outSigFile == stdout) files->outSigFile = NULL;

	if (files->tempSigName) {
		if (result == KT_OK) {
			freopen(NULL, "rb", files->outSigFile);
			while (!feof(files->outSigFile)) {
				count = fread(buf, 1, sizeof(buf), files->outSigFile);
				fwrite(buf, 1, count, stdout);
			}
		}
		fclose(files->outSigFile);
		files->outSigFile = NULL;
		remove(files->tempSigName);
		KSI_free(files->tempSigName);
	}

	if (files->backupSigName) {
		if (result != KT_OK) {
			fclose(files->outSigFile);
			files->outSigFile = NULL;
			remove(files->inSigName);
			fclose(files->inSigFile);
			files->inSigFile = NULL;
			rename(files->backupSigName, files->inSigName);
		}
		KSI_free(files->backupSigName);
	}

	if (files->derivedSigName) {
		KSI_free(files->derivedSigName);
	}

	if (files->inSigFile) fclose(files->inSigFile);
	if (files->outSigFile) fclose(files->outSigFile);
}
