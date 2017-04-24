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

static int generate_tasks_set(PARAM_SET *set, TASK_SET *task_set);
static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err);
static int generate_filenames(ERR_TRCKR *err, IO_FILES *files);
static int open_input_and_output_files(ERR_TRCKR *err, IO_FILES *files);
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

	memset(&files, 0, sizeof(files));

	/**
	 * Extract command line parameters.
	 */
	res = PARAM_SET_new(
			CONF_generate_param_set_desc("{input}{o}{d}{show-progress}{log}{conf}{h|help}", "S", buf, sizeof(buf)),
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

	res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files.user.log);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files.user.sig);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = generate_filenames(err, &files);
	if (res != KT_OK) goto cleanup;

	res = open_input_and_output_files(err, &files);
	if (res != KT_OK) goto cleanup;

	res = logsignature_sign(set, err, ksi, &files);
	if (res != KT_OK) goto cleanup;

	res = rename_temporary_and_backup_files(err, &files);
	if (res != KT_OK) goto cleanup;

cleanup:

	/* If there is an error while closing files, report it only if everything else was OK. */
	close_input_and_output_files(err, res, &files);

	print_progressResult(res);
	LOGKSI_KSI_ERRTrace_save(ksi);

	if (res != KT_OK) {
		if (ERR_TRCKR_getErrCount(err) == 0) {ERR_TRCKR_ADD(err, res, NULL);}
		LOGKSI_KSI_ERRTrace_LOG(ksi);

		print_errors("\n");
		if (d) 	ERR_TRCKR_printExtendedErrors(err);
		else 	ERR_TRCKR_printErrors(err);
	}

	SMART_FILE_close(logfile);
	TASK_SET_free(task_set);
	PARAM_SET_free(set);
	ERR_TRCKR_free(err);
	KSI_CTX_free(ksi);

	return LOGKSI_errToExitCode(res);
}

char *sign_help_toString(char*buf, size_t len) {
	KSI_snprintf(buf, len,
		"Usage:\n"
		" %s sign [<logfile>] [-o <out.logsig>] -S <URL> [--aggr-user <user> --aggr-key <key>]\n"
		"          [more_options]\n"
		"\n"
		" <logfile>\n"
		"           - Name of the log file whose log signature file's unsigned blocks are to be signed.\n"
		"             If not specified, the log signature file is read from stdin.\n"
		" -o <out.logsig>\n"
		"           - Name of the signed output log signature file. An existing log signature file is overwritten.\n"
		"             If not specified, the log signature is saved to <logfile.logsig> while a backup of <logfile.logsig>\n"
		"             is saved in <logfile.logsig.bak>.\n"
		"             Use '-' to redirect the signed log signature binary stream to stdout.\n"
		"             If both input and output are not specified, stdin and stdout are used resepectively.\n"
		" -S <URL>  - Signing service (KSI Aggregator) URL.\n"
		" --aggr-user <user>\n"
		"           - Username for signing service.\n"
		" --aggr-key <key>\n"
		"           - HMAC key for signing service.\n"
		" -d        - Print detailed information about processes and errors to stderr.\n"
		" --show-progress"
		"           - Print signing progress. Only valid with -d.\n"
		" --conf <file>\n"
		"           - Read configuration options from the given file. It must be noted\n"
		"             that configuration options given explicitly on command line will\n"
		"             override the ones in the configuration file.\n"
		" --log <file>\n"
		"           - Write libksi log to the given file. Use '-' as file name to redirect the log to stdout.\n",
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
	PARAM_SET_addControl(set, "{d}{show-progress}", isFormatOk_flag, NULL, NULL, NULL);


	PARAM_SET_setParseOptions(set, "input", PST_PRSCMD_COLLECT_LOOSE_VALUES | PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS);
	PARAM_SET_setParseOptions(set, "d", PST_PRSCMD_HAS_NO_VALUE | PST_PRSCMD_NO_TYPOS);
	PARAM_SET_setParseOptions(set, "show-progress", PST_PRSCMD_HAS_NO_VALUE);

	/*					  ID	DESC										MAN					ATL		FORBIDDEN		IGN	*/
	TASK_SET_add(task_set, 0,	"Sign data.",								"S",				NULL,	NULL,		NULL);

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

static int generate_filenames(ERR_TRCKR *err, IO_FILES *files) {
	int res;
	IO_FILES tmp;

	memset(&tmp.internal, 0, sizeof(tmp.internal));

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* If not specified, the input signature is read from stdin. */
	if (files->user.log == NULL) {
		if (files->user.sig == NULL || !strcmp(files->user.sig, "-")) {
			/* Output must go to a nameless temporary file before redirecting it to stdout. */
			tmp.internal.bStdout = 1;
		} else {
			/* Output must go to a named temporary file that is renamed appropriately on success. */
			res = temp_name(files->user.sig, &tmp.internal.tempSig);
			ERR_CATCH_MSG(err, res, "Error: could not generate temporary output log signature file name.");
			tmp.internal.outSig = strdup(files->user.sig);
			if (tmp.internal.outSig == NULL) {
				res = KT_OUT_OF_MEMORY;
				ERR_CATCH_MSG(err, res, "Error: could not duplicate output log signature file name.");
			}
		}
	} else {
		/* Generate input log signature file name. */
		res = concat_names(files->user.log, ".logsig", &tmp.internal.inSig);
		ERR_CATCH_MSG(err, res, "Error: could not generate input log signature file name.");

		/* Check if output would overwrite the input log signature file. */
		if (files->user.sig == NULL || !strcmp(files->user.sig, tmp.internal.inSig)) {
			/* Output must to go to a temporary file before overwriting the input log signature file. */
			res = temp_name(tmp.internal.inSig, &tmp.internal.tempSig);
			ERR_CATCH_MSG(err, res, "Error: could not generate temporary output log signature file name.");
			/* Input must kept in a backup file when overwritten by the output log signature file. */
			res = concat_names(tmp.internal.inSig, ".bak", &tmp.internal.backupSig);
			ERR_CATCH_MSG(err, res, "Error: could not generate backup input log signature file name.");
		} else if (!strcmp(files->user.sig, "-")) {
			/* Output must go to a nameless temporary file before redirecting it to stdout. */
			tmp.internal.bStdout = 1;
		} else {
			/* Output must go to a named temporary file that is renamed appropriately on success. */
			res = temp_name(files->user.sig, &tmp.internal.tempSig);
			ERR_CATCH_MSG(err, res, "Error: could not generate temporary output log signature file name.");
			tmp.internal.outSig = strdup(files->user.sig);
			if (tmp.internal.outSig == NULL) {
				res = KT_OUT_OF_MEMORY;
				ERR_CATCH_MSG(err, res, "Error: could not duplicate output log signature file name.");
			}
		}
	}
	files->internal = tmp.internal;
	memset(&tmp.internal, 0, sizeof(tmp.internal));
	res = KT_OK;

cleanup:

	logksi_internal_filenames_free(&tmp.internal);

	return res;
}

static int open_input_and_output_files(ERR_TRCKR *err, IO_FILES *files) {
	int res;
	IO_FILES tmp;

	memset(&tmp.files, 0, sizeof(tmp.files));

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (files->internal.inSig) {
		/* Make sure that the input log signature exists. */
		tmp.files.inSig = fopen(files->internal.inSig, "rb");
		if (tmp.files.inSig == NULL) {
			if (errno == ENOENT) {
				res = KT_IO_ERROR;
				ERR_CATCH_MSG(err, res, "Error: no matching log signature file found for log file %s.", files->user.log);
			} else {
				res = KT_IO_ERROR;
				ERR_CATCH_MSG(err, res, "Error: could not open input log signature file %s.", files->internal.inSig);
			}
		}
	} else {
		/* If not specified, the input is taken from stdin. */
		tmp.files.inSig = stdin;
	}

	/* Output goes either to a named or nameless temporary file. */
	if (files->internal.bStdout) {
		tmp.files.outSig = tmpfile();
	} else {
		tmp.files.outSig = fopen(files->internal.tempSig, "wb");
	}
	if (tmp.files.outSig == NULL) {
		res = KT_IO_ERROR;
		ERR_CATCH_MSG(err, res, "Error: could not create temporary output log signature file.");
	}

	files->files = tmp.files;
	memset(&tmp.files, 0, sizeof(tmp.files));

	res = KT_OK;

cleanup:

	logksi_files_close(&tmp.files);
	return res;
}

static int rename_temporary_and_backup_files(ERR_TRCKR *err, IO_FILES *files) {
	int res;
	char buf[1024];
	size_t count = 0;

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Check if input log signature must be backed up. */
	if (files->internal.backupSig) {
		/* Create a backup of the input log signature file by renaming it. */
		logksi_file_close(&files->files.inSig);
		res = logksi_remove_file(files->internal.backupSig);
		ERR_CATCH_MSG(err, res, "Error: could not remove existing backup file %s.", files->internal.backupSig);
		if (rename(files->internal.inSig, files->internal.backupSig) != 0) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: could not rename input log signature file %s to backup file %s.", files->internal.inSig, files->internal.backupSig);
		}
		/* Output must be saved in input log signature file, so the temporary file is renamed. */
		logksi_file_close(&files->files.outSig);
		if (rename(files->internal.tempSig, files->internal.inSig) != 0) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: could not rename temporary file %s to input log signature file %s.", files->internal.tempSig, files->internal.inSig);
		}
	} else if (files->internal.tempSig) {
		logksi_file_close(&files->files.inSig);
		res = logksi_remove_file(files->internal.outSig);
		ERR_CATCH_MSG(err, res, "Error: could not remove existing output log signature file %s.", files->internal.outSig);
		/* Output must be saved in output log signature file, so the temporary file is renamed. */
		logksi_file_close(&files->files.outSig);
		if (rename(files->internal.tempSig, files->internal.outSig) != 0) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: could not rename temporary file %s to output log signature file %s.", files->internal.tempSig, files->internal.outSig);
		}
	} else if (files->internal.bStdout) {
		/* Copy the contents of the (nameless) temporary output log signature file to stdout. */
		if (files->files.outSig == NULL) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: could not access temporary output log signature file in read mode.");
		}
		if (fseek(files->files.outSig, 0, SEEK_SET) != 0) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: could not seek temporary output log signature file.");
		}
		while(!feof(files->files.outSig)) {
			count = fread(buf, 1, sizeof(buf), files->files.outSig);
			if (fwrite(buf, 1, count, stdout) != count) {
				res = KT_IO_ERROR;
				ERR_CATCH_MSG(err, res, "Error: could not write temporary output log signature file to stdout.");
			}
		}
	}

	logksi_filename_free(&files->internal.backupSig);
	res = KT_OK;

cleanup:

	/* Restore initial situation if something failed. */
	if (files && files->internal.backupSig) {
		if (!SMART_FILE_doFileExist(files->internal.inSig)) {
			if (rename(files->internal.backupSig, files->internal.inSig) != 0) {
				res = KT_IO_ERROR;
			}
		}
	}
	return res;
}

static void close_input_and_output_files(ERR_TRCKR *err, int res, IO_FILES *files) {
	if (files) {
		logksi_files_close(&files->files);
		if (files->internal.tempSig && res != KT_OK) {
			if (remove(files->internal.tempSig) != 0) {
				if (err) ERR_TRCKR_ADD(err, KT_IO_ERROR, "Error: could not remove temporary output log signature %s.", files->internal.tempSig);
			}
		}
		logksi_internal_filenames_free(&files->internal);
	}
}
