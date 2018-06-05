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
static int rename_temporary_and_backup_files(ERR_TRCKR *err, IO_FILES *files);
static void close_log_and_signature_files(ERR_TRCKR *err, int res, IO_FILES *files);

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

	memset(&files, 0, sizeof(files));

	/**
	 * Extract command line parameters and also add configuration specific parameters.
	 */
	res = PARAM_SET_new(
			CONF_generate_param_set_desc("{input}{log-from-stdin}{sig-from-stdin}{o}{out-log}{out-proof}{r}{d}{log}{h|help}", "", buf, sizeof(buf)),
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

	files.user.bStdinLog = PARAM_SET_isSetByName(set, "log-from-stdin");
	files.user.bStdinSig = PARAM_SET_isSetByName(set, "sig-from-stdin");

	res = PARAM_SET_getValueCount(set, "input", NULL, PST_PRIORITY_NONE, &count);
	if (res != KT_OK) goto cleanup;

	/* Either log or signature is from stdin, but not both. */
	if (files.user.bStdinLog) {
		res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_NONE, 0, &files.user.inSig);
		if (res != KT_OK) goto cleanup;
	} else if (files.user.bStdinSig) {
		res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_NONE, 0, &files.user.inLog);
		if (res != KT_OK) goto cleanup;
	} else {
		res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_NONE, 0, &files.user.inLog);
		if (res != KT_OK) goto cleanup;
		if (count > 1) {
			res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_NONE, 1, &files.user.inSig);
			if (res != KT_OK) goto cleanup;
		}
	}

	res = PARAM_SET_getStr(set, "out-log", NULL, PST_PRIORITY_NONE, 0, &files.user.outLog);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = PARAM_SET_getStr(set, "out-proof", NULL, PST_PRIORITY_NONE, 0, &files.user.outProof);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_NONE, 0, &files.user.outBase);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = generate_filenames(err, &files);
	if (res != KT_OK) goto cleanup;

	res = open_log_and_signature_files(err, &files);
	if (res != KT_OK) goto cleanup;

	res = logsignature_extract(set, err, ksi, &files);
	if (res != KT_OK) goto cleanup;

	res = rename_temporary_and_backup_files(err, &files);
	if (res != KT_OK) goto cleanup;

cleanup:

	close_log_and_signature_files(err, res, &files);

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
		" %s extract <logfile> [<logfile.logsig>] [-o <outfile>] -r <records> [more_options]\n"
		" %s extract --log-from-stdin <logfile.logsig> -o <outfile> -r <records> [more_options]\n"
		" %s extract --sig-from-stdin <logfile> [-o <outfile>] -r <records> [more_options]\n"
		"\n"
		" <logfile>\n"
		"           - Log file from where to extract log records.\n"
		" <logfile.logsig>\n"
		"             Log signature file from where to extract the KSI signature for integrity proof.\n"
		"             If omitted, the log signature file name is derived by adding .logsig to <logfile>.\n"
		"             It is expected to be found in the same folder as the <logfile>.\n"
		" --log-from-stdin\n"
		"             The log file is read from stdin. Cannot be used with --sig-from-stdin.\n"
		"             If --log-from-stdin is used, the log signature file name must be specified explicitly.\n"
		" --sig-from-stdin\n"
		"             The log signature file is read from stdin. Cannot be used with --log-from-stdin.\n"
		"             If --sig-from-stdin is used, the log file name must be specified explicitly.\n"
		" -o <outfile>\n"
		"             Names of the output files will be derived from <outfile> by adding the appropriate suffixes.\n"
		"             Name of the excerpt file will be <outfile.excerpt>.\n"
		"             Name of the integrity proof file will be <outfile.excerpt.logsig>.\n"
		"             If <outfile> is not specified, names of the output files will be derived from <logfile>.\n"
		"             <outfile> must be specified if the log file is read from stdin.\n"
		" --out-log <log.records>\n"
		"             Name of the output log records file. '-' can be used to redirect the file to stdout.\n"
		"             If <log.records> is not specified, the name is derived from either <outfile> or <logfile>.\n"
		" --out-proof <integrity.proof>\n"
		"             Name of the output integrity proof file. '-' can be used to redirect the file to stdout.\n"
		"             If <integrity.proof> is not specified, the name is derived from either <outfile> or <logfile>.\n"
		" -r <records>\n"
		"             Positions of log records to be extraced, given as a list of ranges.\n"
		"             Example: -r 12-18,21,88-192\n"
		"             List of positions must be given in a strictly ascending order using positive decimal numbers.\n"
		" -d\n"
		"           - Print detailed information about processes and errors to stderr.\n"
		" --log <file>\n"
		"           - Write libksi log to the given file. Use '-' as file name to redirect the log to stdout.\n",
		TOOL_getName(),
		TOOL_getName(),
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
	PARAM_SET_addControl(set, "{log}{out-log}{out-proof}{o}", isFormatOk_path, NULL, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{input}", isFormatOk_inputFile, NULL, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{log-from-stdin}{sig-from-stdin}{d}", isFormatOk_flag, NULL, NULL, NULL);
	PARAM_SET_addControl(set, "{r}", isFormatOk_string, NULL, NULL, NULL);

	PARAM_SET_setParseOptions(set, "input", PST_PRSCMD_COLLECT_LOOSE_VALUES | PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS);
	PARAM_SET_setParseOptions(set, "d", PST_PRSCMD_HAS_NO_VALUE | PST_PRSCMD_NO_TYPOS);
	PARAM_SET_setParseOptions(set, "r", PST_PRSCMD_HAS_VALUE | PST_PRSCMD_NO_TYPOS);
	PARAM_SET_setParseOptions(set, "log-from-stdin,sig-from-stdin", PST_PRSCMD_HAS_NO_VALUE);


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

static int generate_filenames(ERR_TRCKR *err, IO_FILES *files) {
	int res;
	IO_FILES tmp;

	memset(&tmp.internal, 0, sizeof(tmp.internal));

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (files->user.inLog) {
		res = duplicate_name(files->user.inLog, &tmp.internal.inLog);
		ERR_CATCH_MSG(err, res, "Error: Could not duplicate input log file name.");
		/* If input log signature file name is not specified, it is generared from the input log file name. */
		if (files->user.inSig == NULL) {
			/* Generate input log signature file name. */
			res = concat_names(files->user.inLog, ".logsig", &tmp.internal.inSig);
			ERR_CATCH_MSG(err, res, "Error: Could not generate input log signature file name.");
		}
	}

	if (files->user.inSig) {
		res = duplicate_name(files->user.inSig, &tmp.internal.inSig);
		ERR_CATCH_MSG(err, res, "Error: Could not duplicate input log signature file name.");
	}

	if (files->user.outLog) {
		if (!strcmp(files->user.outLog, "-")) {
			tmp.internal.bStdoutLog = 1;
		} else {
			res = duplicate_name(files->user.outLog, &tmp.internal.outLog);
			ERR_CATCH_MSG(err, res, "Error: Could not duplicate output log records file name.");
		}
	} else if (files->user.outBase) {
		if (!strcmp(files->user.outBase, "-")) {
			res = KT_INVALID_CMD_PARAM;
			ERR_CATCH_MSG(err, res, "Error: Both output files cannot be redirected to stdout.");
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
		if (!strcmp(files->user.outProof, "-")) {
			tmp.internal.bStdoutProof = 1;
		} else {
			res = duplicate_name(files->user.outProof, &tmp.internal.outProof);
			ERR_CATCH_MSG(err, res, "Error: Could not duplicate output integrity proof file name.");
		}
	} else if (files->user.outBase) {
		if (!strcmp(files->user.outBase, "-")) {
			res = KT_INVALID_CMD_PARAM;
			ERR_CATCH_MSG(err, res, "Error: Both output files cannot be redirected to stdout.");
		} else {
			res = concat_names(files->user.outBase, ".excerpt.logsig", &tmp.internal.outProof);
			ERR_CATCH_MSG(err, res, "Error: Could not generate output log records file name.");
		}
	} else {
		if (files->user.inLog) {
			res = concat_names(files->user.inLog, ".excerpt.logsig", &tmp.internal.outProof);
			ERR_CATCH_MSG(err, res, "Error: Could not generate output integrity proof file name.");
		} else {
			res = KT_INVALID_CMD_PARAM;
			ERR_CATCH_MSG(err, res, "Error: Output integrity proof file name must be specified if log file is read from stdin.");
		}
	}

	if (tmp.internal.bStdoutLog && tmp.internal.bStdoutProof) {
		res = KT_INVALID_CMD_PARAM;
		ERR_CATCH_MSG(err, res, "Error: Both output files cannot be redirected to stdout.");
	}

	if(!tmp.internal.bStdoutLog) {
		res = temp_name(tmp.internal.outLog, &tmp.internal.tempLog);
		ERR_CATCH_MSG(err, res, "Error: Could not generate temporary output log records file name.");
	}

	if (!tmp.internal.bStdoutProof) {
		res = temp_name(tmp.internal.outProof, &tmp.internal.tempProof);
		ERR_CATCH_MSG(err, res, "Error: Could not generate temporary output integrity proof file name.");
	}

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

	if (files->user.bStdinLog) {
		tmp.files.inLog = stdin;
	} else {
		res = logksi_file_check_and_open(err, files->internal.inLog, &tmp.files.inLog);
		if (res != KT_OK) goto cleanup;
	}

	if (files->user.bStdinSig) {
		tmp.files.inSig = stdin;
	} else {
		res = logksi_file_check_and_open(err, files->internal.inSig, &tmp.files.inSig);
		if (res != KT_OK) goto cleanup;
	}

	res = logksi_file_create_temporary(files->internal.tempLog, &tmp.files.outLog, files->internal.bStdoutLog);
	ERR_CATCH_MSG(err, res, "Error: Could not create temporary output log records file.");

	res = logksi_file_create_temporary(files->internal.tempProof, &tmp.files.outProof, files->internal.bStdoutProof);
	ERR_CATCH_MSG(err, res, "Error: Could not create temporary output integrity proof file.");

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

	if (files->internal.tempLog) {
		/* Output must be saved in log records file, so the temporary file is renamed. */
		logksi_file_close(&files->files.outLog);
		res = logksi_file_rename(files->internal.tempLog, files->internal.outLog);
		ERR_CATCH_MSG(err, res, "Error: Could not rename temporary file %s to output log records file %s.", files->internal.tempLog, files->internal.outLog);
	} else if (files->internal.bStdoutLog) {
		res = logksi_file_redirect_to_stdout(files->files.outLog);
		ERR_CATCH_MSG(err, res, "Error: Could not write temporary output log records file to stdout.");
	}

	if (files->internal.tempProof) {
		/* Output must be saved in integrity proof file, so the temporary file is renamed. */
		logksi_file_close(&files->files.outProof);
		res = logksi_file_rename(files->internal.tempProof, files->internal.outProof);
		ERR_CATCH_MSG(err, res, "Error: Could not rename temporary file %s to output integrity proof file %s.", files->internal.tempProof, files->internal.outProof);
	} else if (files->internal.bStdoutProof) {
		res = logksi_file_redirect_to_stdout(files->files.outProof);
		ERR_CATCH_MSG(err, res, "Error: Could not write temporary output integrity proof file to stdout.");
	}

	res = KT_OK;

cleanup:

	return res;
}

static void close_log_and_signature_files(ERR_TRCKR *err, int res, IO_FILES *files) {
	if (files) {
		logksi_files_close(&files->files);
		if (files->internal.tempLog && res != KT_OK) {
			if (remove(files->internal.tempLog) != 0) {
				if (err) ERR_TRCKR_ADD(err, KT_IO_ERROR, "Error: Could not remove temporary log records file %s.", files->internal.tempLog);
			}
		}
		if (files->internal.tempProof && res != KT_OK) {
			if (remove(files->internal.tempProof) != 0) {
				if (err) ERR_TRCKR_ADD(err, KT_IO_ERROR, "Error: Could not remove temporary integrity proof file %s.", files->internal.tempProof);
			}
		}
		logksi_internal_filenames_free(&files->internal);
	}
}
