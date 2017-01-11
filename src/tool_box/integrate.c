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

#include <string.h>
#include <ksi/ksi.h>
#include <ksi/compatibility.h>
#include "param_set/param_set.h"
#include "param_set/task_def.h"
#include "param_set/parameter.h"
#include "tool_box/ksi_init.h"
#include "tool_box/param_control.h"
#include "tool_box/task_initializer.h"
#include "smart_file.h"
#include "ksitool_err.h"
#include "conf_file.h"
#include "api_wrapper.h"
#include "printer.h"
#include "debug_print.h"
#include "tool.h"
#include "rsyslog.h"

static int generate_tasks_set(PARAM_SET *set, TASK_SET *task_set);
static int open_input_and_output_files(ERR_TRCKR *err, IO_FILES *files);
static void close_input_and_output_files(int result, IO_FILES *files);

int integrate_run(int argc, char **argv, char **envp) {
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
			CONF_generate_param_set_desc("{input}{o}{d}{log}{h|help}", "", buf, sizeof(buf)),
			&set);
	if (res != KT_OK) goto cleanup;

	res = TASK_SET_new(&task_set);
	if (res != PST_OK) goto cleanup;

	res = generate_tasks_set(set, task_set);
	if (res != PST_OK) goto cleanup;

	res = TASK_INITIALIZER_getServiceInfo(set, argc, argv, envp);
	if (res != PST_OK) goto cleanup;

	res = TASK_INITIALIZER_check_analyze_report(set, task_set, 0.5, 0.1, &task);
	if (res != KT_OK) goto cleanup;

	res = TOOL_init_ksi(set, &ksi, &err, &logfile);
	if (res != KT_OK) goto cleanup;

	d = PARAM_SET_isSetByName(set, "d");

	res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files.partsPathName);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files.outSigName);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = open_input_and_output_files(err, &files);
	if (res != KT_OK) goto cleanup;

	res = logsignature_integrate(set, err, ksi, &files);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	close_input_and_output_files(res, &files);
	print_progressResult(res);

	KSITOOL_KSI_ERRTrace_save(ksi);

	if (res != KT_OK) {
		if (ERR_TRCKR_getErrCount(err) == 0) {ERR_TRCKR_ADD(err, res, NULL);}
		KSITOOL_KSI_ERRTrace_LOG(ksi);

		print_errors("\n");
		if (d) ERR_TRCKR_printExtendedErrors(err);
		else  ERR_TRCKR_printErrors(err);
	}

	SMART_FILE_close(logfile);
	PARAM_SET_free(set);
	TASK_SET_free(task_set);
	ERR_TRCKR_free(err);
	KSI_CTX_free(ksi);

	return KSITOOL_errToExitCode(res);
}

char *integrate_help_toString(char *buf, size_t len) {
	size_t count = 0;

	count += KSI_snprintf(buf + count, len - count,
		"Usage:\n"
		" %s integrate <logfile> [-o <logfile.logsig>]\n",
		TOOL_getName()
	);

	return buf;
}

const char *integrate_get_desc(void) {
	return "Integrates individual log signature blocks and KSI signatures into a single file.";
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
	PARAM_SET_addControl(set, "{input}", isFormatOk_path, NULL, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{log}{o}", isFormatOk_inputFile, NULL, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{d}", isFormatOk_flag, NULL, NULL, NULL);

	PARAM_SET_setParseOptions(set, "input", PST_PRSCMD_COLLECT_LOOSE_VALUES | PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS);

	/**
	 * Define possible tasks.
	 */
	/*					  ID	DESC													MAN			ATL		FORBIDDEN		IGN	*/
	TASK_SET_add(task_set, 0,	"Integrate log signature block with KSI signature.",	"input",	NULL,	NULL,			NULL);

	res = KT_OK;

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

static int open_input_and_output_files(ERR_TRCKR *err, IO_FILES *files) {
	int res = KT_IO_ERROR;
	IO_FILES tmp;

	memset(&tmp, 0, sizeof(tmp));

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = get_derived_name(files->partsPathName, ".logsig.parts/blocks.dat", &tmp.partsBlockName);
	ERR_CATCH_MSG(err, res, "Error: out of memory.");

	if (!SMART_FILE_doFileExist(tmp.partsBlockName)) {
		res = KT_KSI_SIG_VER_IMPOSSIBLE;
		ERR_CATCH_MSG(err, res, "Error: unable to find block file %s.", tmp.partsBlockName);
	}

	res = get_derived_name(files->partsPathName, ".logsig.parts/block-signatures.dat", &tmp.partsSigName);
	ERR_CATCH_MSG(err, res, "Error: out of memory.");

	if (files->outSigName == NULL) {
		res = get_derived_name(files->partsPathName, ".logsig", &tmp.integratedSigName);
		ERR_CATCH_MSG(err, res, "Error: out of memory");
		tmp.outSigName = tmp.integratedSigName;
	} else {
		tmp.outSigName = files->outSigName;
	}

	tmp.inBlockFile = fopen(tmp.partsBlockName, "rb");
	res = (tmp.inBlockFile == NULL) ? KT_IO_ERROR : KT_OK;
	ERR_CATCH_MSG(err, res, "Error: could not open file %s.", tmp.partsBlockName);

	tmp.inSigFile = fopen(tmp.partsSigName, "rb");
	res = (tmp.inSigFile == NULL) ? KT_IO_ERROR : KT_OK;
	ERR_CATCH_MSG(err, res, "Error: could not open file %s.", tmp.partsSigName);

	tmp.outSigFile = fopen(tmp.outSigName, "wb");
	res = (tmp.outSigFile == NULL) ? KT_IO_ERROR : KT_OK;
	ERR_CATCH_MSG(err, res, "Error: could not open file %s.", tmp.outSigName);

	tmp.partsPathName = files->partsPathName;
	tmp.outSigName = files->outSigName;
	*files = tmp;
	memset(&tmp, 0, sizeof(tmp));
	res = KT_OK;

cleanup:

	if (tmp.partsBlockName) {
		KSI_free(tmp.partsBlockName);
	}
	if (tmp.partsSigName) {
		KSI_free(tmp.partsSigName);
	}
	if (tmp.integratedSigName) {
		KSI_free(tmp.integratedSigName);
	}

	if (tmp.inBlockFile) fclose(tmp.inBlockFile);
	if (tmp.inSigFile) fclose(tmp.inSigFile);
	if (tmp.outSigFile) fclose(tmp.outSigFile);

	return res;
}

static void close_input_and_output_files(int result, IO_FILES *files) {
	if (files == NULL) return;
	if (files->partsBlockName) {
		KSI_free(files->partsBlockName);
	}
	if (files->partsSigName) {
		KSI_free(files->partsSigName);
	}
	if (files->integratedSigName) {
		if (result != KT_OK) {
			if (files->outSigFile) {
				fclose(files->outSigFile);
				files->outSigFile = NULL;
				remove(files->integratedSigName);
			}
		}
		KSI_free(files->integratedSigName);
	}

	if (files->inBlockFile) fclose(files->inBlockFile);
	if (files->inSigFile) fclose(files->inSigFile);
	if (files->outSigFile) fclose(files->outSigFile);
}
