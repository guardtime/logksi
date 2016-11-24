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
#include <ksi/blocksigner.h>
#include "param_set/param_set.h"
#include "param_set/task_def.h"
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

typedef struct SIGNING_AGGR_ROUND_st {
	/* Aggregation round block-signer. */
	KSI_BlockSigner *block_signer;
	 /* Block signer handles for aggregation round. */
	KSI_BlockSignerHandleList *bs_handleList;

	 /* A list of hash values. */
	KSI_DataHash **hash_values;

	 /* A list of file names to be used to save the signature file. */
	char **fname;
	char **fname_out;

	 /* Count of hash values used in aggreation round. */
	size_t hash_count_max;
	size_t hash_count;
} SIGNING_AGGR_ROUND;

static int generate_tasks_set(PARAM_SET *set, TASK_SET *task_set);
static char* get_output_file_name(PARAM_SET *set, ERR_TRCKR *err, int how_is_saved, int i, char *buf, size_t buf_len);
static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err);
static int check_hash_algo_errors(PARAM_SET *set, ERR_TRCKR *err);
static int check_io_naming_and_type_errors(PARAM_SET *set, ERR_TRCKR *err);
static int how_is_output_saved_to(PARAM_SET *set);
static void SIGNING_AGGR_ROUND_free(SIGNING_AGGR_ROUND *obj);
static void SIGNING_AGGR_ROUND_ARRAY_free(SIGNING_AGGR_ROUND **array);
static int KT_SIGN_getMaximumInputsPerRound(PARAM_SET *set, ERR_TRCKR *err, size_t *inputs);
static int KT_SIGN_getAggregationRoundsNeeded(PARAM_SET *set, ERR_TRCKR *err, size_t max_tree_inputs, size_t *rounds);
static int KT_SIGN_performSigning(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ctx, size_t max_tree_inputs, size_t rounds, SIGNING_AGGR_ROUND ***aggr_rounds_record);
static int KT_SIGN_saveToOutput(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, SIGNING_AGGR_ROUND **aggr_round);
static int KT_SIGN_getMetadata(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, size_t seq_offset, KSI_MetaData **mdata);
static int KT_SIGN_dump(PARAM_SET *set, ERR_TRCKR *err, SIGNING_AGGR_ROUND **aggr_round);

int sign_run(int argc, char** argv, char **envp) {
	int res;
	char buf[2048];
	PARAM_SET *set = NULL;
	TASK_SET *task_set = NULL;
	TASK *task = NULL;
	KSI_CTX *ksi = NULL;
	ERR_TRCKR *err = NULL;
	SMART_FILE *logfile = NULL;
	SIGNING_AGGR_ROUND **aggr_rounds = NULL;
	int d = 0;
	size_t max_tree_input = 0;
	size_t rounds = 0;

	/**
	 * Extract command line parameters.
	 */
	res = PARAM_SET_new(
			CONF_generate_param_set_desc("{sign}{i}{input}{o}{H}{data-out}{d}{dump}{log}{conf}{h|help}{dump-last-leaf}{prev-leaf}{mdata}{mask}{show-progress}", "S", buf, sizeof(buf)),
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

	res = check_hash_algo_errors(set, err);
	if (res != KT_OK) goto cleanup;

	res = check_io_naming_and_type_errors(set, err);
	if (res != KT_OK) goto cleanup;

	/**
	 * If everything OK, run the task.
	 */
	res = KT_SIGN_getMaximumInputsPerRound(set, err, &max_tree_input);
	if (res != KT_OK) goto cleanup;

	res = KT_SIGN_getAggregationRoundsNeeded(set, err, max_tree_input, &rounds);
	if (res != KT_OK) goto cleanup;

	res = KT_SIGN_performSigning(set, err, ksi, max_tree_input, rounds, &aggr_rounds);
	if (res != KT_OK) goto cleanup;

	res = KT_SIGN_saveToOutput(set, err, ksi, aggr_rounds);
	if (res != KT_OK) goto cleanup;

	/**
	 * If signature was created without errors print some info on demand.
	 */
	res = KT_SIGN_dump(set, err, aggr_rounds);
	if (res != KT_OK) goto cleanup;

cleanup:
	print_progressResult(res);
	KSITOOL_KSI_ERRTrace_save(ksi);

	if (res != KT_OK) {
		if (ERR_TRCKR_getErrCount(err) == 0) {ERR_TRCKR_ADD(err, res, NULL);}
		KSITOOL_KSI_ERRTrace_LOG(ksi);

		print_errors("\n");
		if (d) 	ERR_TRCKR_printExtendedErrors(err);
		else 	ERR_TRCKR_printErrors(err);
	}

	SIGNING_AGGR_ROUND_ARRAY_free(aggr_rounds);
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
		" %s sign -S <URL> [--aggr-user <user> --aggr-key <key>] [-H <alg>]\n"
		"          [--data-out <file>] [more_options] [-i <input>]... [<input>]...\n"
		"          [-- [<only file input>]...] [-o <out.ksig>]...\n"
		"\n"
		"\n"
		" -i <input>\n"
		"           - The input is either the path to the file to be hashed and signed\n"
		"             or a hash imprint in the case the data to be signed has been hashed\n"
		"             already. Use '-' as file name to read data to be hashed from stdin.\n"
		"             Hash imprint format: <alg>:<hash in hex>.\n\n"
		"             Flag -i can be omitted when specifying the input. To interpret all\n"
		"             inputs as regular files no matter what the file's name is see\n"
		"             parameter --.\n"
		" -o <out.ksig>\n"
		"           - Output file path for the signature. Use '-' as file name to\n"
		"             redirect signature binary stream to stdout. If not specified the\n"
		"             output is saved to the same directory where the input file is\n"
		"             located. When specified as directory all the signatures are saved\n"
		"             there. When signature's output file name is not explicitly\n"
		"             specified the signature is saved to <input file>.ksig\n"
		"             (or <input file>_<nr>.ksig, where <nr> is auto-incremented counter\n"
		"             if the output file already exists). When there are N x input and\n"
		"             explicitly specified N x output every signature is saved to the\n"
		"             corresponding path. If output file name is explicitly specified,\n"
		"             will always overwrite the existing file.\n"
		" -H <alg> \n"
		"           - Use the given hash algorithm to hash the file to be signed.\n"
		"             Use ksi -h to get the list of supported hash algorithms.\n"
		" -S <URL>  - Signing service (KSI Aggregator) URL.\n"
		" --aggr-user <str>\n"
		"           - Username for signing service.\n"
		" --aggr-key <str>\n"
		"           - HMAC key for signing service.\n"
		" --data-out <file>\n"
		"           - Save signed data to file. Use when signing an incoming stream.\n"
		"             Use '-' as file name to redirect data being hashed to stdout.\n"

		" --max-lvl <int>\n"
		"           - Set the maximum depth (0 - 255) of the local aggregation tree\n"
		"             (default 0).\n"
		" --max-aggr-rounds <int>\n"
		"           - Set the upper limit of local aggregation rounds that may be\n"
		"             performed (default 1).\n"
		" --mask [<hex | alg:[arg...]>]\n"
		"           - Specify a hex string to initialize and apply the masking process,\n"
		"             or algorithm to generate the initial value instead.\n"
		"             Supported algorithms:\n\n"
		"               * crand:seed,len - Use standard C rand() function to generate\n"
		"                 array of random numbers with the given seed and length. The\n"
		"                 seed value is unsigned 32bit integer or 'time' to use the\n"
		"                 system time value instead. If function is specified without the\n"
		"                 arguments (crand:) 'time' is used to generate random array with\n"
		"                 size of 32 bytes.\n\n"
		"             When mask is specified without the argument (--mask) 'crand:' is\n"
		"             used as default.\n"
		" --prev-leaf <alg>:<hash>\n"
		"           - Specify the hash imprint of the last leaf from another local\n"
		"             aggregation tree to link it with the current first local\n"
		"             aggregation round. Is valid only with option --mask.\n"
		" --mdata   - Embed metadata to the KSI signature. To configure metadata at lest\n"
		"             --mdata-cli-id must be specified.\n"
		" --mdata-cli-id <str>\n"
		"           - Specify client id as a string that will be embedded into the\n"
		"             signature as metadata. It is mandatory part of the metadata.\n"
		" --mdata-mac-id <str>\n"
		"           - Specify machine id as a string that will be embedded into the\n"
		"             signature as metadata. It is optional part of metadata.\n"
		" --mdata-sqn-nr <int>\n"
		"           - Specify incremental (sequence number is incremented in every\n"
		"             aggregation round) sequence number of the request as integer\n"
		"             that will be embedded into the signature as metadata. It is\n"
		"             optional part of metadata.\n"
		" --mdata-req-tm <int>\n"
		"           - Embed request time extracted from the machine clock into the\n"
		"             signature as metadata. It is optional part of metadata.\n"
		" --        - If used everything specified after the token is interpreted as\n"
		"             input file (command-line parameters (e.g. --conf, -d), stdin (-)\n"
		"             and pre-calculated hash imprints (SHA-256:7647c6...) are all\n"
		"             interpreted as regular files).\n"
		" -d        - Print detailed information about processes and errors to stderr.\n"
		" --dump    - Dump signature(s) created in human-readable format to stdout.\n"
		" --show-progress\n"
		"           - Show progress bar. Is only valid with -d.\n"
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
	int extra_parse_flags = 0;

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
	PARAM_SET_addControl(set, "{o}{data-out}{log}", isFormatOk_path, NULL, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{i}", isFormatOk_inputHash, isContentOk_inputHash, convertRepair_path, extract_inputHash);
	PARAM_SET_addControl(set, "{input}", isFormatOk_inputFile, isContentOk_inputFile, convertRepair_path, extract_inputHashFromFile);
	PARAM_SET_addControl(set, "{H}", isFormatOk_hashAlg, isContentOk_hashAlg, NULL, extract_hashAlg);
	PARAM_SET_addControl(set, "{prev-leaf}", isFormatOk_imprint, isContentOk_imprint, NULL, extract_imprint);
	PARAM_SET_addControl(set, "{d}{dump}{dump-last-leaf}{mdata}{show-progress}", isFormatOk_flag, NULL, NULL, NULL);
	PARAM_SET_addControl(set, "{mask}", isFormatOk_mask, isContentOk_mask, convertRepair_mask, extract_mask);
	PARAM_SET_setParseOptions(set, "{d}{dump}{dump-last-leaf}{mdata}{show-progress}", PST_PRSCMD_HAS_NO_VALUE);

	/**
	 * To enable wildcard characters (WC) to work on Windows, configure the WC
	 * expander function and set parsing flag that enables WC parsing after all
	 * values from command-line are read.
	 */
#ifdef _WIN32
	res = PARAM_SET_wildcardExpander(set, "i,input", NULL, Win32FileWildcard);
	extra_parse_flags = PST_PRSCMD_EXPAND_WILDCARD;
#endif

	/**
	 * Make the parameter -i collect:
	 * 1) All values that are exactly after -i (both a and -i are collected -i a, -i -i)
	 * 2) all values that are not potential parameters (unknown / typo) parameters (will ignore -q, --test)
	 * Make the parameter input collect all values after the parsing is closed.
	 * 1) All values that are specified after --.
	 */
	PARAM_SET_setParseOptions(set, "i", PST_PRSCMD_HAS_VALUE | PST_PRSCMD_COLLECT_LOOSE_VALUES | extra_parse_flags);
	PARAM_SET_setParseOptions(set, "input", PST_PRSCMD_CLOSE_PARSING | PST_PRSCMD_COLLECT_WHEN_PARSING_IS_CLOSED | PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS | extra_parse_flags);

	/**
	 * Add some default values.
	 */

	res = PARAM_SET_add(set, "max-aggr-rounds", "1", "default", PRIORITY_KSI_DEFAULT);
	res = PARAM_SET_add(set, "max-lvl", "0", "default", PRIORITY_KSI_DEFAULT);

	/*					  ID	DESC										MAN				ATL			FORBIDDEN	IGN	*/
	TASK_SET_add(task_set, 0,	"Sign data.",								"S",			"i,input",	"H,data-out",		NULL);
	TASK_SET_add(task_set, 1,	"Sign data, specify hash alg.",				"S,H",			"i,input",	"data-out",		NULL);
	TASK_SET_add(task_set, 2,	"Sign and save data.",						"S,data-out",	"i,input",	"H",		NULL);
	TASK_SET_add(task_set, 3,	"Sign and save data, specify hash alg.",	"S,H,data-out", "i,input",	NULL,		NULL);

cleanup:

	return res;
}

static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err) {
	int res;

	res = get_pipe_out_error(set, err, "o", "data-out,log", "dump");
	if (res != KT_OK) goto cleanup;

	res = get_pipe_in_error(set, err, "i", NULL, NULL);
	if (res != KT_OK) goto cleanup;

cleanup:
	return res;
}

static int check_hash_algo_errors(PARAM_SET *set, ERR_TRCKR *err) {
	int res;
	char *i_value = NULL;
	int count_i = 0;
	int count_input = 0;
	int imprint_count = 0;
	int i = 0;

	/**
	 * Check if Hash algorithm is specified. If not there can't be Hash algorithm
	 * errors.
	 */
	if (!PARAM_SET_isSetByName(set, "H")) {
		res = KT_OK;
		goto cleanup;
	}

	res = PARAM_SET_getValueCount(set, "input", NULL, PST_PRIORITY_NONE, &count_input);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	/**
	 * Check if there are some regular files that can be signed with user
	 * specified hash algorithms.
	 */
	if (count_input > 0) {
		res = KT_OK;
		goto cleanup;
	}

	res = PARAM_SET_getValueCount(set, "i", NULL, PST_PRIORITY_NONE, &count_i);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	for (i = 0; i < count_i; i++) {
		res = PARAM_SET_getStr(set, "i", NULL, PST_PRIORITY_NONE, i, &i_value);
		if (res != KT_OK) goto cleanup;

		if (is_imprint(i_value)) imprint_count++;
	}

	if (count_i == imprint_count) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: Unable to use -H as all inputs are pre-calculated hash imprints.");
		goto cleanup;
	}

	res = KT_OK;

cleanup:

	return res;
}

enum OUTPUT_TYPE {
	OUTPUT_SPECIFIED_FILE = 0x01,
	OUTPUT_TO_STDOUT,
	OUTPUT_TO_DIR,
	OUTPUT_NEXT_TO_INPUT,
	OUTPUT_UNKNOWN
};

static int how_is_output_saved_to(PARAM_SET *set) {
	int res;
	int ret = OUTPUT_UNKNOWN;
	int in_count = 0;
	int out_count = 0;
	char *out_file = NULL;

	if (set == NULL) goto cleanup;

	res = PARAM_SET_getValueCount(set, "i,input", NULL, PST_PRIORITY_NONE, &in_count);
	if (res != PST_OK) goto cleanup;

	res = PARAM_SET_getValueCount(set, "o", NULL, PST_PRIORITY_NONE, &out_count);
	if (res != PST_OK) goto cleanup;

	res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_NONE, 0, &out_file);
	if (res != PST_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	if (in_count == 1 && out_count == 1 && strcmp(out_file, "-") == 0) return OUTPUT_TO_STDOUT;
	else if (out_count != 1 && in_count == out_count) return OUTPUT_SPECIFIED_FILE;
	else if (out_count == 1 && !SMART_FILE_isFileType(out_file, SMART_FILE_TYPE_DIR) && in_count == out_count) return OUTPUT_SPECIFIED_FILE;
	else if (out_count == 1 && SMART_FILE_isFileType(out_file, SMART_FILE_TYPE_DIR)) return OUTPUT_TO_DIR;
	else if (out_count == 0) return OUTPUT_NEXT_TO_INPUT;

cleanup:

	return ret;
}

static int check_io_naming_and_type_errors(PARAM_SET *set, ERR_TRCKR *err) {
	int res;
	int in_count = 0;
	int in_count_i = 0;
	int out_count = 0;
	int i = 0;
	char *fname_in = NULL;
	char *fname_out = NULL;
	char *data_out = NULL;


	if (set == NULL || err == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/**
	 * Get the count of inputs and outputs for error handling.
	 */

	res = PARAM_SET_getValueCount(set, "i,input", NULL, PST_PRIORITY_NONE, &in_count);
	if (res != PST_OK) goto cleanup;

	res = PARAM_SET_getValueCount(set, "i", NULL, PST_PRIORITY_NONE, &in_count_i);
	if (res != PST_OK) goto cleanup;

	res = PARAM_SET_getValueCount(set, "o", NULL, PST_PRIORITY_NONE, &out_count);
	if (res != PST_OK) goto cleanup;

	res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_NONE, 0, &fname_out);
	if (res != PST_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = PARAM_SET_getStr(set, "data-out", NULL, PST_PRIORITY_NONE, 0, &data_out);
	if (res != PST_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	if (in_count > 1 && data_out != NULL) {
		int is_data_out_stream = strcmp(data_out, "-") == 0;
		ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: It is not possible redirect multiple inputs (-i) to %s%s%s (--data-out).",
				is_data_out_stream ? "" : "'",
				is_data_out_stream ? "stdout" : data_out,
				is_data_out_stream ? "" : "'"
				);
		goto cleanup;
	}

	/**
	 * Examine if there is something wrong with the output.
	 */

	if (out_count > 1 && in_count > out_count) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: Not enough output parameters specified to store all signatures to corresponding file.");
		goto cleanup;
	}

	if (out_count > in_count) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: More output parameters specified than the count of input parameters.");
		goto cleanup;
	}

	if (out_count == 1 && in_count > 1) {
		if (!SMART_FILE_isFileType(fname_out, SMART_FILE_TYPE_DIR)) {
			ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: Only one output parameter specified, that is not directory, for multiple signatures.");
			goto cleanup;
		}
	}

	for (i = 0; out_count > 1 && i < out_count; i++) {
		res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_NONE, i, &fname_out);
		if (res != PST_OK) goto cleanup;

		if (SMART_FILE_isFileType(fname_out, SMART_FILE_TYPE_DIR)) {
			ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: There are multiple outputs specified and one output is directory '%s'.", fname_out);
			goto cleanup;
		}
	}

	/**
	 * Check if there is something wrong with the input.
	 */

	for (i = 0; i < in_count; i++) {
		res = PARAM_SET_getStr(set, "i,input", NULL, PST_PRIORITY_NONE, i, &fname_in);
		if (res != PST_OK) goto cleanup;

		if (SMART_FILE_isFileType(fname_in, SMART_FILE_TYPE_DIR)) {
			ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: Input can not be directory ('%s').", fname_in);
			goto cleanup;
		}
	}

	res = KT_OK;

cleanup:

	return res;
}

static int KT_SIGN_getMaximumInputsPerRound(PARAM_SET *set, ERR_TRCKR *err, size_t *inputs) {
	int res = KT_UNKNOWN_ERROR;
	int max_lvl_virtual = 0;
	int max_lvl = 0;
	int has_prev_leaf = 0;
	int is_masking = 0;
	int is_metadata = 0;
	size_t tmp = 0;


	if (set == NULL || err == NULL || inputs == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = PARAM_SET_getObj(set, "max-lvl", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, (void*)&max_lvl);
	if (res != PST_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	/**
	 * Check if masking is done and / or metadata is appended to the tree.
	 */
	is_masking = PARAM_SET_isSetByName(set, "mask");
	is_metadata = PARAM_SET_isSetByName(set, "mdata,mdata-cli-id");
	has_prev_leaf = PARAM_SET_isSetByName(set, "prev-leaf");

	if (!is_masking && has_prev_leaf) {
		ERR_TRCKR_ADD(err, res = KT_AGGR_LVL_LIMIT_TOO_SMALL, "Error: Unable to link the local aggregation tree with the last leaf of the previous local aggregation tree as masking is not enabled (see --mask).\n");
		goto cleanup;
	}

	if (max_lvl < 2 && has_prev_leaf && is_metadata) {
		ERR_TRCKR_ADD(err, res = KT_AGGR_LVL_LIMIT_TOO_SMALL, "Error: Unable to embed metadata and link the local aggregation tree with the last leaf of the previous local aggregation tree with masking as the local aggregation tree's maximum allowed depth is too small (see --max-lvl).\n");
		goto cleanup;
	}

	if (max_lvl < 2 && is_masking && is_metadata) {
		ERR_TRCKR_ADD(err, res = KT_AGGR_LVL_LIMIT_TOO_SMALL, "Error: Unable to add metadata with masking as the local aggregation tree's maximum allowed depth is too small (see --max-lvl).\n");
		goto cleanup;
	}

	if (max_lvl == 0 && is_metadata) {
		ERR_TRCKR_ADD(err, res = KT_AGGR_LVL_LIMIT_TOO_SMALL, "Error: Unable to embed metadata as the local aggregation tree's maximum allowed depth is too small (see --max-lvl).\n");
		goto cleanup;
	}

	if (max_lvl == 0 && is_masking) {
		ERR_TRCKR_ADD(err, res = KT_AGGR_LVL_LIMIT_TOO_SMALL, "Error: Unable to use masking as the local aggregation tree's maximum allowed depth is too small (see --max-lvl).\n");
		goto cleanup;
	}

	/**
	 * Create a virtual max level that is decremented if masking is done or
	 * if metadada is appended.
	 */
	max_lvl_virtual = max_lvl;

	if (is_masking) if (max_lvl_virtual > 0) max_lvl_virtual--;
	if (is_metadata) if (max_lvl_virtual > 0) max_lvl_virtual--;

	if (sizeof(size_t) * 8 <= max_lvl_virtual) {
		ERR_TRCKR_ADD(err, res = KT_INDEX_OVF, "Error: The maximum local aggregation tree to be generated may contain more values than internal iterators can handle (See --max-lvl).");
		goto cleanup;
	}

	/**
	 * Calculate 2^max_lvl_virtual.
	 */
	tmp = ((size_t)1 << max_lvl_virtual);
	*inputs = tmp;
	res = KT_OK;

cleanup:

	return res;
}

static int KT_SIGN_getAggregationRoundsNeeded(PARAM_SET *set, ERR_TRCKR *err, size_t max_tree_inputs, size_t *rounds) {
	int res = KT_UNKNOWN_ERROR;
	int input_file_count = 0;
	int max_local_aggr_rounds = 0;
	int is_sequential = 0;
	size_t round_count = 0;


	if (set == NULL || err == NULL || rounds == NULL || max_tree_inputs == 0) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = PARAM_SET_getValueCount(set, "i,input", NULL, PST_PRIORITY_NONE, &input_file_count);
	if (res != PST_OK) goto cleanup;

	res = PARAM_SET_getObj(set, "max-aggr-rounds", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, (void*)&max_local_aggr_rounds);
	if (res != PST_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	is_sequential = max_local_aggr_rounds > 1;

	round_count = (size_t)ceil((double)input_file_count / (double)max_tree_inputs);

	if (round_count > 1 && !is_sequential) {
		ERR_TRCKR_ADD(err, res = KT_AGGR_LVL_LIMIT_TOO_SMALL, "Error: Too much inputs for a single aggregation round.");
		goto cleanup;
	}

	if (is_sequential && round_count > max_local_aggr_rounds ) {
		ERR_TRCKR_ADD(err, res = KT_AGGR_LVL_LIMIT_TOO_SMALL, "Error: Too much inputs! Permitted rounds is %u but %u is needed.", max_local_aggr_rounds, round_count);
		goto cleanup;
	}


	*rounds = round_count;
	res = KT_OK;

cleanup:

	return res;
}

static void SIGNING_AGGR_ROUND_free(SIGNING_AGGR_ROUND *obj) {
	int i = 0;

	if (obj == NULL) return;

	KSI_BlockSigner_free(obj->block_signer);
	KSI_BlockSignerHandleList_free(obj->bs_handleList);
	KSI_free(obj->fname);

	if (obj->fname_out != NULL) {
		i = 0;
		while (i < obj->hash_count && obj->fname_out[i] != NULL) {
			KSI_free(obj->fname_out[i++]);
		}
		KSI_free(obj->fname_out);
	}

	if (obj->hash_values != NULL) {
		i = 0;
		while (i < obj->hash_count && obj->hash_values[i] != NULL) {
			KSI_DataHash_free(obj->hash_values[i++]);
		}
		KSI_free(obj->hash_values);
	}

	KSI_free(obj);
}

static void SIGNING_AGGR_ROUND_ARRAY_free(SIGNING_AGGR_ROUND **array) {
		if (array != NULL) {
		int i = 0;

		while (array[i] != NULL) {
			SIGNING_AGGR_ROUND_free(array[i]);
			i++;
		}

		KSI_free(array);
	}
}

static int SIGNING_AGGR_ROUND_new(size_t max_leaves, SIGNING_AGGR_ROUND **round) {
	int res;
	SIGNING_AGGR_ROUND *tmp = NULL;
	KSI_DataHash **tmp_hash = NULL;
	char **tmp_fname = NULL;
	char **tmp_fname_out = NULL;

	if (round == NULL || max_leaves < 1) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = (SIGNING_AGGR_ROUND*)KSI_calloc(1, sizeof(SIGNING_AGGR_ROUND));
	if (tmp == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->hash_count_max = max_leaves;
	tmp->hash_count = 0;
	tmp->hash_values = NULL;
	tmp->fname = NULL;
	tmp->block_signer = NULL;
	tmp->bs_handleList = NULL;
	tmp->fname_out = NULL;

	tmp_hash = (KSI_DataHash**)KSI_calloc(max_leaves, sizeof(KSI_DataHash*));
	if (tmp_hash == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp_fname = (char**)KSI_calloc(max_leaves, sizeof(char*));
	if (tmp_fname == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp_fname_out = (char**)KSI_calloc(max_leaves, sizeof(char*));
	if (tmp_fname == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->hash_values = tmp_hash;
	tmp->fname = tmp_fname;
	tmp->fname_out = tmp_fname_out;
	*round = tmp;

	tmp = NULL;
	tmp_fname_out = NULL;
	tmp_fname = NULL;
	tmp_hash = NULL;
	res = KT_OK;

cleanup:

	SIGNING_AGGR_ROUND_free(tmp);
	KSI_free(tmp_fname_out);
	KSI_free(tmp_fname);
	KSI_free(tmp_hash);

	return res;
}

static int SIGNING_AGGR_ROUND_append(SIGNING_AGGR_ROUND *round, KSI_DataHash *hsh, char *fname) {
	int res;

	if (round == NULL || hsh == NULL || fname == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (round->hash_count == round->hash_count_max) {
		res = KT_INDEX_OVF;
		goto cleanup;
	}

	round->hash_values[round->hash_count] = hsh;
	round->fname[round->hash_count] = fname;
	round->hash_count++;
	res = KT_OK;

cleanup:

	return res;
}

static int KT_SIGN_performSigning(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ctx, size_t max_tree_inputs, size_t rounds, SIGNING_AGGR_ROUND ***aggr_rounds_record) {
	int res = KT_UNKNOWN_ERROR;
	int d = 0;
	int prgrs = 0;
	int in_count = 0;
	int divider = 0;
	char *signed_data_out = NULL;
	KSI_HashAlgorithm algo = KSI_UNAVAILABLE_HASH_ALGORITHM;
	COMPOSITE extra;
	KSI_OctetString *mask_iv = NULL;
	int isMetadata = 0;
	int isMasking = 0;
	KSI_DataHash *prev_leaf = NULL;
	SIGNING_AGGR_ROUND **aggr_round = NULL;
	int tree_size_1 = 0;
	KSI_BlockSigner *bs = NULL;
	KSI_BlockSignerHandle *hndl = NULL;
	KSI_LIST(KSI_BlockSignerHandle) *hndlList = NULL;
	KSI_MetaData *mdata = NULL;
	size_t i = 0;
	size_t r = 0;
	KSI_DataHash *hash = NULL;

	if (set == NULL || err == NULL || max_tree_inputs == 0 || rounds == 0 || aggr_rounds_record == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/**
	 * Read main parameters from the set.
	 */
	d = PARAM_SET_isSetByName(set, "d");
	prgrs = PARAM_SET_isSetByName(set, "show-progress");

	res = PARAM_SET_getValueCount(set, "i,input", NULL, PST_PRIORITY_NONE, &in_count);
	if (res != PST_OK) goto cleanup;

	if (in_count >= 10000) divider = in_count / 100;
	else if (in_count >= 1000) divider = 10;
	else divider = 1;

	res = PARAM_SET_getStr(set, "data-out", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &signed_data_out);
	if (res != PST_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	/**
	 * Extract the hash algorithm. If not specified, set algorithm as default.
	 * It must be noted that if hash is extracted from imprint, has algorithm has
	 * no effect.
	 */
	if (PARAM_SET_isSetByName(set, "H")) {
		res = PARAM_SET_getObjExtended(set, "H", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, NULL, (void**)&algo);
		if (res != PST_OK && res != PST_PARAMETER_EMPTY) goto cleanup;
	} else {
		algo = KSI_getHashAlgorithmByName("default");
	}

	/**
	 * Configure extra parameter for OBJ extractor.
	 */
	extra.ctx = ctx;
	extra.err = err;
	extra.h_alg = &algo;
	extra.fname_out = signed_data_out;

	/**
	 * Extract initial value for masking mask.
	 */
	res = PARAM_SET_getObjExtended(set, "mask", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, (void*)&extra, (void**)&mask_iv);
	if (res != PST_OK && res != PST_PARAMETER_EMPTY) {
		ERR_TRCKR_ADD(err, res, "Error: Unable to get initial value for masking.");
		goto cleanup;
	}

	/**
	 * Analyze parameter to determine if masking is going to be performed and
	 * if metadata is embedded to the signature.
	 */
	isMetadata = PARAM_SET_isSetByName(set, "mdata,mdata-cli-id");
	isMasking = PARAM_SET_isSetByName(set, "mask");

	/**
	 * Extract previous leaf hash value.
	 */
	if (isMasking) {
		if (PARAM_SET_isSetByName(set, "prev-leaf")) {
			res = PARAM_SET_getObjExtended(set, "prev-leaf", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, (void*)&extra, (void**)&prev_leaf);
			if (res != PST_OK && res != PST_PARAMETER_EMPTY) goto cleanup;
		} else {
			res = KSI_DataHash_createZero(ctx, algo, &prev_leaf);
			ERR_CATCH_MSG(err, res, "Error: Unable to create zero hash.");
		}
	}


	/**
	 * Create records for each aggregation round + 1 extra for indicating the end
	 * of the array.
	 */
	aggr_round = (SIGNING_AGGR_ROUND**)KSI_calloc(rounds + 1, sizeof(SIGNING_AGGR_ROUND*));
	if (aggr_round == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	aggr_round[rounds] = NULL;

	if (rounds == 1 && in_count == 1 && !isMasking && !isMetadata) tree_size_1 = 1;

	/**
	 * Perform local aggregation.
	 */
	for (r = 0; r < rounds; r++) {
		size_t tree_input = 0;
		size_t to_be_signed_in_round = (((r + 1) * max_tree_inputs) < in_count) ? max_tree_inputs : in_count - (int)r * max_tree_inputs;

		res = SIGNING_AGGR_ROUND_new(to_be_signed_in_round, &aggr_round[r]);
		ERR_CATCH_MSG(err, res, "Error: Unable to create a record for aggregation round.");

		res = KSI_BlockSigner_new(ctx, algo, isMasking ? prev_leaf : NULL, isMasking ? mask_iv : NULL, &bs);
		ERR_CATCH_MSG(err, res, "Error: Unable to create KSI Block Signer.");

		/* Initialize a list for keeping hash handles. */
		res = KSI_BlockSignerHandleList_new(&hndlList);
		ERR_CATCH_MSG(err, res, "Error: Unable to create KSI Block Signer handle list.");

		/**
		 * Extract the metadata if requested by the user. If not return NULL and
		 * metadata is not embedded to the signature.
		 */
		res = KT_SIGN_getMetadata(set, err, ctx, r, &mdata);
		ERR_CATCH_MSG(err, res, "Error: Unable to construct metadata structure.");


		if (prgrs || in_count > 1) {
			print_debug("Signing %i files in round %i/%i.\n", to_be_signed_in_round, r + 1, rounds);
		}

		for (tree_input = 0; tree_input < max_tree_inputs && i < in_count; tree_input++, i++) {
			char *fname = NULL;

			if (!prgrs) print_progressDesc(d, "Extracting hash from input... ");

			res = PARAM_SET_getObjExtended(set, "i,input", NULL, PST_PRIORITY_NONE, (int)i, &extra, (void**)&hash);
			if (res != KT_OK) goto cleanup;

			if (!tree_size_1 && !prgrs) print_progressResult(res);

			if (!tree_size_1 && !prgrs) print_progressDesc(d, "Add document hash %d/%d %s%s%sto the local aggregation tree... ",
					tree_input + 1, to_be_signed_in_round,
					(isMetadata && !isMasking) ? "with metadata " : "",
					(!isMetadata && isMasking) ? "with enabled masking " : "",
					(isMetadata && isMasking) ? "and metadata with enabled masking " : ""
					);

			res = KSI_BlockSigner_addLeaf(bs, hash, 0, mdata, &hndl);
			ERR_CATCH_MSG(err, res, "Error: Unable to add a hash value to a local aggregation tree.");

			res = KSI_BlockSignerHandleList_append(hndlList, hndl);
			ERR_CATCH_MSG(err, res, "Error: Unable to append blck-signer handle to the list.");
			hndl = NULL;

			res = PARAM_SET_getStr(set, "i,input", NULL, PST_PRIORITY_NONE, (int)i, &fname);
			ERR_CATCH_MSG(err, res, "Error: Unable to get files name.");

			res = SIGNING_AGGR_ROUND_append(aggr_round[r], hash, fname);
			ERR_CATCH_MSG(err, res, "Error: Unable to add hash value and files name to local aggregation record.");
			hash = NULL;

			if (!prgrs) print_progressResult(res);

			if (prgrs && (i % divider == 0 || i + 1 >= in_count || tree_input + 1 == to_be_signed_in_round)) {
				PROGRESS_BAR_display((int)((tree_input + 1) * 100 / to_be_signed_in_round));
			}

		}


		if (prgrs) print_debug("\n");

		if (tree_size_1) print_progressDesc(d, "Creating signature from hash... ");
		else print_progressDesc(d, "Signing the local aggregation tree %d/%d... ", r + 1, rounds);

		res = KSITOOL_BlockSigner_closeAndSign(err, ctx, bs);
		if (tree_size_1) {ERR_CATCH_MSG(err, res, "Error: Unable to create signature.");}
		else {ERR_CATCH_MSG(err, res, "Error: Unable to complete and sign the local aggregation tree.");}

		aggr_round[r]->block_signer = bs;
		bs = NULL;
		aggr_round[r]->bs_handleList = hndlList;
		hndlList = NULL;

		print_progressResult(res);

		if (!tree_size_1 || (tree_size_1 && prgrs)) print_debug("\n");
		KSI_MetaData_free(mdata);
		mdata = NULL;
	}


	*aggr_rounds_record = aggr_round;
	aggr_round = NULL;
	res = KT_OK;

cleanup:

	SIGNING_AGGR_ROUND_ARRAY_free(aggr_round);
	KSI_DataHash_free(hash);
	KSI_DataHash_free(prev_leaf);
	KSI_BlockSigner_free(bs);
	KSI_BlockSignerHandle_free(hndl);
	KSI_BlockSignerHandleList_free(hndlList);
	KSI_MetaData_free(mdata);
	KSI_OctetString_free(mask_iv);

	return res;
}

static char* get_output_file_name(PARAM_SET *set, ERR_TRCKR *err, int how_is_saved, int i, char *buf, size_t buf_len) {
	char *ret = NULL;
	int res;
	char *in_file_name = NULL;
	char hash_algo[1024];
	char generated_name[1024] = "";
	char *colon = NULL;
	int in_count = 0;

	if (set == NULL || err == NULL || buf == NULL || buf_len == 0) goto cleanup;

	res = PARAM_SET_getValueCount(set, "i,input", NULL, PST_PRIORITY_NONE, &in_count);
	if (res != PST_OK) goto cleanup;

	res = PARAM_SET_getStr(set, "i,input", NULL, PST_PRIORITY_NONE, i, &in_file_name);
	if (res != PST_OK && res != PST_PARAMETER_EMPTY && res != PST_PARAMETER_VALUE_NOT_FOUND) goto cleanup;

	if (res == PST_PARAMETER_EMPTY || res == PST_PARAMETER_VALUE_NOT_FOUND) {
		ERR_TRCKR_ADD(err, res, "Error: Unable to get path to output file name.");
		goto cleanup;
	}

	/**
	 * Output file name hast to be generated.
	 */
	if (how_is_saved == OUTPUT_NEXT_TO_INPUT || how_is_saved == OUTPUT_TO_DIR) {
		if (strcmp(in_file_name, "-") == 0 && in_count == 1) {
			KSI_snprintf(generated_name, sizeof(generated_name), "stdin.ksig");
		} else if (is_imprint(in_file_name)) {
			/* Search for the algorithm name. */
			KSI_strncpy(hash_algo, in_file_name, sizeof(hash_algo));
			colon = strchr(hash_algo, ':');

			/* Create the file name from hash algorithm. */
			if (colon != NULL) {
				*colon = '\0';
				KSI_snprintf(generated_name, sizeof(generated_name), "%s.ksig", hash_algo);
			} else {
				KSI_snprintf(generated_name, sizeof(generated_name), "hash_imprint.ksig");
			}
		} else {
			KSI_snprintf(generated_name, sizeof(generated_name), "%s.ksig", in_file_name);
		}
	}

	/**
	 * Specify the output name.
	 */
	if (how_is_saved == OUTPUT_NEXT_TO_INPUT) {
		KSI_snprintf(buf, buf_len, "%s", generated_name);
	} else if (how_is_saved == OUTPUT_SPECIFIED_FILE) {
		char *out_file_name = NULL;

		res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_NONE, i, &out_file_name);
		if (res != PST_OK) goto cleanup;

		KSI_snprintf(buf, buf_len, "%s", out_file_name);
	} else if (how_is_saved == OUTPUT_TO_DIR) {
		char tmp[1024];
		char *file_name = NULL;
		int path_len = 0;
		int is_slash = 0;
		char *out_dir_name = NULL;


		res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_NONE, 0, &out_dir_name);
		if (res != PST_OK) goto cleanup;


		file_name = STRING_extractAbstract(generated_name, "/", NULL, tmp, sizeof(tmp), find_charAfterLastStrn, NULL, NULL) == tmp ? tmp : generated_name;
		path_len = (int)strlen(out_dir_name);

		is_slash =(path_len != 0 && out_dir_name[path_len - 1]) == '/' ? 1 : 0;

		KSI_snprintf(buf, buf_len, "%s%s%s",
				out_dir_name,
				is_slash ? "" : "/",
				file_name);
	} else if (how_is_saved == OUTPUT_TO_STDOUT) {
		char *out_dir_name = NULL;

		res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_NONE, 0, &out_dir_name);
		if (res != PST_OK) goto cleanup;

		KSI_snprintf(buf, buf_len, "%s", out_dir_name);
	}


	ret = buf;

cleanup:

	return ret;
}

static int KT_SIGN_saveToOutput(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, SIGNING_AGGR_ROUND **aggr_round) {
	int res = PST_UNKNOWN_ERROR;
	int in_count = 0;
	int divider = 0;
	int prgrs = 0;
	int how_to_save = OUTPUT_UNKNOWN;
	int i = 0;
	int n = 0;
	int count = 0;
	KSI_Signature *sig = NULL;
	char *real_output_name_copy = NULL;

	if (set == NULL || err == NULL || ksi == NULL || aggr_round == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = PARAM_SET_getValueCount(set, "i,input", NULL, PST_PRIORITY_NONE, &in_count);
	if (res != PST_OK) goto cleanup;

	if (in_count >= 10000) divider = in_count / 100;
	else if (in_count >= 1000) divider = 10;
	else divider = 1;

	prgrs = PARAM_SET_isSetByName(set, "show-progress");

	how_to_save = how_is_output_saved_to(set);

	if (prgrs) print_debug("Saving %i files.\n", in_count);

	while (aggr_round[i] != NULL) {
		for (n = 0; n < aggr_round[i]->hash_count; n++) {
			char save_to_file[1024] = "";
			char real_output_name[1024] = "";
			size_t real_out_name_size = 0;
			KSI_DataHash *hsh = NULL;
			const char *mode = NULL;
			KSI_BlockSignerHandle *hndl = NULL;

			/* Get the handle from the list. */
			res = KSI_BlockSignerHandleList_elementAt(aggr_round[i]->bs_handleList, n, &hndl);
			ERR_CATCH_MSG(err, res, "Error: Unable to extract block signer leaf handle from the list.");

			/* Get KSI signature from block-signer handle. */
			res = KSI_BlockSignerHandle_getSignature(hndl, &sig);
			ERR_CATCH_MSG(err, res, "Error: Unable to extract signature.");

			res = KSI_Signature_getDocumentHash(sig, &hsh);
			ERR_CATCH_MSG(err, res, "Error: Unable to extract signature document hash.");

			/* Verify that is it the correct signature. */
			if (!KSI_DataHash_equals(aggr_round[i]->hash_values[n], hsh)) {
				ERR_TRCKR_ADD(err, res = KT_UNKNOWN_ERROR, "Error: Unexpected error. Signature data hash mismatch.");
				goto cleanup;
			}

			if (get_output_file_name(set, err, how_to_save, count, save_to_file, sizeof(save_to_file)) == NULL) {
				ERR_TRCKR_ADD(err, res = KT_UNKNOWN_ERROR, "Error: Unexpected error. Unable to get the file name to save the signature to.");
				goto cleanup;
			}

			if (how_to_save == OUTPUT_TO_STDOUT) mode = "wbs";
			else if (how_to_save == OUTPUT_NEXT_TO_INPUT) mode = "wbi";
			else if (how_to_save == OUTPUT_TO_DIR) mode = "wbi";
			else if (how_to_save == OUTPUT_SPECIFIED_FILE) mode = "wb";
			else if (how_to_save == OUTPUT_UNKNOWN) {
				ERR_TRCKR_ADD(err, res = KT_UNKNOWN_ERROR, "Error: Unexpected error. Unable to resolve how the output signatures should be stored.");
				goto cleanup;
			}

			res = KSI_OBJ_saveSignature(err, ksi, sig, mode, save_to_file, real_output_name, sizeof(real_output_name));
			ERR_CATCH_MSG(err, res, "Error: Unable to save signature.");

			real_out_name_size = sizeof(char) * (strlen(real_output_name) + 1);

			real_output_name_copy = (char*)KSI_malloc(real_out_name_size);
			if (real_output_name_copy == NULL) {
				res = KT_OUT_OF_MEMORY;
				goto cleanup;
			}

			PST_strncpy(real_output_name_copy, real_output_name, real_out_name_size);
			aggr_round[i]->fname_out[n] = real_output_name_copy;
			if (!prgrs) print_debug("Signature saved to '%s'.\n", real_output_name);

			KSI_Signature_free(sig);
			sig = NULL;
			real_output_name_copy = NULL;

			count++;
			if (prgrs && (count % divider == 0 || count + 1 >= in_count)) {
				PROGRESS_BAR_display((count + 1) * 100 / in_count);
			}

		}
		i++;
	}
	if (i > 0) print_debug("\n");

	res = KT_OK;

cleanup:

	KSI_free(real_output_name_copy);
	KSI_Signature_free(sig);

	return res;
}

static int KT_SIGN_dump(PARAM_SET *set, ERR_TRCKR *err, SIGNING_AGGR_ROUND **aggr_round) {
	int res = PST_UNKNOWN_ERROR;
	int i = 0;
	int n = 0;
	int in_count = 0;
	int dump = 0;
	KSI_Signature *sig = NULL;

	if (set == NULL || err == NULL || aggr_round == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = PARAM_SET_getValueCount(set, "i,input", NULL, PST_PRIORITY_NONE, &in_count);
	if (res != PST_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	dump = PARAM_SET_isSetByName(set, "dump");

	while (dump && aggr_round[i] != NULL) {
		if (in_count > 1) print_result("Signatures from aggregation round: %i\n\n", i);

		for (n = 0; n < aggr_round[i]->hash_count; n++) {
			KSI_BlockSignerHandle *hndl = NULL;

			/* Get the handle from the list. */
			res = KSI_BlockSignerHandleList_elementAt(aggr_round[i]->bs_handleList, n, &hndl);
			ERR_CATCH_MSG(err, res, "Error: Unable to extract block signer leaf handle from the list.");

			res = KSI_BlockSignerHandle_getSignature(hndl, &sig);
			ERR_CATCH_MSG(err, res, "Error: Unable to get signature to dump its content.");

			print_result("Document : '%s'\n", aggr_round[i]->fname[n]);
			print_result("Signature: '%s'\n", aggr_round[i]->fname_out[n]);
			OBJPRINT_signatureDump(sig, print_result);
			KSI_Signature_free(sig);
			sig = NULL;
			print_result("\n\n");
		}
		i++;
	}

	res = KT_OK;

cleanup:

	KSI_Signature_free(sig);

	return res;
}

static int KT_SIGN_getMetadata(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, size_t seq_offset, KSI_MetaData **mdata) {
	int res;
	char *cli_id = NULL;
	char *mac_id = NULL;
	int sqn_nr = 0;
	KSI_Utf8String *client_id = NULL;
	KSI_Utf8String *machine_id = NULL;
	KSI_Integer *sequence_nr = NULL;
	KSI_Integer *aggr_time = NULL;
	KSI_MetaData *tmp = NULL;

	if (set == NULL || err == NULL || ksi == NULL || mdata == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/**
	 * If metadata is not used, exit with success and return NULL.
	 */
	if (PARAM_SET_isSetByName(set, "mdata")) {
		/**
		 * Check if metadata record is consistent.
		 */

		if (!PARAM_SET_isSetByName(set, "mdata-cli-id") && PARAM_SET_isOneOfSetByName(set, "mdata-mac-id,mdata-sqn-nr,mdata-req-tm")) {
			ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: Client ID is missing but is mandatory part of metadata.");
			goto cleanup;
		}

		/**
		 * Get the mandatory client ID, and if set, optional machine ID.
		 */
		res = PARAM_SET_getStr(set, "mdata-cli-id", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &cli_id);
		if (res != PST_OK) goto cleanup;

		res = KSI_Utf8String_new(ksi, cli_id, strlen(cli_id) + 1, &client_id);
		if (res != KSI_OK) goto cleanup;

		res = PARAM_SET_getStr(set, "mdata-mac-id", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &mac_id);
		if (res != PST_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

		if (mac_id != NULL) {
			res = KSI_Utf8String_new(ksi, mac_id, strlen(mac_id) + 1, &machine_id);
			if (res != KSI_OK) goto cleanup;
		}

		/**
		 * Check if the sequence number is going to be embedded and if a special
		 * or default value is used. Note that the seq_offset is used to increase
		 * the sequence number.
		 */
		if (PARAM_SET_isSetByName(set, "mdata-sqn-nr")) {
			char *dummy = NULL;
			res = PARAM_SET_getStr(set, "mdata-sqn-nr", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &dummy);
			if (res != PST_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

			if (dummy != NULL) {
				res = PARAM_SET_getObj(set, "mdata-sqn-nr", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, (void**)&sqn_nr);
				if (res != PST_OK && res != PST_PARAMETER_EMPTY) goto cleanup;
			} else {
				sqn_nr = 0;
			}

			res = KSI_Integer_new(ksi, sqn_nr + seq_offset, &sequence_nr);
			if (res != KSI_OK) goto cleanup;
		}

		/**
		 * Check if aggregation time is embedded into metadata record.
		 */
		if (PARAM_SET_isSetByName(set, "mdata-req-tm")) {
			res = KSI_Integer_new(ksi, time(NULL) * 1000000, &aggr_time);
			if (res != KSI_OK) goto cleanup;
		}

		/**
		 * Create metadata record from input data.
		 */

		res = KSI_MetaData_new(ksi, &tmp);
		if (res != KSI_OK) goto cleanup;

		res = KSI_MetaData_setClientId(tmp, client_id);
		if (res != KSI_OK) goto cleanup;

		res = KSI_MetaData_setMachineId(tmp, machine_id);
		if (res != KSI_OK) goto cleanup;

		res = KSI_MetaData_setRequestTimeInMicros(tmp, aggr_time);
		if (res != KSI_OK) goto cleanup;

		res = KSI_MetaData_setSequenceNr(tmp, sequence_nr);
		if (res != KSI_OK) goto cleanup;

	}

	*mdata = tmp,
	tmp = NULL;
	res = KT_OK;


cleanup:

	KSI_Utf8String_free(client_id);
	KSI_Utf8String_free(machine_id);
	KSI_Integer_free(sequence_nr);
	KSI_Integer_free(aggr_time);

	return res;
}
