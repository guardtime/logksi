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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ksi/ksi.h>
#include <ksi/compatibility.h>
#include "param_set/param_set.h"
#include "param_set/task_def.h"
#include "tool_box/default_tasks.h"
#include "tool_box.h"
#include "component.h"
#include "ksitool_err.h"
#include "printer.h"
#include "conf_file.h"


#ifndef _WIN32
#  ifdef HAVE_CONFIG_H
#    include "config.h"
#  endif
#endif

const char *TOOL_getVersion(void) {
	static const char versionString[] = VERSION;
	return versionString;
}

const char *TOOL_getName(void) {
	static const char name[] = TOOL_NAME;
	return name;
}

static char *hash_algorithms_to_string(char *buf, size_t buf_len) {
	int i;
	size_t count = 0;

	if (buf == NULL || buf_len == 0) {
		return NULL;
	}


	for (i = 0; i < KSI_NUMBER_OF_KNOWN_HASHALGS; i++) {
		if (KSI_isHashAlgorithmSupported(i)) {
			count += KSI_snprintf(buf + count, buf_len - count, "%s%s",
				count == 0 ? "" : " ",
				KSI_getHashAlgorithmName(i)
				);
		}
	}
	if (count > 0) {
		count += KSI_snprintf(buf + count, buf_len - count, ".");
	}

	return buf;
}

static void print_general_help(PARAM_SET *set, const char *KSI_CONF){
	int res;
	char *aggre_url = NULL;
	char *ext_url = NULL;
	char *pub_url = NULL;
	char *cnstr = NULL;
	char buf[1024];
	int i = 0;

	if (set == NULL) {
		return;
	}

	res = PARAM_SET_getStr(set, "S", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &aggre_url);
	if (res != PST_OK && res != PST_PARAMETER_EMPTY) return;

	res = PARAM_SET_getStr(set, "X", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &ext_url);
	if (res != PST_OK && res != PST_PARAMETER_EMPTY) return;

	res = PARAM_SET_getStr(set, "P", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &pub_url);
	if (res != PST_OK && res != PST_PARAMETER_EMPTY) return;


	aggre_url = aggre_url != NULL ? aggre_url : "Not defined.";
	ext_url = ext_url != NULL ? ext_url : "Not defined.";
	pub_url = pub_url != NULL ? pub_url : "Not defined.";

	print_result("\n");
	if (KSI_CONF != NULL && KSI_CONF[0] != '\0') print_result("KSI_CONF=%s\n", KSI_CONF);
	print_result("Configured service access URL-s:\n");

	/**
	 * Print info about default services.
	 */
	print_result(
	"  Signing:		%s\n"
	"  Extending/Verifying:	%s\n"
	"  Publications file:	%s\n\n",
		aggre_url, ext_url, pub_url
	);

	print_result("Default publications file certificate constraints:\n");
	while (PARAM_SET_getStr(set, "cnstr", NULL, PST_PRIORITY_HIGHEST, i, &cnstr) == PST_OK) {
		print_result("  %s\n", cnstr);
		i++;
	}

	if (i == 0) {
		print_result("  none\n\n");
	} else {
		print_result("\n");
	}

	/**
	 * Print info about supported hash algorithms.
	 */
	print_result(
	"Supported hash algorithms:\n"
	"  %s\n",
		hash_algorithms_to_string(buf, sizeof(buf)));
}

static int ksitool_compo_get(TASK_SET *tasks, PARAM_SET **set, TOOL_COMPONENT_LIST **compo);
static int min_arg_cnt(TASK_ID id);

int main(int argc, char** argv, char **envp) {
	int res;
	PARAM_SET *set_task_name = NULL;
	PARAM_SET *set = NULL;
	PARAM_SET *configuration = NULL;
	TOOL_COMPONENT_LIST *components = NULL;
	TASK_SET *tasks = NULL;
	TASK *task = NULL;
	int retval = EXIT_SUCCESS;
	char buf[0xffff];

	/**
	 * Configure KSI tool to print only values that are result of the user request
	 * or an error.
	 */
	print_init();
	print_disable(PRINT_WARNINGS | PRINT_INFO | PRINT_DEBUG);
	print_enable(PRINT_RESULT | PRINT_ERRORS);


	/**
	 * Define parameter and task set.
	 */
	res = PARAM_SET_new("{h|help}{version}{d}", &set);
	if (res != PST_OK) goto cleanup;

	res = TASK_SET_new(&tasks);
	if (res != PST_OK) goto cleanup;

	res = CONF_createSet(&configuration);
	if (res != PST_OK) goto cleanup;

	/**
	 * Load the configuration file from environment.
	 */
	res = CONF_fromEnvironment(configuration, "KSI_CONF", envp, 0, 1);
	res = conf_report_errors(configuration, CONF_getEnvNameContent(), res);
	if (res != KT_OK) goto cleanup;

	/**
	 * Get all possible components to run.
	 */
	res = ksitool_compo_get(tasks, &set_task_name, &components);
	if (res != PST_OK) {
		print_errors("Error: Unable get ksi components.\n");
		goto cleanup;
	}

	/**
	 * Add the values to the set.
	 */
	res = PARAM_SET_add(set_task_name, argv[1], NULL, NULL, 0);

	if (argc > 1) {
		res = PARAM_SET_readFromCMD(set, argc, argv, NULL, 0);
	}

	/**
	 * Extract the task.
	 */
	res = TASK_SET_analyzeConsistency(tasks, set_task_name, 0.2);
	if (res != PST_OK) goto cleanup;

	res = TASK_SET_getConsistentTask(tasks, &task);
	if (res != PST_OK && res != PST_TASK_ZERO_CONSISTENT_TASKS && res !=PST_TASK_MULTIPLE_CONSISTENT_TASKS) goto cleanup;

	/**
	 * Simple tool help handler.
	 */
	if (PARAM_SET_isSetByName(set, "h") || (argc < 2 && task == NULL) || (task != NULL && argc < min_arg_cnt(TASK_getID(task)) + 2)) {
		print_result("%s %s (C) Guardtime\n", TOOL_getName(), TOOL_getVersion());
		print_result("%s (C) Guardtime\n\n", KSI_getVersion());

		if (task == NULL) {
			print_result(
				"Usage:\n"
				"  %s [-h] [--version]\n"
				"  %s command -h\n"
				"  %s command [service_parameters] [options]\n"
				"\n"
				"Commands:\n",
				TOOL_getName(),
				TOOL_getName(),
				TOOL_getName()
			);
			print_result("%s", TOOL_COMPONENT_LIST_toString(components, "  ", buf, sizeof(buf)));
		} else {
			print_result("%s\n", TOOL_COMPONENT_LIST_helpToString(components, TASK_getID(task),buf, sizeof(buf)));
		}

		print_general_help(configuration, CONF_getEnvNameContent());
		res = KT_OK;
		goto cleanup;
	} else if (PARAM_SET_isSetByName(set, "version")) {
		print_result("%s %s (C) Guardtime\n", TOOL_getName(), TOOL_getVersion());
		res = KT_OK;
		goto cleanup;
	}

	if (CONF_isInvalid(configuration)) {
		print_errors("KSI configuration file from KSI_CONF is invalid:\n");
		print_errors("%s\n", CONF_errorsToString(configuration, "  ", buf, sizeof(buf)));
		res = KT_INVALID_CONF;
		goto cleanup;
	}


	/**
	 * Invalid task. Give user some hints.
	 */
	if (task == NULL) {
		print_errors("Error: Invalid task. Read help (-h) or man page.\n");
		if (PARAM_SET_isTypoFailure(set_task_name)) {
			print_errors("%s\n", PARAM_SET_typosToString(set_task_name, PST_TOSTR_NONE, NULL, buf, sizeof(buf)));
		} else if (PARAM_SET_isUnknown(set_task_name)){
			print_errors("%s\n", PARAM_SET_unknownsToString(set_task_name, NULL, buf, sizeof(buf)));
		}

		res = KT_INVALID_CMD_PARAM;
		goto cleanup;
	}


	if (PARAM_SET_isSetByName(set, "d")) {
		print_enable(PRINT_DEBUG);
	}

	/**
	 * Run component by its ID.
	 */
	retval = TOOL_COMPONENT_LIST_run(components, TASK_getID(task), argc - 1, argv + 1, envp);

	res = KT_OK;


cleanup:

	if (res != KT_OK && retval == EXIT_SUCCESS) {
		retval = KSITOOL_errToExitCode(res);
	}

	PARAM_SET_free(set);
	PARAM_SET_free(set_task_name);
	PARAM_SET_free(configuration);
	TASK_SET_free(tasks);
	TOOL_COMPONENT_LIST_free(components);

	return retval;
}

static int ksitool_compo_get(TASK_SET *tasks, PARAM_SET **set, TOOL_COMPONENT_LIST **compo) {
	int res;
	TOOL_COMPONENT_LIST *tmp_compo = NULL;
	PARAM_SET *tmp_set = NULL;

	/**
	 * Create parameter list that contains all known tasks.
	 */
	res = PARAM_SET_new("{sign}{extend}{verify}{integrate}{conf}", &tmp_set);
	if (res != PST_OK) goto cleanup;

	res = TOOL_COMPONENT_LIST_new(32, &tmp_compo);
	if (res != PST_OK) goto cleanup;

	/**
	 * Define all components as possible tasks.
	 */
	TASK_SET_add(tasks, TASK_ID_SIGN, "Sign", "sign", NULL, NULL, NULL);
	TASK_SET_add(tasks, TASK_ID_VERIFY, "Verify", "verify", NULL, NULL, NULL);
	TASK_SET_add(tasks, TASK_ID_EXTEND, "Extend", "extend", NULL, NULL, NULL);
	TASK_SET_add(tasks, TASK_ID_INTEGRATE, "Integrate", "integrate", NULL, NULL, NULL);
	TASK_SET_add(tasks, 0xffff, "conf", "conf", NULL, NULL, NULL);

	/**
	 * Define tool component as runnable.
	 */
	TOOL_COMPONENT_LIST_add(tmp_compo, "sign", sign_run, sign_help_toString,  sign_get_desc, TASK_ID_SIGN);
	TOOL_COMPONENT_LIST_add(tmp_compo, "verify", verify_run, verify_help_toString, verify_get_desc, TASK_ID_VERIFY);
	TOOL_COMPONENT_LIST_add(tmp_compo, "extend", extend_run, extend_help_toString, extend_get_desc, TASK_ID_EXTEND);
	TOOL_COMPONENT_LIST_add(tmp_compo, "integrate", integrate_run, integrate_help_toString, integrate_get_desc, TASK_ID_INTEGRATE);
	TOOL_COMPONENT_LIST_add(tmp_compo, "conf", conf_run, conf_help_toString, conf_get_desc, 0xffff);

	*set = tmp_set;
	*compo = tmp_compo;
	tmp_set = NULL;
	tmp_compo = NULL;
	res = KT_OK;

cleanup:

	PARAM_SET_free(tmp_set);
	TOOL_COMPONENT_LIST_free(tmp_compo);

	return res;
}

static int min_arg_cnt(TASK_ID id) {
	switch(id) {
		case TASK_ID_SIGN:
		case TASK_ID_EXTEND:
			return 0;
		case TASK_ID_VERIFY:
		case TASK_ID_INTEGRATE:
		case 0xffff:
			return 1;
		default:
			return 0xff;
	}
}
