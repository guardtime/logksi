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

#ifndef TASK_INITIALIZER_H
#define	TASK_INITIALIZER_H

#include <ksi/ksi.h>
#include "param_set/param_set.h"
#include "param_set/task_def.h"
#include "logksi_err.h"
#include "debug_print.h"
#include "err_trckr.h"

#ifdef	__cplusplus
extern "C" {
#endif

enum service_info_priorities {
	/* Priority level for default values. */
	PRIORITY_KSI_DEFAULT,

	/* Priority of KSI configuration file read from KSI_CONF environment variable. */
	PRIORITY_KSI_CONF,

	/* Priority of the specific USER configuration file. Not implemented yet.*/
	PRIORITY_KSI_CONF_USER,

	/* Priority of KSI configuration file given with --conf option. */
	PRIORITY_KSI_CONF_FILE,

	/* Priority of values defined on command-line. */
	PRIORITY_CMD,
};

/**
 * 1) Check if parameter set contains invalid values (format / content).
 * 2) Check for typos report errors.
 * 3) Check for unknown, report errors.
 * 4) Analyze task set against the given parameter set.
 * 5) Extract the consistent task.
 * 6) If there is no consistent task, report errors.
 *
 * \param set				PARAM_SET obj
 * \param task_set			TASK_SET obj
 * \param task_set_sens		TASK_SET analyze sensitivity. Reccommended value 0.2.
 * \param task_dif			TASK_SET similarity check coeficent. Reccommended value 0.1.
 * \param task
 * \return KT_OK if successful, error code otherwise.
 */
int TASK_INITIALIZER_check_analyze_report(PARAM_SET *set, TASK_SET *task_set, double task_set_sens, double task_dif, TASK **task);

int TASK_INITIALIZER_getServiceInfo(PARAM_SET *set, int argc, char **argv, char **envp);

int TASK_INITIALIZER_getPrinter(PARAM_SET *set, MULTI_PRINTER **mp);

int extract_input_files_from_file(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err);

#ifdef	__cplusplus
}
#endif

#endif	/* TASK_INITIALIZER_H */

