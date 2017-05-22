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

#include "debug_print.h"
#include <string.h>
#include "printer.h"
#include "obj_printer.h"
#include "param_set/param_set.h"
#include "tool_box.h"
#include "ksi/compatibility.h"
#include "logksi_err.h"
#include <limits.h>
#include <sys/time.h>

static unsigned int elapsed_time_ms;
static int inProgress = 0;
static int timerOn = 0;


static unsigned int measureLastCall(void){
	static struct timeval thisCall = {0, 0};
	static struct timeval lastCall = {0, 0};

	gettimeofday(&thisCall, NULL);

	elapsed_time_ms = (unsigned)((thisCall.tv_sec - lastCall.tv_sec) * 1000.0 + (thisCall.tv_usec - lastCall.tv_usec) / 1000.0);

	lastCall = thisCall;
	return elapsed_time_ms;
}

void print_progressDesc(int showTiming, const char *msg, ...) {
	va_list va;
	char buf[1024];


	if (inProgress == 0) {
		inProgress = 1;
		/*If timing info is needed, then measure time*/
		if (showTiming == 1) {
			timerOn = 1;
			measureLastCall();
		}

		va_start(va, msg);
		KSI_vsnprintf(buf, sizeof(buf), msg, va);
		buf[sizeof(buf) - 1] = 0;
		va_end(va);

		print_debug("%s", buf);
	}
}

void print_progressResult(int res) {
	static char time_str[32];

	if (inProgress == 1) {
		inProgress = 0;

		if (timerOn == 1) {
			measureLastCall();

			KSI_snprintf(time_str, sizeof(time_str), " (%i ms)", elapsed_time_ms);
			time_str[sizeof(time_str) - 1] = 0;
		}

		if (res == KT_OK) {
			print_debug("ok.%s\n", timerOn ? time_str : "");
		} else {
			print_debug("failed.%s\n", timerOn ? time_str : "");
		}

		timerOn = 0;
	}
}
