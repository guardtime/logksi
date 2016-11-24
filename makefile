#
# Copyright 2013-2016 Guardtime, Inc.
#
# This file is part of the Guardtime client SDK.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
# "Guardtime" and "KSI" are trademarks or registered trademarks of
# Guardtime, Inc., and no license to trademarks is granted; Guardtime
# reserves and retains all trademark rights.

!IF "$(KSI_LIB)" != "lib" && "$(KSI_LIB)" != "dll"
KSI_LIB = lib
!ENDIF
!IF "$(RTL)" != "MT" && "$(RTL)" != "MTd" && "$(RTL)" != "MD" && "$(RTL)" != "MDd"
!IF "$(KSI_LIB)" == "lib"
RTL = MT
!ELSE
RTL = MD
!ENDIF
!ENDIF

!IF "$(INSTALL_MACHINE)" == "x64"
INSTM = 64
!ELSE IF "$(INSTALL_MACHINE)" == "x86"
INSTM = 32
!ELSE
INSTM = $(INSTALL_MACHINE)
!ENDIF


SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

PARAMSET_OBJ_DIR = $(OBJ_DIR)\param_set
TOOL_BOX_OBJ_DIR = $(OBJ_DIR)\tool_box

VERSION_FILE = VERSION
COMM_ID_FILE = COMMIT_ID
TOOL_NAME = logksi

EXT_LIB = libksiapi$(RTL).lib \
	user32.lib gdi32.lib advapi32.lib Ws2_32.lib
	
	
CCFLAGS = /nologo /W4 /D_CRT_SECURE_NO_DEPRECATE  /I$(KSI_DIR)\include
LDFLAGS = /NOLOGO /LIBPATH:"$(KSI_DIR)\$(KSI_LIB)"

!IF "$(KSI_LIB)" == "dll"
CCFLAGS = $(CCFLAGS) /DDLL_BUILD
!MESSAGE LNINKING AGAINST DLL
!ENDIF

!IF "$(RTL)" == "MT" || "$(RTL)" == "MD"
CCFLAGS = $(CCFLAGS) /DNDEBUG /O2
LDFLAGS = $(LDFLAGS) /RELEASE
!ELSE
CCFLAGS = $(CCFLAGS) /D_DEBUG /Od /RTC1 /Zi
LDFLAGS = $(LDFLAGS) /DEBUG
!ENDIF

!IF "$(LNK_CURL)" == "yes" || "$(LNK_CURL)" == "YES"
LDFLAGS = $(LDFLAGS) /LIBPATH:"$(CURL_DIR)\$(KSI_LIB)"
CCFLAGS = $(CCFLAGS) /I"$(CURL_DIR)\include"
CCFLAGS = $(CCFLAGS) /DCURL_STATICLIB
EXT_LIB = $(EXT_LIB) libcurl$(RTL).lib
!ENDIF

!IF "$(LNK_OPENSSL)" == "yes" || "$(LNK_OPENSSL)" == "YES"
LDFLAGS = $(LDFLAGS) /LIBPATH:"$(OPENSSL_DIR)\$(KSI_LIB)"
CCFLAGS = $(CCFLAGS) /I"$(OPENSSL_DIR)\include"
EXT_LIB = $(EXT_LIB) libeay32$(RTL).lib
!ENDIF

!IF "$(LNK_WININET)" == "yes" || "$(LNK_WININET)" == "YES"
EXT_LIB = $(EXT_LIB) wininet.lib
!ENDIF

!IF "$(LNK_WINHTTP)" == "yes" || "$(LNK_WINHTTP)" == "YES"
EXT_LIB = $(EXT_LIB) winhttp.lib
!ENDIF

!IF "$(LNK_CRYPTOAPI)" == "yes" || "$(LNK_CRYPTOAPI)" == "YES"
EXT_LIB = $(EXT_LIB) crypt32.lib
!ENDIF


CCFLAGS = $(CCFLAGS) $(CCEXTRA)
LDFLAGS = $(LDFLAGS) $(LDEXTRA)

VER = \
!INCLUDE <$(VERSION_FILE)>


!IF [git log -n1 --format="%H">$(COMM_ID_FILE)] == 0
COM_ID = \
!INCLUDE <$(COMM_ID_FILE)>
!MESSAGE Git OK. Include commit ID $(COM_ID).
!IF [rm $(COMM_ID_FILE)] == 0
!MESSAGE File $(COMM_ID_FILE) deleted.
!ENDIF
!ELSE
!MESSAGE Git is not installed. 
!ENDIF 


default: $(BIN_DIR)\$(TOOL_NAME).exe 

build_objects:
	cd $(SRC_DIR)
	nmake /S RTL=$(RTL) VERSION=$(VER) TOOL_NAME=$(TOOL_NAME) COM_ID=$(COM_ID) CCEXTRA="$(CCFLAGS)" LDEXTRA="$(LDFLAGS)"
	cd ..

$(BIN_DIR)\$(TOOL_NAME).exe: error_handling_build_tool $(BIN_DIR) build_objects
	link $(LDFLAGS) /OUT:$@ $(PARAMSET_OBJ_DIR)\*.obj $(TOOL_BOX_OBJ_DIR)\*.obj $(OBJ_DIR)\*.obj $(EXT_LIB)
!IF "$(KSI_LIB)" == "dll"
	xcopy "$(KSI_DIR)\$(KSI_LIB)\libksiapi$(RTL).dll" "$(BIN_DIR)\" /Y
!IF "$(LNK_CURL)" == "yes" || "$(LNK_CURL)" == "YES"
!IF "$(RTL)" == "MT" || "$(RTL)" == "MD"
	copy "$(CURL_DIR)\$(KSI_LIB)\libcurl$(RTL).dll" "$(BIN_DIR)\libcurl.dll" /Y
!ELSE
	copy "$(CURL_DIR)\$(KSI_LIB)\libcurl$(RTL).dll" "$(BIN_DIR)\libcurl_debug.dll" /Y
!ENDIF
!ENDIF
!ENDIF

$(BIN_DIR):
	@if not exist $@ mkdir $@


installer: error_handling_installer $(BIN_DIR)\$(TOOL_NAME).exe
	cd packaging\win
	nmake VERSION=$(VER) TOOL_NAME=$(TOOL_NAME) INSTALL_MACHINE=$(INSTM) KSI_LIB=$(KSI_LIB)
	cd ..\..


error_handling_build_tool:
	@echo ""
!IFNDEF KSI_DIR
	@echo "ERROR: KSI_DIR is not specified! Specify KSI_DIR as path to directory"
	@echo "       containing libksi (KSI C SDK) sub directories lib and include."
	@echo "       See README for more information."
	@exit 1
!ENDIF
!IF "$(LNK_WININET)" != "yes" && "$(LNK_WINHTTP)" != "yes" && "$(LNK_CURL)" != "yes"
	@echo "ERROR: Network provider library not spcified!"
	@echo "       Specify one of the following that matches with the libksi (KSI C SDK):"
	@echo "       LNK_WININET=yes, LNK_WINHTTP=yes or LNK_CURL=yes."
	@echo "       See README for more information."
	@exit 1
!ENDIF
!IF "$(LNK_CURL)" == "yes"
!IFNDEF CURL_DIR
	@echo "ERROR: LNK_CURL is specified but CURL_DIR is not! Specify CURL_DIR as"
	@echo "       path to directory containing curl sub directories lib and include."
	@echo "       See README for more information."
	@exit 1
!ENDIF
!ENDIF
!IF "$(LNK_CRYPTOAPI)" != "yes" && "$(LNK_OPENSSL)" != "yes"
	@echo "ERROR: Cryptographic provider library not spcified!"
	@echo "       Specify one of the following that matches with the libksi (KSI C SDK):"
	@echo "       LNK_OPENSSL=yes or LNK_CRYPTOAPI=yes."
	@echo "       See README for more information."
	@exit 1
!ENDIF
!IF "$(LNK_OPENSSL)" == "yes"
!IFNDEF OPENSSL_DIR
	@echo "ERROR: LNK_OPENSSL is specified but OPENSSL_DIR is not! Specify OPENSSL_DIR as"
	@echo "       path to directory containing OpenSSL sub directories lib and include."
	@echo "       See README for more information."
	@exit 1
!ENDIF
!ENDIF

error_handling_installer:
	@echo ""
!IF "$(INSTM)" != "32" && "$(INSTM)" != "64"
	@echo "ERROR: When building KSI tool Windows installer INSTALL_MACHINE"
	@echo "       must be specfied as INSTALL_MACHINE=32 or INSTALL_MACHINE=64."
	@exit 1
!ENDIF
!IF [candle.exe > nul] != 0
	@echo "ERROR: Program candle.exe is missing. Please install WiX to build installer."
	@exit 1
!ENDIF
!IF [light.exe > nul] != 0
	@echo "Program light.exe is missing. Please install WiX to build installer."
	@exit 1
!ENDIF


clean:
	cd $(SRC_DIR)
	nmake RTL=$(RTL) VERSION=$(VER) TOOL_NAME=$(TOOL_NAME) COM_ID=$(COM_ID) clean
	cd ..
	
	cd packaging\win
	nmake VERSION=$(VER) TOOL_NAME=$(TOOL_NAME) INSTALL_MACHINE=$(INSTM) KSI_LIB=$(KSI_LIB) clean
	cd ..
	
	@for %i in ($(OBJ_DIR) $(BIN_DIR)) do @if exist .\%i rmdir /s /q .\%i