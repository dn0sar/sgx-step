LIBSGXSTEP_DIR       = ../..
LIBSGXSTEP           = $(LIBSGXSTEP_DIR)/libsgxstep
-include $(LIBSGXSTEP)/Makefile.config
-include Makefile.config

ifeq ($(SGX_SDK),)
    SGX_SDK          = /opt/intel/sgxsdk
endif
export SGX_SDK

ifndef URTS_LD_LIBRARY_PATH
    ifneq ($(SGX_SDK), /opt/intel/sgxsdk)
        URTS_LD_LIBRARY_PATH = LD_LIBRARY_PATH=$(LIBSGXSTEP_DIR)/linux-sgx/psw/urts/linux
    endif
endif

ifdef SGX_STEP_TIMER_INTERVAL
    CFLAGS += -DSGX_STEP_TIMER_INTERVAL=${SGX_STEP_TIMER_INTERVAL}
    export SGX_STEP_TIMER_INTERVAL
endif

export NUM

ifdef DEFAULT
    CFLAGS  += -DATTACK_SCENARIO=$(ATTACK_SCENARIO) -DNUM_RUNS=$(NUM) \
               -DEDBGRD=$(EDBGRD) -DDBIRQ=$(DBIRQ) -DPAGE_SIZE=$(PAGE_SIZE) \
               -DPAGES_PER_PMD=$(PAGES_PER_PMD) -DPAGES_PER_PMD=$(PAGES_PER_PMD) \
               -DDEFAULT=$(DEFAULT) -DZERO_STEP_PERCENTAGE=$(ZERO_STEP_PERCENTAGE)
endif

ENCLAVE              = Enclave
SUBDIRS              = $(ENCLAVE) $(LIBSGXSTEP)

CC                   = gcc
AS                   = gcc
LD                   = gcc

ifeq ($(M32), 1)
	ASFLAGS  = -m32 -DM32=$(M32)
	CFLAGS   = -m32 -DM32=$(M32)
	LDFLAGS  = -m32
else
	LIB_SUFX = 64
endif

CFLAGS              += -fPIC -fno-stack-protector -fno-builtin -fno-jump-tables \
                       -fno-common -Wno-attributes -g -D_GNU_SOURCE -O0
INCLUDE              = -I$(SGX_SDK)/include/ -I$(LIBSGXSTEP_DIR)
LDFLAGS             += -lsgx-step -lencl_proxy -lsgx_urts \
                       -lsgx_uae_service -pthread $(SUBDIRS:%=-L %) -L$(SGX_SDK)/lib$(LIB_SUFX)/ \
                       -L$(LIBSGXSTEP_DIR)/linux-sgx/psw/urts/linux

SOURCES              = $(shell ls *.c)
OBJECTS              = $(SOURCES:.c=.o)
OUTPUT               = app

BUILDDIRS            = $(SUBDIRS:%=build-%)
CLEANDIRS            = $(SUBDIRS:%=clean-%)

PARSE  = nop

.SILENT:
all: $(OUTPUT)

run: clean all
	sudo $(URTS_LD_LIBRARY_PATH) ./app > out.txt
	cat out.txt

ifeq ($(EDBGRD), 1)
parse: run
	SGX_STEP_PLATFORM=$(SGX_STEP_PLATFORM) ./parse_$(PARSE).py $(NUM)
else
parse:
	$(error EDBGRD must be set to one for 'make parse', for EDBGRD = 0 use make run)
endif

$(OUTPUT): $(BUILDDIRS) $(OBJECTS)
	echo "$(INDENT)[LD]" $(OBJECTS) $(LIBS) -o $(OUTPUT)
	$(LD) $(OBJECTS) $(LDFLAGS) -o $(OUTPUT)

%.o : %.c
	echo "$(INDENT)[CC] " $<
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

%.o : %.S
	echo "$(INDENT)[AS] " $<
	$(AS) $(ASFLAGS) $(INCLUDE) -c $< -o $@

clean: $(CLEANDIRS)
	echo "$(INDENT)[RM]" $(OBJECTS) $(OUTPUT)
	rm -f $(OBJECTS) $(OUTPUT)

$(BUILDDIRS):
	echo "$(INDENT)[===] $(@:build-%=%) [===]"
	$(MAKE) -C $(@:build-%=%) INDENT+="$(INDENT_STEP)" M32=$(M32) curr-dir=$(curr-dir)/$(@:build-%=%)

$(CLEANDIRS):
	echo "$(INDENT)[===] $(@:clean-%=%) [===]"
	$(MAKE) clean -C $(@:clean-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)
