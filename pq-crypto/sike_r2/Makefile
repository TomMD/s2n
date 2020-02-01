#
# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

SRCS=fips202.c P434.c
OBJS=$(SRCS:.c=.o)

ifndef S2N_NO_PQ_ASM
SHOULD_DISABLE_PQ_ASM = 1
ARCH := $(shell uname -p)
KERNEL := $(shell uname -s)
ifeq ($(KERNEL), Linux)
ifeq ($(ARCH), x86_64)
# Using $(CC) here (instead of directly using gcc) because $(CC) may be set to
# things such as: cc, gcc, gcc-4.9, etc. This should work for all of them.
GCC_FULL_VERSION := $(shell $(CC) --version | grep ^$(CC) | sed 's/^.* //g')
ifeq ($(shell expr "$(GCC_FULL_VERSION)" ">=" "4.9"), 1)
# Linux, x86_64, and GCC >= 4.9 detected, default to optimized ASM
ASRC=fp_x64_asm.S
OBJS+=$(ASRC:.S=.o)
SHOULD_DISABLE_PQ_ASM = 0
endif
endif
endif
ifeq ($(SHOULD_DISABLE_PQ_ASM), 1)
CFLAGS += -DS2N_NO_PQ_ASM
endif
endif

# TODO add when ready for SIKE R2 SAW proofs
#BCS_1=fips202.bc P434.bc
#BCS=$(addprefix $(BITCODE_DIR), $(BCS_1))

.PHONY : all
all: $(OBJS)

# TODO add when ready for SIKE R2 SAW proofs
#.PHONY : bc
#bc: $(BCS)

include ../../s2n.mk
