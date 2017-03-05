# -------------------------------------------------------------------
#
# Copyright (c) 2017 Basho Technologies, Inc.
#
# This file is provided to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file
# except in compliance with the License.  You may obtain
# a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
# -------------------------------------------------------------------
#
# Requires:
#   - Rebar3 environment variables
#   - GNU Make functionality
#   - A Unix-y build environment
#
module	:= bitcask

env_ok	:= true
ifeq ($(REBAR_ROOT_DIR),)
env_ok	:= false
else ifeq ($(REBAR_BUILD_DIR),)
env_ok	:= false
else ifeq ($(ERLANG_ROOT_DIR),)
env_ok	:= false
endif
ifneq ($(env_ok),true)
$(error Must run in Rebar3 environment)
endif

prj_dir	:= $(abspath $(REBAR_ROOT_DIR))
version	:= $(shell git describe --tags 2>/dev/null | cut -d- -f1)

# match the 'Osname' returned by erlang os:type()
sys_type := $(shell uname -s | tr '[A-Z]' '[a-z]')
# it's unlikely there's any case variation, but make sure
sys_arch := $(shell uname -m | tr '[A-Z]' '[a-z]')
sys_rel  := $(shell uname -r | tr '[A-Z]' '[a-z]')

dist_dir := $(prj_dir)/priv

erts_inc := $(ERLANG_ROOT_DIR)/usr/include
work_dir := $(REBAR_BUILD_DIR)/lib/$(module)/_work

# base name of the NIF library that will be calculated by the loader
so_name	:= $(module)
# where it's going to end up when we're done, this is the default target
so_dest	:= $(dist_dir)/$(so_name).so

# The NIF is pretty straightforward
nif_srcs := $(wildcard $(prj_dir)/c_src/*.c)
nif_objs := $(foreach n, $(sort $(basename $(notdir \
		$(nif_srcs)))), $(work_dir)/$(n).o)
nif_deps := $(patsubst %.o,%.d,$(nif_objs))

o_level	:= -g2 -O3

LDFLAGS := -m64
CFLAGS	:= $(LDFLAGS)
CPPFLAGS := -isystem $(erts_inc) -DVERSION="$(version)"
ifeq ($(DEBUG),)
CPPFLAGS += -DNDEBUG
endif
ifneq ($(PULSE),)
CPPFLAGS += -DPULSE
endif

so_flag	:= -shared

ecp	:= /bin/cp -p
# build tools
ifeq	($(sys_type),darwin)
ecp	:= /bin/cp -pX
CC	:= /usr/bin/cc
LDFLAGS := -arch x86_64
LDFLAGS	+= $(shell test $(firstword $(subst ., ,$(sys_rel))) -lt 14 \
		|| echo '-mmacosx-version-min=10.9')
CFLAGS	:= $(LDFLAGS)
so_flag	:= -flat_namespace -undefined suppress -dynamiclib
else ifeq ($(sys_type),freebsd)
CPPFLAGS += _REENTRANT
CC	:= $(shell which cc)
else ifeq ($(sys_type),linux)
CC	:= $(shell which gcc)
else ifeq ($(sys_type),sunos)
CPPFLAGS += _REENTRANT
CC	:= $(shell which gcc)
else
$(error Unsupported platform '$(sys_type)')
endif
CFLAGS    += -std=c99 $(o_level) -fPIC -Wall -Wmissing-prototypes
LDFLAGS   += $(o_level)

ifneq ($(BITCASK_DEBUG),)
CPPFLAGS += -DBITCASK_DEBUG
endif
# bitcask uses macros to define groups of functions, some of which aren't used
CFLAGS	+= -Wno-unused-function

V	?= 0
ifeq	($(V),0)
c_verbose   = @echo ' C      ' $(<F);
cp_verbose  = @echo ' CP     ' $(@F);
d_verbose   = @echo ' DEPS   ' $(<F);
ld_verbose  = @echo ' LD     ' $(@F);
endif

.PHONY:	default dist clean clean-dist veryclean

# don't automatically clean up intermediates
.SECONDARY:

default :: dist

dist :: $(so_dest)

clean ::
	@echo Deleting work directory
	@/bin/rm -rf $(work_dir)

clean-dist :: clean
	@echo Deleting $(notdir $(so_dest))
	@/bin/rm -f $(so_dest)

veryclean :: clean-dist

# install

$(dist_dir)/% : $(work_dir)/%
	@test -d $(@D) || /bin/mkdir -p $(@D)
	$(cp_verbose) $(ecp) $< $@

# link

$(work_dir)/$(so_name).so : $(nif_objs)
	@test -d $(@D) || /bin/mkdir -p $(@D)
	$(ld_verbose) $(strip $(CC) $(so_flag) $(LDFLAGS) -o $@ $^)

# compile

$(work_dir)/%.o : $(prj_dir)/c_src/%.c
	@test -d $(@D) || /bin/mkdir -p $(@D)
	$(c_verbose) $(strip $(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $<)

# dependencies

$(work_dir)/%.d : $(prj_dir)/c_src/%.c
	@test -d $(@D) || /bin/mkdir -p $(@D)
	$(d_verbose) $(strip $(CC) -MM -E $(CFLAGS) $(CPPFLAGS) \
		-MT $@ -MT $(patsubst %.d,%.o,$@) -MF $@ $<)

ifeq ($(NO_DEPS),)
-include $(nif_deps)
endif
