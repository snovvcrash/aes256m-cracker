#
# Makefile
#
# AES-256-M
# by snovvcrash
# 12.2016
#

CXXTARGET=aes256m
CTARGET=

CXX=g++
CC=gcc

CXXFLAGS+=-c -Wall -std=c++11 -O2
CFLAGS=-c -Wall
LDFLAGS=-Wall -pthread

HEADERS=$(wildcard *.h) $(wildcard */*.h)
CXXSOURCES=$(wildcard *.cxx) $(wildcard */*.cxx)
CXXOBJECTS=$(patsubst %.cxx, %.o, $(CXXSOURCES))
CSOURCES=$(wildcard *.c) $(wildcard */*.c)
COBJECTS=$(patsubst %.c, %.o, $(CSOURCES))

.PHONY: cxxbuild cbuild all default clean
.PRECIOUS: $(CXXTARGET) $(CTARGET) $(CXXOBJECTS) $(COBJECTS)

all: clean default
default: cxxbuild
cxxbuild: $(CXXTARGET)
	@echo "Build cxx-project"
cbuild: $(CTARGET)
	@echo "Build c-project"

$(CXXTARGET): $(CXXOBJECTS)
	@echo "(CXX) $?"
	@$(CXX) $(CXXOBJECTS) -o $@ $(LDFLAGS)

$(CTARGET): $(COBJECTS)
	@echo "(CC) $?"
	@$(CC) $(COBJECTS) -o $@ $(LDFLAGS)
	
%.o: %.cxx $(HEADERS)
	@echo "(CXX) $<"
	@$(CXX) $(CXXFLAGS) $< -o $@

%.o: %.c $(HEADERS)
	@echo "(CC) $<"
	@$(CC) $(CFLAGS) $< -o $@

debug: CXXFLAGS+=-DDEBUG -g -O0
debug: CFLAGS+=-DDEBUG -g -O0
debug: all
	@echo "DEBUG MODE"

clean:
	@echo "Clean project"
	@rm -rfv *.o */*.o $(CXXTARGET) $(CTARGET)
