#
#
# $Id: Makefile.in,v 1.2 2005/01/04 09:25:12 luz Exp $
# 
# Makefile
SHELL = /bin/sh
top_srcdir = .
prefix = /usr/local

SUBDIRS       = lib src

all: compile

rmtarget clean distclean:
	@ for DIR in $(SUBDIRS) ; \
        do \
                ( \
                cd ./$$DIR; $(MAKE) $@; \
                ); \
        done

compile:
	@ for DIR in $(SUBDIRS) ; \
        do \
                ( \
                cd ./$$DIR; $(MAKE); \
                ); \
        done

install: 
	@ for DIR in $(SUBDIRS) ; \
        do \
                ( \
                cd ./$$DIR; $(MAKE) $@; \
                ); \
        done

