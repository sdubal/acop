#
#
# $Id: Makefile.in,v 1.3 2006/11/14 15:50:37 luz Exp $
# 
# Makefile
SHELL = /bin/sh

srcdir = .
top_srcdir = ..
prefix = /usr/local
exec_prefix = ${prefix}

bindir = ${exec_prefix}/bin
sbindir = ${exec_prefix}/sbin
libexecdir = ${exec_prefix}/libexec
datadir = ${datarootdir}
datarootdir = ${prefix}/share
libdir = ${exec_prefix}/lib
mandir = ${datarootdir}/man
includedir = ${prefix}/include
oldincludedir = /usr/include
top_builddir = .

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL}
INSTALL_HEADER = $(INSTALL_DATA)
CC = gcc
EXEEXT = 
INSTALL_STRIP_PROGRAM = @INSTALL_STRIP_PROGRAM@
OBJEXT = o
PACKAGE = @PACKAGE@
VERSION = @VERSION@
install_sh = @install_sh@

DEFS = -DHAVE_CONFIG_H 
CPPFLAGS = 
LDFLAGS = 
LIBS =    -L../lib/lib -I../include -L../lib/libmisc -lipfix -lmisc -lpcap
CCOPT = -Wall -g ${ARCH}
#CCOPT = -Wall -g 
INCLS = -I. -I..  -I../include  -I../lib/lib -I../lib/libmisc
CFLAGS = $(CCOPT) $(INCLS) $(DEFS)

TARGETS = acop 
OBJS = ac_app_handlers.o \
	   ac_database.o \
	   acop_data_exporter.o \
	   acop.o

CLEANFILES = $(OBJS) $(TARGETS)

all: $(TARGETS)

clean:
	rm -f $(CLEANFILES)

distclean:
	rm -f $(CLEANFILES) Makefile

#install:

%.o : %.c
	    $(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

acop: $(OBJS)
	     $(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
#example_exporter: example_exporter.o Makefile
#	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ example_exporter.o $(LDFLAGS) $(LIBS)

#acop: acop.o ac_app_handlers.o
#	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ acop.o $(LDFLAGS) $(LIBS)


#example_collector: example_collector.o Makefile
#	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ example_collector.o $(LDFLAGS) $(LIBS)

#example_collector_db: example_collector_db.o Makefile
#	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ example_collector_db.o $(LDFLAGS) $(LIBS)

#example_collector.o: example_collector.c Makefile
#	$(CC) $(CFLAGS) $(CPPFLAGS) -c example_collector.c

#example_collector_db.o: example_collector_db.c Makefile
#	$(CC) $(CFLAGS) $(CPPFLAGS) -c example_collector_db.c

#example_exporter.o: example_exporter.c Makefile
#	$(CC) $(CFLAGS) $(CPPFLAGS) -c example_exporter.c

