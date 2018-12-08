/*

libipfix - a library which provides an implementation of the IPFIX protocol
           for flexible flow data support. IPFIX is the successor of NetFlow v9
           (see http://www.ietf.org/dyn/wg/charter/ipfix-charter.html and
            RFC5101 and RFC5102 for details) 

Copyright (c) 2005-2011, Fraunhofer FOKUS
All rights reserved.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the Free Software
Foundation; either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
details.

You should have received a copy of the GNU Lesser General Public License along with
this program; if not, see <http://www.gnu.org/licenses/>.
 */
/*
** misc.h - export declarations for misc. funcs
**
** Copyright Fraunhofer FOKUS
**
** $Id: misc.h 1023 2009-03-27 22:34:53Z csc $
**
*/
#ifndef _MISC_H
#define _MISC_H

#include <time.h>
#include <sys/time.h>

#include "config.h"
#include "hashtable.h"

#ifdef   __cplusplus
extern "C" {
#endif

/** global logfile
 */
extern int  mlog_vlevel;
extern FILE *mlog_fp;

#if !defined(HAVE_BASENAME)
char *basename(const char *file);
char *dirname (const char *file);
#else
#include <libgen.h>
#endif

#if !defined(HAVE_DAEMON)
int daemon( int nochdir, int noclose );
#endif

#if !defined(HAVE_TIMEGM)
time_t timegm( struct tm *tm ); 
#endif

int writen     ( int fd, char *ptr, int nbytes);
int read_line  ( int fd, char *ptr, int maxlen);
int readselect ( int fd, int sec);

void errorf ( char fmt[], ... ) __attribute__ ((format (printf, 1, 2)));
void debugf ( char fmt[], ... ) __attribute__ ((format (printf, 1, 2)));
void mlogf  ( int verbosity,
              char fmt[], ... ) __attribute__ ((format (printf, 2, 3)));
int  mlog_open  ( char *logfile, char *prefix );
void mlog_close ( void );
void mlog_set_vlevel( int vlevel );

char *mgettimestr( time_t t );

/** poll funcs
 */
#define MPOLL_IN        1
#define MPOLL_OUT       2
#define MPOLL_EXCEPT    4

typedef void *mptimer_t;
typedef void (*pcallback_f)(int fd, int mask, void *arg);
typedef void (*tcallback_f)(void *arg);

int       mpoll_fdadd    ( int fd, int mask, pcallback_f callback, void *arg );
void      mpoll_fdrm     ( int fd );
mptimer_t mpoll_timeradd ( int32_t sec, tcallback_f callback, void *arg );
mptimer_t mpoll_utimeradd( int32_t usec, tcallback_f callback, void *arg );
void      mpoll_timerrm  ( mptimer_t timer );
int       mpoll_loop     ( int timeout );
void      mpoll_break    ( void );
void      mpoll_cleanup  ( void );

/** sting list
 */
typedef struct mstrnode
{
    struct mstrnode *next;
    char            *str;
} mstrnode_t;

void mstrlist_free( mstrnode_t **root );

/** get/setGlobal() hashtable 
 */

struct hashtable  *ht_globals;

void     initGlobals();
void*    setGlobal(char *key, void *value);
void*    getGlobal(char *key);
void*    removeGlobal(char *key);
int      countGlobals();
void     freeGlobals();

#ifdef   __cplusplus
}
#endif
#endif 
