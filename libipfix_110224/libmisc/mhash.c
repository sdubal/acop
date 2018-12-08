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
/**************************************************************************
 *
 * mhash.c - miscellaneous hashtable functions.
 *
 * Copyright Fraunhofer FOKUS
 *
 * $Date: 2009-03-27 21:48:11 +0100 (Fri, 27 Mar 2009) $
 *
 * $Revision: 1.2 $
 *
 **************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>

#include "misc.h"
#include "hashtable.h"

static unsigned int dj2b_hash_from_char_fn( void *strp ) { /* char* */
  char * str = (char*) strp;
  unsigned int hash = 5381;
  int c;

  while ((c = *str++))
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
  return hash;
}

static int char_equal_fn ( void *key1, void *key2 ) { /* char* x2 */
  int l1, l2;
  if ((!key1)||(!key2)) return 0;
  l1 = strlen(key1); 
  l2 = strlen(key2);
  return l1!=l2?0:strncmp(key1, key2, strlen(key1))==0;
}

void initGlobals() {
  ht_globals = create_hashtable(16, dj2b_hash_from_char_fn, char_equal_fn);
}

void* setGlobal(char *key, void *value) {
  if (! hashtable_insert(ht_globals, key, value) ) {
     return 0;
  }
  return value;
}

void* getGlobal(char *key) {
  void *found;
  if (NULL == (found = hashtable_search(ht_globals, key) )) {
    return 0;
  }
  return found;
}

void* removeGlobal(char *key) {
  void *found;
  if (NULL == (found = hashtable_remove(ht_globals, key) )) {
    return 0;
  }
  return found;
}

int countGlobals() {
  return hashtable_count(ht_globals);
}

void freeGlobals() {
  hashtable_destroy(ht_globals, 1); /* second arg indicates "free(value)", might have to be set to zero if necessary */
}
