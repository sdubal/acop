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
** mlist.c
**
** Copyright Fraunhofer FOKUS
**
** $Date: 2008-10-14 12:40:12 +0200 (Tue, 14 Oct 2008) $
**
** $Revision: 1.1 $
**
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>

#include "misc.h"

/*------ defines ---------------------------------------------------------*/

#define xfree(p)          {if ((p)) free((p));}

/*------ stuctures -------------------------------------------------------*/

/*------ globals ---------------------------------------------------------*/

/*------ revision id -----------------------------------------------------*/

static char const cvsid[]="$Id: mlist.c 956 2008-10-14 10:40:12Z hir $";

/*------ export funcs ----------------------------------------------------*/

/*
 * name       : mstrlist_free
 * description: 
 */
void mstrlist_free( mstrnode_t **root )
{
    mstrnode_t *n;

    if ( root==NULL )
        return;
    else
        n = *root;

    while ( n ) {
        n = (*root)->next;
        xfree( (*root)->str );
        xfree( (*root) );
        *root = n;
    }
}
