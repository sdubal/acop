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
** ipfix_col.h - export declarations of ipfix collector funcs
**
** Copyright Fraunhofer FOKUS
**
** $Id: ipfix_col_db.h 23 2008-08-14 11:30:44Z tor $
**
*/
#ifndef IPFIX_COL_DB_H
#define IPFIX_COL_DB_H

#ifdef __cplusplus
extern "C" {
#endif

int  ipfix_export_newsrc_db( ipfixs_node_t *s, void *arg ) ;
int  ipfix_export_newmsg_db( ipfixs_node_t *s, ipfix_hdr_t *hdr, void *arg );
int  ipfix_export_trecord_db( ipfixs_node_t *s, ipfixt_node_t *t, void *arg );
int  ipfix_export_drecord_db( ipfixs_node_t *s, ipfixt_node_t *t,
                              ipfix_datarecord_t *d, void *arg );
void ipfix_export_cleanup_db( void *arg );
int  ipfix_export_init_db( char *dbhost, char *dbuser,
                           char *dbpw, char *dbname, void **data );

#ifdef __cplusplus
}
#endif
#endif
