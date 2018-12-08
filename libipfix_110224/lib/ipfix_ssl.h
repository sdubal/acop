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
 *
 * ipfix_ssl.h - export declarations of ipfix_ssl.c
 *
 * Copyright Fraunhofer FOKUS
 *
 * $Id: ipfix_ssl.h 22 2008-08-12 08:34:40Z tor $
 *
 */
#ifndef IPFIX_SSL_H
#define IPFIX_SSL_H

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"

extern int openssl_is_init;

void ipfix_ssl_opts_free( ipfix_ssl_opts_t *opts );
int  ipfix_ssl_opts_new( ipfix_ssl_opts_t **opts,
                         ipfix_ssl_opts_t *vals );
int  ipfix_ssl_setup_client_ctx( SSL_CTX **ctx,
                                 SSL_METHOD *method,
                                 ipfix_ssl_opts_t *vals );
int  ipfix_ssl_setup_server_ctx( SSL_CTX **ctx,
                                 SSL_METHOD *method,
                                 ipfix_ssl_opts_t *vals );
long ipfix_ssl_post_connection_check( SSL *ssl, char *host );

#endif
