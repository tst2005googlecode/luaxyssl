/*
 *  Debugging routines
 *
 *  Copyright (C) 2006-2007  Christophe Devine
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License, version 2.1 as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include "xyssl/config.h"

#if defined(XYSSL_DEBUG_C)

#include "xyssl/debug.h"

#include <stdarg.h>
#include <stdlib.h>

static char text[256];

char *debug_format_msg( const char *format, ... )
{
    va_list argp;

    va_start( argp, format );
    vsprintf( text, format, argp );
    va_end( argp );

    return( text );
}

void debug_print_msg( char *file, int line, char *text )
{
    printf( "%s(%04d): %s\n", file, line, text );
}

void debug_print_ret( char *file, int line, char *text, int ret )
{
    printf( "%s(%04d): %s() returned %d (0x%x)\n",
            file, line, text, ret, ret );
}

void debug_print_buf( char *file, int line, char *text,
                    unsigned char *buf, int len )
{
    int i;

    if( len < 0 )
        return;

    printf( "%s(%04d): dumping '%s' (%d bytes)\n",
            file, line, text, len );

    for( i = 0; i < len; i++ )
    {
        if( i >= 4096 )
            break;

        if( i % 16 == 0 )
        {
            if( i > 0 ) printf( "\n" );
            printf( "%s(%04d): %04x: ", file, line, i );
        }

        printf( " %02x", (unsigned int) buf[i] );
    }

    if( len > 0 )
        printf( "\n" );
}

void debug_print_mpi( char *file, int line, char *text, mpi *X )
{
    int i, j, k, n, l;

    if( X == NULL )
        return;

    l = sizeof( t_int );

    for( n = X->n - 1; n >= 0; n-- )
        if( X->p[n] != 0 )
            break;

    printf( "%s(%04d): value of bignum '%s' (%d bytes) is:\n",
            file, line, text, l * ( n + 1 ) );

    for( i = n, j = 0; i >= 0; i--, j++ )
    {
        if( j % ( 16 / sizeof( t_int ) ) == 0 )
        {
            if( j > 0 ) printf( "\n" );
            printf( "%s(%04d): %04x: ", file, line, j * l );
        }

        for( k = l - 1; k >= 0; k-- )
            printf( " %02x", (unsigned int)
                ( X->p[i] >> (k << 3) ) & 0xFF );
    }

    printf( "\n" );
}

void debug_print_crt( char *file, int line, char *text, x509_cert *crt )
{
    int i = 0;
    char prefix[64], *p;

    if( crt == NULL )
        return;

    sprintf( prefix, "%s(%04d): ", file, line );

    while( crt != NULL && crt->next != NULL )
    {
        if( ( p = x509parse_cert_info( prefix, crt ) ) != NULL )
        {
            printf( "%s(%04d): %s #%d:\n%s", file, line, text, ++i, p );
            free( p );
        }

        debug_print_mpi( file, line, "crt->rsa.N", &crt->rsa.N );
        debug_print_mpi( file, line, "crt->rsa.E", &crt->rsa.E );

        crt = crt->next;
    }
}

#endif
