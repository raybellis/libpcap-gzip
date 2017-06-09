# $Id$

# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([libpcap-gzip],[0.1],[ray@isc.org])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

CHECK_COMPILER_FLAG([Wall], [CFLAGS="-Wall $CFLAGS"])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_PROG_LN_S

AC_ARG_WITH(zlib,
	    [ --with-zlib=DIR          zlib install directory], [
	     	AM_CPPFLAGS="$AM_CPPFLAGS -I$withval/include"
	     	AM_LDFLAGS="$AM_LDFLAGS -L$withval/lib"
	    ])

AC_ARG_WITH(libpcap,
	    [ --with-libpcap=DIR      libpcap install directory], [
	     	AM_CPPFLAGS="$AM_CPPFLAGS -I$withval/include"
	     	AM_LDFLAGS="$AM_LDFLAGS -L$withval/lib"
	    ])

# save user flags
OLDCFLAGS="$CFLAGS"
OLDCPPFLAGS="$CPPFLAGS"
OLDLDFLAGS="$LDFLAGS"
tmp_LIBS="$LIBS"

# check for libraries using supplied flags
CPPFLAGS="$AM_CPPFLAGS $CPPFLAGS"
LDFLAGS="$AM_LDFLAGS $LDFLAGS"

AC_CHECK_LIB([z], [gzdopen])

AC_CHECK_LIB([pcap], [pcap_dump_open], [],
	     AC_MSG_ERROR([libpcap unuseable])
)

# restore user flags
CPPFLAGS="$OLDCPPFLAGS"
CFLAGS="$OLDCFLAGS"
LDFLAGS="$OLDLDFLAGS"
LIBS="$tmp_LIBS"

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h string.h])
AC_CHECK_HEADERS([zlib.h pcap.h])
AC_HEADER_STDBOOL

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS(funopen fopencookie)
AC_SUBST(AM_CPPFLAGS)
AC_SUBST(AM_CFLAGS)
AC_SUBST(AM_LDFLAGS)
AC_OUTPUT
