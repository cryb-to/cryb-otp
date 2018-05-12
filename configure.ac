AC_PREREQ([2.63])
AC_INIT([cryb.otp], [0.20180506], [des@des.no], [cryb-otp], [http://cryb.to/])
AC_CONFIG_SRCDIR([include/cryb/otp.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign no-dist-gzip dist-xz])
AM_CONFIG_HEADER([include/config.h])
AM_MAINTAINER_MODE([enable])

############################################################################
#
# Toolchain
#

# C compiler and features
AC_LANG(C)
AC_PROG_CC([clang gcc cc])
AC_PROG_CC_STDC
AC_PROG_CPP
AC_PROG_CXX([clang++ g++ c++])
AC_GNU_SOURCE
AC_C_CONST
AC_C_RESTRICT
AC_C_VOLATILE
AC_C_BIGENDIAN
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_INTMAX_T
AC_TYPE_INTPTR_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_TYPE_UINTMAX_T
AC_TYPE_UINTPTR_T

# libtool
LT_PREREQ([2.2.6])
LT_INIT()

# pkg-config
AX_PROG_PKG_CONFIG

# other programs
AC_PROG_INSTALL

############################################################################
#
# Headers and functions
#

AC_CHECK_HEADERS([endian.h sys/endian.h])
AX_GCC_BUILTIN([__builtin_bswap16])
AX_GCC_BUILTIN([__builtin_bswap32])
AX_GCC_BUILTIN([__builtin_bswap64])
AC_CHECK_DECLS([
    bswap16, bswap32, bswap64,
    be16enc, be16dec, le16enc, le16dec,
    be32enc, be32dec, le32enc, le32dec,
    be64enc, be64dec, le64enc, le64dec,
    htobe16, be16toh, htole16, le16toh,
    htobe32, be32toh, htole32, le32toh,
    htobe64, be64toh, htole64, le64toh,
    nothing
], [], [], [[
#if HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#if HAVE_ENDIAN_H
#include <endian.h>
#endif
]])
AC_CHECK_FUNCS([strlcat strlcmp strlcpy])
AC_CHECK_FUNCS([wcslcat wcslcmp wcslcpy])

############################################################################
#
# Build options
#

# Documentation
AC_ARG_ENABLE([doc],
    AS_HELP_STRING([--disable-doc],
	[do not build the documentation]),
    [with_doc=$enableval])
AM_CONDITIONAL([WITH_DOC], [test x"$with_doc" != x"no"])

# Make utilities setuid
AC_ARG_ENABLE([setuid],
    AS_HELP_STRING([--disable-setuid],
	[do not set the setuid bit on command-line utilities]),
    [enable_setuid=$enableval],
    [enable_setuid=yes])
AM_CONDITIONAL([WITH_SETUID], [test x"$enable_setuid" = x"yes"])

############################################################################
#
# Debugging
#

# Developer-friendly compiler flags
AC_ARG_ENABLE([developer-warnings],
    AS_HELP_STRING([--enable-developer-warnings],
	[enable strict warnings (default is NO)]),
    [CFLAGS="${CFLAGS} -Wall -Wextra -Wcast-qual -Wshadow"])
AC_ARG_ENABLE([debugging-symbols],
    AS_HELP_STRING([--enable-debugging-symbols],
	[enable debugging symbols (default is NO)]),
    [CFLAGS="${CFLAGS} -O0 -g -fno-inline"])
AC_ARG_ENABLE([werror],
    AS_HELP_STRING([--enable-werror],
	[use -Werror (default is NO)]),
    [CFLAGS="${CFLAGS} -Werror"])

############################################################################
#
# Components
#
CRYB_INIT

CRYB_LIB_REQUIRE([digest test])

CRYB_LIB_PROVIDE([otp], [core oath])

CRYB_PROVIDE([bsdauth],	[otp])
CRYB_PROVIDE([pam],	[otp])
CRYB_PROVIDE([radius],	[otp])
CRYB_PROVIDE([cli],	[otp])

if test x"$enable_cryb_pam" = x"yes" ; then
    save_LIBS="${LIBS}"
    LIBS=""
    AC_CHECK_LIB([pam], [pam_start], [], [
        AC_MSG_ERROR([libpam is required to build the PAM module])
    ])
    PAM_LIBS="${LIBS}"
    LIBS="${save_LIBS}"
    AC_SUBST(PAM_LIBS)
fi

CRYB_RESOLVE

############################################################################
#
# Output
#

AC_CONFIG_FILES([
    Makefile
    include/Makefile
    include/cryb/Makefile
    lib/Makefile
    lib/otp/Makefile
    lib/otp/cryb-otp.pc
    pam/Makefile
    pam/pam_otp/Makefile
    libexec/Makefile
    libexec/login_otp/Makefile
    bin/Makefile
    bin/otpkey/Makefile
    sbin/Makefile
    sbin/otpradiusd/Makefile
    t/Makefile
])
AC_OUTPUT

CRYB_SUMMARY
