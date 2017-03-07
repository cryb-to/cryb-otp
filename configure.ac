AC_PREREQ([2.63])
AC_INIT([cryb.otp], [devel], [des@des.no], [cryb-otp], [http://cryb.to/])
AC_CONFIG_SRCDIR([include/cryb/otp.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign no-dist-gzip dist-xz])
AM_CONFIG_HEADER([include/config.h])

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
PKG_PROG_PKG_CONFIG
PKG_INSTALLDIR

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
# Extra libraries
#

# Cryb.to components
PKG_HAVE_WITH_MODULES([CRYB_CORE], [cryb-core],
  [Cryb.to core utilities])
PKG_HAVE_WITH_MODULES([CRYB_OATH], [cryb-oath],
  [Cryb.to Open Authentication primitives])
PKG_HAVE_WITH_MODULES([CRYB_TEST], [cryb-test],
  [Cryb.to test framework])

# libpam
save_LIBS="${LIBS}"
LIBS=""
AC_SEARCH_LIBS([pam_start], [pam], [
  PAM_LIBS="${LIBS}"
], [
  PAM_LIBS=""
])
LIBS="${save_LIBS}"
AC_SUBST(PAM_LIBS)

############################################################################
#
# Build options
#

# Documentation
AC_ARG_ENABLE([doc],
    AC_HELP_STRING([--disable-doc],
	[do not build the documentation]),
    [with_doc=$enableval])
AM_CONDITIONAL([WITH_DOC], [test x"$with_doc" != x"no"])

# Make utilities setuid
AC_ARG_ENABLE([setuid],
    AC_HELP_STRING([--disable-setuid],
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
    [CFLAGS="${CFLAGS} -Wall -Wextra -Wcast-qual -Wshadow -Wno-unused-result"])
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

# Everything
AC_ARG_ENABLE([all],
    AC_HELP_STRING([--disable-all],
        [disable all libraries and tools]),
    [enable_all=$enableval],
    [enable_all=yes])

# Library
elements="$elements lib"
AC_ARG_ENABLE([otp-lib],
    AC_HELP_STRING([--enable-otp-lib],
	[build the OTP library]),
    [enable_otp_lib=$enableval],
    [enable_otp_lib=$enable_all])
AM_CONDITIONAL([OTP_LIB], [test x"$enable_otp_lib" = x"yes"])

# BSD Auth module
elements="$elements bsdauth"
requires="$requires bsdauth:lib"
AC_ARG_ENABLE([otp-bsdauth],
    AC_HELP_STRING([--enable-otp-bsdauth],
	[build the BSD Auth module]),
    [enable_otp_bsdauth=$enableval],
    [enable_otp_bsdauth=$enable_all])
AM_CONDITIONAL([OTP_BSDAUTH], [test x"$enable_otp_bsdauth" = x"yes"])

# PAM module
elements="$elements pam"
requires="$requires pam:lib"
AC_ARG_ENABLE([otp-pam],
    AC_HELP_STRING([--enable-otp-pam],
	[build the PAM module]),
    [enable_otp_pam=$enableval],
    [enable_otp_pam=$enable_all])
AM_CONDITIONAL([OTP_PAM], [test x"$enable_otp_pam" = x"yes"])

# RADIUS server
elements="$elements radius"
requires="$requires radius:lib"
AC_ARG_ENABLE([otp-radius],
    AC_HELP_STRING([--enable-otp-radius],
	[build the RADIUS server]),
    [enable_otp_radius=$enableval],
    [enable_otp_radius=$enable_all])
AM_CONDITIONAL([OTP_RADIUS], [test x"$enable_otp_radius" = x"yes"])

# Command-line utilities
elements="$elements util"
requires="$requires util:lib"
AC_ARG_ENABLE([otp-util],
    AC_HELP_STRING([--enable-otp-util],
	[build the command-line utilities]),
    [enable_otp_util=$enableval],
    [enable_otp_util=$enable_all])
AM_CONDITIONAL([OTP_UTIL], [test x"$enable_otp_util" = x"yes"])

# Check dependencies
AC_MSG_CHECKING([dependencies])
for req in $requires ; do
    lhs=${req%:*}
    lhs_ena=`eval echo \\\$enable_otp_$lhs`
    if test x"$lhs_ena" = x"yes" ; then
        rhs=${req#*:}
	rhs_ena=`eval echo \\\$enable_otp_$rhs`
	if test x"$rhs_ena" != x"yes" ; then
	    AC_MSG_ERROR([otp-$lhs requires otp-$rhs])
	fi
    fi
done
AC_MSG_RESULT([ok])

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

echo
echo The following Cryb OTP components will be built:
echo
for elem in $elements ; do
    enable=`eval echo \\\$enable_otp_$elem`
    printf "%16s: %s\n" $elem ${enable:-no}
done
echo
