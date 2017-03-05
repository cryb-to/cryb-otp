AM_CPPFLAGS = -I$(top_srcdir)/include

libotp = $(top_builddir)/lib/otp/libcryb-otp.la

libexec_PROGRAMS = login_otp

login_otp_SOURCES = login_otp.c
login_otp_LDADD = $(libotp)

dist_man8_MANS = login_otp.8
