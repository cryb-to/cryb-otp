AM_CPPFLAGS = -I$(top_srcdir)/include

EXTRA_DIST =

if HAVE_CRYB_TEST

libotp = $(top_builddir)/lib/otp/libcryb-otp.la

# tests
TESTS =

# c++ header test
TESTS += t_cxx
t_cxx_SOURCES = t_cxx.cc
t_cxx_CPPFLAGS = $(AM_CPPFLAGS) $(CRYB_CORE_CFLAGS)
t_cxx_LDADD =
if CRYB_OTP
t_cxx_CPPFLAGS += -DWITH_CRYB_OTP
t_cxx_LDADD += $(libotp)
endif CRYB_OTP

# libcryb-otp
if CRYB_OTP
endif CRYB_OTP

check_PROGRAMS = $(TESTS)

endif HAVE_CRYB_TEST
