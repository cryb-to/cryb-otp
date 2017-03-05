AM_CPPFLAGS = -I$(top_srcdir)/include

EXTRA_DIST =

if WITH_CRYB_TEST

libotp = $(top_builddir)/lib/otp/libcryb-otp.la

# tests
TESTS =

# c++ header test
TESTS += t_cxx
t_cxx_SOURCES = t_cxx.cc
t_cxx_CPPFLAGS = $(AM_CPPFLAGS)
t_cxx_LDADD =
if OTP_LIB
t_cxx_CPPFLAGS += -DWITH_OTP_LIB
t_cxx_LDADD += $(libotp)
endif OTP_LIB

# libcryb-otp
if OTP_LIB
endif OTP_LIB

check_PROGRAMS = $(TESTS)

endif WITH_CRYB_TEST
