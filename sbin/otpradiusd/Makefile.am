AM_CPPFLAGS = -I$(top_srcdir)/include

libotp = $(top_builddir)/lib/otp/libcryb-otp.la

sbin_PROGRAMS = otpradiusd

otpradiusd_SOURCES = otpradiusd.c

otpradiusd_CFLAGS = \
	$(CRYB_CORE_CFLAGS)

otpradiusd_LDADD = $(libotp)

dist_man8_MANS = otpradiusd.8
