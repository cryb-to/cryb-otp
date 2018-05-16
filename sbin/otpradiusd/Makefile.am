AM_CPPFLAGS = -I$(top_srcdir)/include

libotp = $(top_builddir)/lib/otp/libcryb-otp.la

sbin_PROGRAMS = otpradiusd

otpradiusd_SOURCES = \
	auth.c \
	main.c \
	network.c \
	radius.c \
	resolver.c

otpradiusd_CFLAGS = \
	$(CRYB_OATH_CFLAGS) \
	$(CRYB_DIGEST_CFLAGS) \
	$(CRYB_CORE_CFLAGS)

otpradiusd_LDADD = \
	$(libotp) \
	$(CRYB_OATH_LIBS) \
	$(CRYB_DIGEST_LIBS) \
	$(CRYB_CORE_LIBS)

dist_man8_MANS = otpradiusd.8

noinst_HEADERS = otpradiusd.h
