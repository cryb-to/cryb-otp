AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = libcryb-otp.la

libcryb_otp_la_SOURCES = \
	cryb_otp_resync.c \
	cryb_otp_verify.c \
	\
	cryb_otp.c

libcryb_otp_la_CFLAGS = \
	 $(CRYB_CORE_CFLAGS) \
	 $(CRYB_OATH_CFLAGS)

libcryb_otp_la_LIBADD = \
	$(CRYB_CORE_LIBS) \
	$(CRYB_OATH_LIBS)

pkgconfig_DATA = cryb-otp.pc
