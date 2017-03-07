AM_CPPFLAGS = -I$(top_srcdir)/include

libotp = $(top_builddir)/lib/otp/libcryb-otp.la

moduledir = $(libdir)
module_LTLIBRARIES = pam_otp.la

pam_otp_la_SOURCES = pam_otp.c

pam_otp_la_CFLAGS = \
	$(CRYB_CORE_CFLAGS)

pam_otp_la_LIBADD = \
	$(libotp) \
	$(PAM_LIBS)

pam_otp_la_LDFLAGS = \
	-no-undefined -module -export-symbols-regex '^pam_sm_'

dist_man8_MANS = pam_otp.8
