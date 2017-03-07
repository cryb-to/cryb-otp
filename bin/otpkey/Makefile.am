AM_CPPFLAGS = -I$(top_srcdir)/include

libotp = $(top_builddir)/lib/otp/libcryb-otp.la

bin_PROGRAMS = otpkey

otpkey_SOURCES = otpkey.c

otpkey_CFLAGS = \
	$(CRYB_CORE_CFLAGS)

otpkey_LDADD = $(libotp)

dist_man1_MANS = otpkey.1

if WITH_SETUID
install-exec-hook:
	chmod u+s $(DESTDIR)$(bindir)/otpkey$(EXEEXT)
endif WITH_SETUID
