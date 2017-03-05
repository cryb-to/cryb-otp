AM_CPPFLAGS = -I$(top_srcdir)/include

bin_PROGRAMS = otpkey

otpkey_SOURCES = otpkey.c
dist_man1_MANS = otpkey.1

if WITH_SETUID
install-exec-hook:
	chmod u+s $(DESTDIR)$(bindir)/otpkey$(EXEEXT)
endif WITH_SETUID
