AUTOMAKE_OPTIONS = foreign 1.10
MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ $(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/ylwrap \
	$(srcdir)/config.guess $(srcdir)/config.sub
EXTRA_DIST = .gitignore

AM_CFLAGS = $(GSF_CFLAGS) $(OPENSSL_CFLAGS) $(OPTIONAL_LIBCURL_CFLAGS)

bin_PROGRAMS = osslsigncode

osslsigncode_SOURCES = osslsigncode.c
osslsigncode_LDADD = $(GSF_LIBS) $(OPENSSL_LIBS) $(OPTIONAL_LIBCURL_LIBS)
