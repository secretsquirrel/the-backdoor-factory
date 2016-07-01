AC_PREREQ(2.60)

AC_INIT([osslsigncode], [1.7.1], [pallansson@gmail.com])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([osslsigncode.c])

dnl Checks for programs.
AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS

AC_ARG_ENABLE(
	[strict],
	[AS_HELP_STRING([--enable-strict],[enable strict compile mode @<:@disabled@:>@])],
	,
	[enable_strict="no"]
)

AC_ARG_ENABLE(
	[pedantic],
	[AS_HELP_STRING([--enable-pedantic],[enable pedantic compile mode @<:@disabled@:>@])],
	,
	[enable_pedantic="no"]
)

AC_ARG_WITH(
	[curl],
	[AS_HELP_STRING([--with-curl],[enable curl @<:@enabled@:>@])],
	,
	[with_curl="yes"]
)

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes";
	CFLAGS="${CFLAGS} -pedantic"
fi
if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wall -Wextra"
fi

PKG_PROG_PKG_CONFIG
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MKDIR_P
AC_PROG_SED
AC_PROG_MAKE_SET

AC_C_CONST
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS(
	[sys/mman.h],
	[AC_CHECK_FUNC(
		[mmap],
		[AC_DEFINE(HAVE_MMAP, [1], [Define to 1 if you have mmap])],
		[AC_MSG_ERROR([Need mmap to build.])]
	)],
	[have_mmap=no]
)
AC_CHECK_HEADERS(
	[windows.h],
	[],
	[have_MapViewOfFile=no]
)
AS_IF([test "x$have_mmap$have_MapViewOfFile" = "xnono"],
	[AC_MSG_ERROR([Need file mapping function to buid.])])

AC_CHECK_LIB(
	[dl],
	[dlopen],
	[DL_LIBS="-ldl"]
)

AC_CHECK_HEADERS([termios.h])
AC_CHECK_FUNCS(getpass)

AC_ARG_WITH([gsf],
        AS_HELP_STRING([--without-gsf], [Ignore presence of libgsf and disable it])
)
AS_IF([test "x$with_gsf" != "xno"],
        [PKG_CHECK_MODULES([GSF], [libgsf-1], [have_gsf=yes], [have_gsf=no])],
        [have_gsf=no]
)
AS_IF([test "x$have_gsf" = "xyes"],
        [AC_DEFINE([WITH_GSF], 1, [Have libgsf?])],
        [AS_IF([test "x$with_gsf" = "xyes"],
                [AC_MSG_ERROR([libgsf requested but not found])])]
)


PKG_CHECK_MODULES(
	[OPENSSL],
	[libcrypto >= 0.9.8],
	,
	[PKG_CHECK_MODULES(
		[OPENSSL],
		[openssl >= 0.9.8],
		,
		[AC_CHECK_LIB(
			[crypto],
			[RSA_verify],
			[OPENSSL_LIBS="-lcrypto ${SOCKETS_LIBS} ${DL_LIBS}"],
			[AC_MSG_ERROR([OpenSSL 0.9.8 or later is required. http://www.openssl.org/])],
			[${DL_LIBS}]
		)]
	)]
)

PKG_CHECK_MODULES(
	[LIBCURL],
	[libcurl >= 7.12.0],
	,
	[AC_CHECK_LIB(
		[curl],
		[curl_easy_strerror],
		[LIBCURL_LIBS="-lcurl"],
		,
		[${DL_LIBS}]
	)]
)

if test "${with_curl}" = "yes"; then
	test -z "${LIBCURL_LIBS}" && AC_MSG_ERROR([Curl 7.12.0 or later is required for timestamping support. http://curl.haxx.se/])
	OPTIONAL_LIBCURL_CFLAGS="${LIBCURL_CFLAGS}"
	OPTIONAL_LIBCURL_LIBS="${LIBCURL_LIBS}"
	AC_DEFINE([ENABLE_CURL], [1], [libcurl is enabled])
fi

AC_SUBST([OPTIONAL_LIBCURL_CFLAGS])
AC_SUBST([OPTIONAL_LIBCURL_LIBS])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
