# $Source$
# $Id$

AC_MSG_CHECKING(for XML support)
AC_ARG_WITH(xml,
[  --with-xml              Include XML support],[
  case $withval in
    shared)
      shared=yes
      withval=yes
      ;;
    shared,*)
      shared=yes
      withval=`echo $withval | sed -e 's/^shared,//'`
      ;;
    *)
      shared=no
      ;;
  esac
  if test "$withval" != "no"; then
    if test "$shared" = "yes"; then
      AC_MSG_RESULT([yes (shared)])
    else
      AC_MSG_RESULT([yes (static)])
    fi
    if test "$withval" = "yes"; then
      test -d /usr/include/xmltok && XML_INCLUDE="-I/usr/include/xmltok"
      test -d /usr/include/xml && XML_INCLUDE="-I/usr/include/xml"
      test -d /usr/local/include/xml && XML_INCLUDE="-I/usr/local/include/xml"
      AC_CHECK_LIB(expat, main, XML_LIBS="-lexpat", XML_LIBS="-lxmlparse -lxmltok")
    else
      XML_LIBS="-L$withval/lib -lexpat"
      if test -d $withval/include/xml; then
	XML_INCLUDE="-I$withval/include/xml"
      else
	XML_INCLUDE="-I$withval/include"
      fi
    fi
    AC_DEFINE(HAVE_LIBEXPAT, 1)
    PHP_EXTENSION(xml, $shared)
    if test "$shared" != "yes"; then
      EXTRA_LIBS="$EXTRA_LIBS $XML_LIBS"
    fi
  else
    AC_MSG_RESULT(no)
  fi
],[
  AC_MSG_RESULT(no)
]) 
AC_SUBST(XML_LIBS)
AC_SUBST(XML_INCLUDE)
