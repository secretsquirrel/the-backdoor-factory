@ECHO OFF
ECHO --- Building aPLib Watcom C/C++ example ---
ECHO.

wcl386 /oneax /oe /oh /5r /zc -zld /i=..\lib\omf appack.c /"library ..\lib\omf\aplib"
