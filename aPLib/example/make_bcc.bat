@ECHO OFF
ECHO --- Building aPLib Borland C/C++ example ---
ECHO.

bcc32 -I..\lib\omf appack.c ..\lib\omf\aplib.lib -eappack.exe
