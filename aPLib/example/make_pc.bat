@ECHO OFF
ECHO --- Building aPLib Pelles C example ---
ECHO.

cc /Ot /I..\lib\coff appack.c ..\lib\coff\aplib.lib
