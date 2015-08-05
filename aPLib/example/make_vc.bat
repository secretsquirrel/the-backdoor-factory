@ECHO OFF
ECHO --- Building aPLib Visual C/C++ example ---
ECHO.

cl /nologo /O2 /I..\lib\coff appack.c ..\lib\coff\aplib.lib
