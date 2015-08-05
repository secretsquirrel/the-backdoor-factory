@ECHO OFF
ECHO --- Building aPLib Visual C/C++ DLL example ---
ECHO.

cl /nologo /O2 /I..\lib\dll /DAP_DLL appack.c ..\lib\dll\aplib.lib

ECHO.
ECHO Remember to copy APLIB.DLL here before running.
