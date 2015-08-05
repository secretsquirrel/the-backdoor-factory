@ECHO OFF
ECHO --- Building aPLib Ada example for GNAT/Windows ---
ECHO.

gnatmake -g -i %1 -O2 -gnatp -aOACU_Win apacdemo -largs ..\..\lib\coff\aplib.lib

if exist b~*.* del b~*.*
