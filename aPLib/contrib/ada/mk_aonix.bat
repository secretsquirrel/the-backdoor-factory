@ECHO OFF
ECHO --- Building aPLib Ada example for Aonix ObjectAda for Windows ---
ECHO.

SET OAPATH=C:\Program Files\Aonix\ObjectAda\bin\

if not exist "%OAPATH%adareg.exe" echo Wrong path [%OAPATH%] - change mk_aonix.bat!

if exist unit.map goto build

"%OAPATH%adareg" *.ad?
ECHO.

:build

"%OAPATH%adabuild" apacdemo -ll ..\..\lib\coff\aplib.lib
ECHO.

ECHO Warning: this version doesn't work yet! :-(
