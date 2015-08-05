@ECHO OFF
ECHO --- Building aPLib .NET dll wrapper ---
ECHO.

csc /nologo /w:3 /t:library /debug- /o+ /out:IbsenSoftware.aPLib.dll IbsenSoftware\aPLib\*.cs
