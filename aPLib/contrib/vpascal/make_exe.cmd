@echo off
cls
rem VP base directory -- also change in vpc.cfg
set vpbase=y:\vp21
set host=os2
if [os_shell]==[] set host=w32
set vpbin=%vpbase%\bin.%host%
set beginlibpath=%vpbin%

if exist dynamic goto md1
echo *** MkDir ***
md dynamic
md dynamic\lnx
md dynamic\os2
md dynamic\w32
md static
md static\os2
md static\w32
md static\d32
md static\lnx
:md1

echo *** DLL ***

rem  OS/2
link386 /NoLogo /NoIgnoreCase /Map ..\..\lib\omf\aplib.lib,dynamic\os2\aplib.dll,dynamic\os2\aplib.map,,aplib.def
cd dynamic\os2
mapsym aplib.map > nul
del aplib.map
cd ..\..
rem if errorlevel 1 goto Error_Exit

rem  Win32
copy ..\..\lib\dll\aplib.dll dynamic\w32\aplib.dll
if errorlevel 1 goto Error_Exit

rem Linux
echo gcc -shared -nostdlib -Wl,--whole-archive aplib.a -o aplib.so > dynamic\lnx\aplib.txt

echo *** dynamic EXE ***

echo * OS/2: aPPack
set cfg=/Edynamic\os2 -CO -DDYNAMIC_VERSION @vpc.cfg
%vpbin%\vpc %cfg% aPPack.pas
if errorlevel 1 goto Error_Exit
echo * OS/2: aPUnpack
%vpbin%\vpc %cfg% aPUnpack.pas
if errorlevel 1 goto Error_Exit

echo * Win32: aPPack
set cfg=/Edynamic\w32 -CW -DDYNAMIC_VERSION @vpc.cfg
%vpbin%\vpc %cfg% aPPack.pas
if errorlevel 1 GOTO Error_Exit
echo * Win32: aPUnpack
%vpbin%\vpc %cfg% aPUnpack.pas
if errorlevel 1 goto Error_Exit

if not exist %vpbase%\units.lnx goto No_Linux_dyn
echo * Linux: aPPack
set cfg=/Edynamic\lnx -CL:LNX:LINUX -DDYNAMIC_VERSION @vpc.cfg
%vpbin%\vpc %cfg% aPPack.pas
if errorlevel 1 goto Error_Exit
%vpbin%\pe2elf -m3 dynamic\lnx\aPPack.exe
if errorlevel 1 goto Error_Exit
del dynamic\lnx\aPPack.exe
echo * Linux: aPUnpack
%vpbin%\vpc %cfg% aPUnpack.pas
if errorlevel 1 goto Error_Exit
%vpbin%\pe2elf -m3 dynamic\lnx\aPUnpack.exe
if errorlevel 1 goto Error_Exit
del dynamic\lnx\aPUnpack.exe
:No_Linux_dyn


echo *** static EXE ***

echo * OS/2: aPPack
set cfg=/Estatic\os2 -CO @vpc.cfg
%vpbin%\vpc %cfg% aPPack.pas
if errorlevel 1 goto Error_Exit
echo * OS/2: aPUnpack
%vpbin%\vpc %cfg% aPUnpack.pas
if errorlevel 1 goto Error_Exit

echo * Win32: aPPack
set cfg=/Estatic\w32 -CW @vpc.cfg
%vpbin%\vpc %cfg% aPPack.pas
if errorlevel 1 goto Error_Exit
echo * Win32: aPUnpack
%vpbin%\vpc %cfg% aPUnpack.pas
if errorlevel 1 goto Error_Exit


if not exist %vpbase%\units.d32 goto No_DPMI32
echo * DPMI32: aPPack
copy %vpbase%\bin.d32\wdosxle.exe static\d32\wdosxle.exe
set cfg=/Estatic\d32 -CW:D32:DPMI32 @vpc.cfg
%vpbin%\vpc %cfg% aPPack.pas
if errorlevel 1 goto Error_Exit
%vpbin%\pe2le static\d32\aPPack.exe static\d32\aPPack.exe /s:wdxs_le.exe
32lite -8:0 -9:0 static\d32\aPPack.exe
echo * DPMI32: aPUnpack
%vpbin%\vpc %cfg% aPUnpack.pas
if errorlevel 1 goto Error_Exit
%vpbin%\pe2le static\d32\aPUnpack.exe static\d32\aPUnpack.exe /s:wdxs_le.exe
call 32lite -8:0 -9:0 static\d32\aPUnpack.exe
:No_DPMI32

if not exist %vpbase%\units.lnx goto No_Linux
echo * Linux: aPPack
set cfg=/Estatic\lnx -CL:LNX:LINUX @vpc.cfg
%vpbin%\vpc %cfg% aPPack.pas
if errorlevel 1 goto Error_Exit
%vpbin%\pe2elf -m3 static\lnx\aPPack.exe
if errorlevel 1 goto Error_Exit
del static\lnx\aPPack.exe
echo * Linux: aPUnpack
%vpbin%\vpc %cfg% aPUnpack.pas
if errorlevel 1 goto Error_Exit
%vpbin%\pe2elf -m3 static\lnx\aPUnpack.exe
if errorlevel 1 goto Error_Exit
del static\lnx\aPUnpack.exe
:No_Linux

call LxLite static\os2\* dynamic\os2\* /U+ /F+ /ZS /T

goto End

:Error_Exit
PAUSE

:End
