@echo off
if [%1] == [L1] goto L1

cls
set testfile=aPPack.exe
call %0 L1 dynamic os2
call %0 L1 dynamic w32
call %0 L1 static  d32
call %0 L1 static  os2
call %0 L1 static  w32
goto END

:L1
echo ** %2 ** %3 **
cd %2\%3
if exist out.apk  del out.apk
if exist test.ap  del test.ap
if exist test.unp del test.unp
if [%3] == [d32] Dos4GW.exe aPPack.exe %testfile% test.ap
if [%3] == [os2]            aPPack.exe %testfile% test.ap
if [%3] == [w32] call pec   aPPack.exe %testfile% test.ap
if not exist test.ap pause
if [%3] == [d32] Dos4GW.exe aPUnpack.exe test.ap test.unp
if [%3] == [os2]            aPUnpack.exe test.ap test.unp
if [%3] == [w32] call pec   aPUnpack.exe test.ap test.unp
if not exist test.unp pause
if exist test.ap  del test.ap
if exist test.unp del test.unp
cd ..\..

:END
