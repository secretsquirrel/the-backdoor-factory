@ECHO OFF
ECHO --- Building aPLib 16bit NASM depacker examples ---
ECHO.

call nasm deppack.nas -o deppack.com
call nasm depptiny.nas -o depptiny.com
