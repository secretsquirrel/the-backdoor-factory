@ECHO OFF
ECHO --- Building aPLib TMT Pascal example ---
ECHO.

tmtpc -C aplibu.pas
tmtpc -$LOGO- appack.pas
tmtpc -$LOGO- apunpack.pas
