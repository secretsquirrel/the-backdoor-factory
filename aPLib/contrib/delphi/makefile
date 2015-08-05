##
## aPLib compression library  -  the smaller the better :)
##
## Delphi example makefile (Borland make)
##
## Copyright (c) 1998-2009 by Joergen Ibsen / Jibz
## All Rights Reserved
##

# Add -DDYNAMIC_VERSION to the dccflags variable to link with the
# dll interface (remember to copy the aPLib dll here).

libdir   = ..\..\lib\omf

target   = aptest.exe
objects  = t_main.dcu aplib.dcu aplibu.dcu aplibud.dcu aptest.dpr $(libdir)\aplib.obj $(libdir)\depack.obj $(libdir)\depackf.obj

dcc      = dcc32.exe
dccflags = -Q -$A+ -$O+ -$D-

.phony: clean

$(target): $(objects)
	$(dcc) $(dccflags) aptest.dpr

.pas.dcu:
	$(dcc) $(dccflags) $<

clean:
	del $(target)
	del *.dcu
