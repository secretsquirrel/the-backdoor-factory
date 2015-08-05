//---------------------------------------------------------------------------
// MainFormUnit.cpp
// bcb shell coded by mouser (9/18/04) using existing samples for delphi+c
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
// System includes and C++ Builder Stuff
#include <vcl.h>
#pragma hdrstop
//---------------------------------------------------------------------------


//---------------------------------------------------------------------------
// System includes
//#include <stdlib.h>
#include <stdio.h>
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
// Application includes
#include "MainFormUnit.h"

#include "apacksamplec.h"
#include "aplib.h"
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
// C++ Builder stuff
#pragma package(smart_init)
#pragma resource "*.dfm"
//---------------------------------------------------------------------------


//---------------------------------------------------------------------------
// Global Form Instance Pointer
TMainForm *MainForm;
//---------------------------------------------------------------------------



//---------------------------------------------------------------------------
// Compression callback sample
int STDPREFIX mainformcallback(unsigned int insize, unsigned int inpos, unsigned int outpos, void *cbparam)
{
	char resultstr[255];
	unsigned int ratioval=ratio(inpos, insize);
	sprintf(resultstr,"compressed %u -> %u bytes (%u%% done)", inpos, outpos, ratioval);
	MainForm->LabelResult->Caption=AnsiString(resultstr);
	MainForm->ProgressBar->Position=ratioval;
	// let gui update
	Application->ProcessMessages();
	// return
	if (MainForm->get_wantscancel())
		return 0;
	return 1;
}

// result callback
void STDPREFIX mainformresultcallback(char *resultstr, int errorcode)
{
	MainForm->LabelResult->Caption=AnsiString(resultstr);
	if (errorcode==0)
		MainForm->LabelResult->Font->Color=clBlack;
	else
		MainForm->LabelResult->Font->Color=clMaroon;
}
//---------------------------------------------------------------------------








//---------------------------------------------------------------------------
__fastcall TMainForm::TMainForm(TComponent* Owner)
	: TForm(Owner)
{
	// constructor
	Initialize();
}
//---------------------------------------------------------------------------





//---------------------------------------------------------------------------
void TMainForm::Initialize()
{
	// initialize the library
	SetStateNotRunning();
}

void TMainForm::SetStateRunning()
{
	// change visible state to running
	ButtonCancel->Enabled=true;
}

void TMainForm::SetStateNotRunning()
{
	// change visible state to not running
	ButtonCancel->Enabled=false;
	wantscancel=false;
	ProgressBar->Position=0;
}
//---------------------------------------------------------------------------







//---------------------------------------------------------------------------
void __fastcall TMainForm::ButtonCompressClick(TObject *Sender)
{
	// ask for file and compress it
	bool bretv;
	int retv;
	OpenDialog->Title="Browse for file to Compress..";
	bretv=OpenDialog->Execute();
	if (bretv)
		{
		// compress it
		AnsiString filename=OpenDialog->FileName;
		AnsiString newfilename=filename+".out";
		SetStateRunning();
		retv=compress_file(filename.c_str(),newfilename.c_str(),mainformcallback,mainformresultcallback);
		SetStateNotRunning();
		}
}


void __fastcall TMainForm::ButtonDecompressClick(TObject *Sender)
{
	// ask for file and decompress it
	bool bretv;
	int retv;
	OpenDialog->Title="Browse for file to Decompress..";
	bretv=OpenDialog->Execute();
	if (bretv)
		{
		// decompress it
		AnsiString filename=OpenDialog->FileName;
		AnsiString newfilename=filename+".out";
		SetStateRunning();
		retv=decompress_file(filename.c_str(),newfilename.c_str(),mainformcallback,mainformresultcallback);
		SetStateNotRunning();
		}
}
//---------------------------------------------------------------------------




//---------------------------------------------------------------------------
void __fastcall TMainForm::ButtonCancelClick(TObject *Sender)
{
	// user wants to cancel
	wantscancel=true;
}
//---------------------------------------------------------------------------




