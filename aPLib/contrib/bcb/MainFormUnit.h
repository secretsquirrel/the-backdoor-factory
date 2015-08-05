//---------------------------------------------------------------------------
// MainFormUnit.cpp
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
// Header Guard
#ifndef MainFormUnitH
#define MainFormUnitH
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
// Application Includes
#include <Classes.hpp>
#include <Controls.hpp>
#include <StdCtrls.hpp>
#include <Forms.hpp>
#include <ComCtrls.hpp>
#include <ExtCtrls.hpp>
#include <Dialogs.hpp>
//---------------------------------------------------------------------------


//---------------------------------------------------------------------------
class TMainForm : public TForm
{
private:
	bool wantscancel;
__published:
	// IDE-managed Components
	TPanel *Panel1;
	TLabel *LabelaPLib2;
	TLabel *LabelaPLib1;
	TLabel *Label5;
	TGroupBox *GroupBox1;
	TLabel *LabelResult;
	TProgressBar *ProgressBar;
	TButton *ButtonCancel;
	TButton *ButtonCompress;
	TButton *ButtonDecompress;
	TOpenDialog *OpenDialog;
	void __fastcall ButtonCompressClick(TObject *Sender);
	void __fastcall ButtonDecompressClick(TObject *Sender);
	void __fastcall ButtonCancelClick(TObject *Sender);
public:
	// constructor
	__fastcall TMainForm(TComponent* Owner);
public:
	void Initialize();
	void SetStateRunning();
	void SetStateNotRunning();
public:
	bool get_wantscancel() {return wantscancel;};
};
//---------------------------------------------------------------------------






//---------------------------------------------------------------------------
// C++ Builder Global Instance Pointer
extern PACKAGE TMainForm *MainForm;
//---------------------------------------------------------------------------





//---------------------------------------------------------------------------
// End of Header Guard
#endif
//---------------------------------------------------------------------------
