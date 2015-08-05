//---------------------------------------------------------------------------
// apackcsample.c
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
// Header Guard
#ifndef aspacksamplecH
#define aspacksamplecH
//---------------------------------------------------------------------------


//---------------------------------------------------------------------------
// Calling Convenction (depends on library)
// This version works with watcom version of the lib
//#define STDPREFIX __stdcall
#define STDPREFIX __cdecl
//---------------------------------------------------------------------------


//---------------------------------------------------------------------------
// Forward declarations
//
typedef STDPREFIX int (callbackfuncdef)(unsigned int insize, unsigned int inpos, unsigned int outpos, void *cbparam);
typedef STDPREFIX void (resultcallbackfundef)(char *errorstring,int errorcode);
//
int STDPREFIX samplecallback(unsigned int insize, unsigned int inpos, unsigned int outpos, void *cbparam);
void STDPREFIX sampleresultcallback(char *errorstr);
//
unsigned int ratio(unsigned int x, unsigned int y);
int compress_file(const char *oldname, const char *packedname,callbackfuncdef *callbackfp,resultcallbackfundef *resultcallbackfp);
int decompress_file(const char *packedname, const char *newname,callbackfuncdef *callbackfp,resultcallbackfundef *resultcallbackfp);
int samplemain(int argc, char *argv[]);
void show_syntax(void);
//---------------------------------------------------------------------------






//---------------------------------------------------------------------------
// Header Guard
#endif
//---------------------------------------------------------------------------