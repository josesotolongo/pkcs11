#pragma once
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType __declspec(dllexport) name
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif


#include <Windows.h>
#include <pkcs11.h>
#include <iostream>
#include <stdio.h>
using namespace std;

//functions typedefs
typedef CK_RV(__cdecl* Initialize)(CK_VOID_PTR);
typedef CK_RV(__cdecl* Finalize)(CK_VOID_PTR);
typedef CK_RV(__cdecl* GetInfo)(CK_INFO_PTR);

typedef CK_RV(__cdecl* SlotList)(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);
typedef CK_RV(__cdecl* GetSlotInfo)(CK_SLOT_ID, CK_SLOT_INFO_PTR);
typedef CK_RV(__cdecl* TokenInfo)(CK_SLOT_ID, CK_TOKEN_INFO_PTR);

class crypt
{
public:
	crypt();
	crypt(LPCWSTR libPath);

	~crypt();

	void LoadDLL(LPCWSTR libPath);
	void InitializeCrypto();
	bool IsLoaded();
	
	void DisplayInfo();					// Displays information of the current cryptoki library being used.
	void DisplayTokenInfo();			// Displays the information of the current token.

	CK_SLOT_INFO GetFirstSlotInfo();
private:
	HINSTANCE instLib;

	CK_SLOT_ID_PTR GetSlotList();
	CK_TOKEN_INFO GetTokenInfo(CK_SLOT_ID_PTR slotList);
};