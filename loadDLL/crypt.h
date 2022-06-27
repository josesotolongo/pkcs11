#pragma once
#define CK_PTR *
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
#include <cassert>
using namespace std;

//functions typedefs
typedef CK_RV(__cdecl* Initialize)(CK_VOID_PTR);
typedef CK_RV(__cdecl* Finalize)(CK_VOID_PTR);
typedef CK_RV(__cdecl* GetInfo)(CK_INFO_PTR);
typedef CK_RV(__cdecl* GetMechanismList)(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR);
typedef CK_RV(__cdecl* GetMechanismInfo)(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR);

typedef CK_RV(__cdecl* SlotList)(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);
typedef CK_RV(__cdecl* GetSlotInfo)(CK_SLOT_ID, CK_SLOT_INFO_PTR);
typedef CK_RV(__cdecl* TokenInfo)(CK_SLOT_ID, CK_TOKEN_INFO_PTR);

typedef CK_RV(__cdecl* OpenSession)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR);
typedef CK_RV(__cdecl* CloseSession)(CK_SESSION_HANDLE);
typedef CK_RV(__cdecl* SessionInfo)(CK_SESSION_HANDLE, CK_SESSION_INFO_PTR);

typedef CK_RV(__cdecl* InitToken)(CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR);
typedef CK_RV(__cdecl* InitPin)(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG);
typedef CK_RV(__cdecl* SetPin)(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG);

//logging functions
typedef CK_RV(__cdecl* Login)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG);
typedef CK_RV(__cdecl* Logout)(CK_SESSION_HANDLE);

// Object Management Functions
typedef CK_RV(__cdecl* CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
typedef CK_RV(__cdecl* AttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
typedef CK_RV(__cdecl* GenerateKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
typedef CK_RV(__cdecl* GenerateKeyPair)
(
	CK_SESSION_HANDLE,
	CK_MECHANISM_PTR,
	CK_ATTRIBUTE_PTR,
	CK_ULONG,
	CK_ATTRIBUTE_PTR,
	CK_ULONG,
	CK_OBJECT_HANDLE_PTR,
	CK_OBJECT_HANDLE_PTR
);

enum LogLevel
{
	INFO,
	WARN,
};

class crypt
{
private:
	// Handles
	HINSTANCE instLib;
	CK_SESSION_HANDLE hSession;

	CK_BBOOL ckTrue = TRUE;
	CK_BBOOL ckFalse = FALSE;

// Initialize class
public: 
	crypt(LPCWSTR libPath);

	void InitializeCrypto();
	void FreeCrypto();
	bool IsLoaded();
	void GetMechList();
	void GetMechInfo();
private:
	void LoadDLL(LPCWSTR libPath);

public:
	void LogAndDisplay(LogLevel severity, std::string messsage);

private:
	std::string ConvertLogLevel(LogLevel serverity);

// Display infos
public:
	void DisplayInfo();					// Displays information of the current cryptoki library being used.
	void DisplayTokenInfo();			// Displays the information of the current token.
	void DisplaySessionMenu();			// Display the Session Menu options

// Token Functions
public:
	void newToken();
	void InitTokenPin();
	void SetTokenPin();
private:
	CK_SLOT_ID_PTR GetSlotList();
	CK_TOKEN_INFO GetTokenInfo(CK_SLOT_ID_PTR slotList);
	CK_SLOT_ID GetFirstSlotId();

// Session Functions
private:
	void Open();
	void Close();
	CK_RV TokenLogin();
	CK_RV TokenLogout();
	CK_SESSION_INFO GetSessionInfo();


// Key Object
public:
	void KeyCreation();
private:
};