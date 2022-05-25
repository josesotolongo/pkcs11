#include "crypt.h"

#pragma region Constructors
crypt::crypt(LPCWSTR libPath)
{
	LoadDLL(libPath);
}
#pragma endregion

#pragma region Load and Free
void crypt::LoadDLL(LPCWSTR libPath)
{
	HINSTANCE hinstLib = LoadLibrary((libPath));
	if (hinstLib == NULL)
	{
		return;
	}
	instLib = hinstLib;
}

void crypt::InitializeCrypto()
{
	CK_C_INITIALIZE_ARGS initArgs;
	
	Initialize procInitialize = (Initialize)GetProcAddress(instLib, "C_Initialize");
	if (procInitialize == NULL)
	{
		cout << "Unable to initialize cryptoki" << endl;
		return;
	}
	CK_RV result = procInitialize((CK_VOID_PTR)&initArgs);
	
}

bool crypt::IsLoaded()
{
	return (instLib != NULL) ? true : false;
}

void crypt::FreeCrypto()
{
	if (instLib == NULL)
		return;

	Finalize procFinalize = (Finalize)GetProcAddress(instLib, "C_Finalize");
	if (procFinalize == NULL)
	{
		cout << "Unable to free cryptoki library." << endl;
		return;
	}
	CK_RV result = procFinalize(NULL_PTR);
}
#pragma endregion

void crypt::DisplayInfo()
{
	CK_RV result;
	CK_INFO info;
	GetInfo procGetInfo = (GetInfo)GetProcAddress(instLib, "C_GetInfo");
	result = procGetInfo(&info);

	if (result != CKR_OK)
	{
		return;
	}
	
	cout << "========= Cryptoki Infomation =========" << endl;
	printf("Major: %d\t\tMinor: %d\n", info.cryptokiVersion.major, info.cryptokiVersion.minor);
	printf("Manufacturer: %s\n", info.manufacturerID);
	printf("Library Description: %s\n", info.libraryDescription);
	cout << "=======================================" << endl;
}

void crypt::DisplayTokenInfo()
{
	CK_SLOT_ID_PTR slotList = GetSlotList();
	CK_TOKEN_INFO tokenInfo = GetTokenInfo(slotList);

	cout << "========= Token Infomation =========" << endl;
	printf("Label: %s\n", tokenInfo.label);
	printf("Model: %s\n", tokenInfo.model);
	printf("Serial Number: %s\n", tokenInfo.serialNumber);
	printf("Hardware Version: %d %d\n", tokenInfo.hardwareVersion.major, tokenInfo.hardwareVersion.minor);
	cout << "====================================" << endl;
}

void crypt::newToken()
{
	InitToken procInitToken = (InitToken)GetProcAddress(instLib, "C_InitToken");
	if (procInitToken == NULL)
	{
		cout << "Unable to load C_InitToken" << endl;
		return;
	}
	
	CK_SLOT_ID slotId = GetFirstSlotId();
	CK_UTF8CHAR_PTR pin = (CK_UTF8CHAR_PTR)"MyPin";
	CK_UTF8CHAR label[32];

	memset(label, ' ', sizeof(label));
	memcpy(label, "My First token", strlen("My First token"));
	CK_RV rv = procInitToken(slotId, pin, strlen("MyPin"), label);
}

void crypt::InitTokenPin()
{
	// Start an active session
	// Check if session is active
	if (hSession == NULL)
	{
		Open();
	}
	CK_SESSION_INFO seshInfo = GetSessionInfo();
	if (seshInfo.state == CKS_RW_SO_FUNCTIONS)
	{
		CK_UTF8CHAR newPin[] = { "MyPIN" };
		InitPin procInitPin = (InitPin)GetProcAddress(instLib, "C_InitPIN");
		if (procInitPin == NULL)
		{
			cout << "Unable to load InitPin function" << endl;
			return;
		}
		CK_RV rv = procInitPin(hSession, newPin, sizeof(newPin) - 1);
	}
}

void crypt::SetTokenPin()
{

}

/// <summary>
/// Retrieves the information about the first slot. 
/// </summary>
/// <param name="slotList"></param>
/// <returns></returns>
CK_SLOT_ID crypt::GetFirstSlotId()
{
	CK_SLOT_ID_PTR slotList = GetSlotList();
	if (slotList == NULL_PTR)
	{
		cout << "Slot List is empty, unable to retrieve first slot info" << endl;
		return CK_SLOT_ID{};
	}

	CK_SLOT_INFO slotInfo{};
	GetSlotInfo procGetSlotInfo = (GetSlotInfo)GetProcAddress(instLib, "C_GetSlotInfo");
	if (procGetSlotInfo == NULL)
	{
		cout << "Unable to access C_GetSlotInfo" << endl;
		return NULL_PTR;
	}

	CK_RV rv = procGetSlotInfo(slotList[0], &slotInfo);
	CK_SLOT_ID slotId = slotList[0];

	return slotId;
}

CK_TOKEN_INFO crypt::GetTokenInfo(CK_SLOT_ID_PTR slotList)
{
	CK_TOKEN_INFO tokenInfo{};
	TokenInfo procGetTokenInfo = (TokenInfo)GetProcAddress(instLib, "C_GetTokenInfo");
	if (procGetTokenInfo == NULL)
	{
		cout << "Unable to access C_GetTokenInfo" << endl;
		return tokenInfo;
	}
	
	CK_RV rv = procGetTokenInfo(slotList[0], &tokenInfo);
	return tokenInfo;
}

CK_SLOT_ID_PTR crypt::GetSlotList()
{
	CK_SLOT_ID_PTR pSlotList{};
	SlotList procGetSlotList = (SlotList)GetProcAddress(instLib, "C_GetSlotList");
	if (procGetSlotList == NULL)
	{
		cout << "Unable to access C_GetSlotList" << endl;
		return pSlotList;
	}
	CK_ULONG ulCount = 0;
	CK_RV rv = procGetSlotList(CK_FALSE, NULL_PTR, &ulCount);
	if ((rv == CKR_OK) && (ulCount > 0))
	{
		pSlotList = (CK_SLOT_ID_PTR)malloc(ulCount * sizeof(CK_SLOT_ID));
		rv = procGetSlotList(CK_FALSE, pSlotList, &ulCount);
		return pSlotList;
	}

	return pSlotList;
}

#pragma region Session Management Functions
void crypt::DisplaySessionMenu()
{
	cout << "\nSession menu" << endl;
	cout << "1. Open Session" << endl;
	cout << "2. Get operation state" << endl;
	cout << "3. Close Session" << endl;

	bool exit = false;
	while (!exit)
	{
		int userInput;
		cin >> userInput;

		if (userInput == 3)
			exit = true;

		switch (userInput)
		{
		case 1:
			Open();
			break;
		case 2:
			break;
		case 3:
			Close();
			break;
		}
	}
}

void crypt::Open()
{
	CK_BYTE application;
	CK_SLOT_ID id = GetFirstSlotId();

	OpenSession procOpenSession = (OpenSession)GetProcAddress(instLib, "C_OpenSession");
	if (procOpenSession == NULL)
	{
		cout << "Unable to start open session" << endl;
		return;
	}

	application = 17;
	CK_RV rv = procOpenSession(id, CKF_SERIAL_SESSION | CKF_RW_SESSION, 
								(CK_VOID_PTR)&application, NULL_PTR, &hSession);

	CK_SESSION_INFO seshInfo = GetSessionInfo();
	TokenLogin();
}

void crypt::Close()
{
	if (hSession == NULL)
		return;

	TokenLogout();

	CloseSession procCloseSession = (CloseSession)GetProcAddress(instLib, "C_CloseSesion");
	if (procCloseSession == NULL)
	{
		cout << "Unable to call Close Session" << endl;
		return;
	}

	CK_RV rv = procCloseSession(hSession);

}

/// <summary>
/// Session State
/// 0 - RO Public Session
/// 1 - RO User Functions
/// 2 - RW Public Functions
/// 3 - RW User Functions
/// 4 - RW SO Functions
/// </summary>
/// <returns></returns>
CK_SESSION_INFO crypt::GetSessionInfo()
{
	CK_SESSION_INFO sessionInfo{};
	SessionInfo procGetSessionInfo = (SessionInfo)GetProcAddress(instLib, "C_GetSessionInfo");
	if (procGetSessionInfo == NULL)
	{
		cout << "Unable to GetSessionInfo" << endl;
		return CK_SESSION_INFO{};
	}

	if (hSession == NULL)
	{
		cout << "There are no open sessions." << endl;
		return CK_SESSION_INFO{};
	}
	CK_RV rv = procGetSessionInfo(hSession, &sessionInfo);
	return sessionInfo;
}
#pragma endregion

#pragma region Login - Logout
void crypt::TokenLogin()
{
	CK_UTF8CHAR pin[] = { "tokenTest2 " };
	CK_TOKEN_INFO tokenInfo = GetTokenInfo(GetSlotList());
	if (hSession == NULL)
	{
		cout << "Session has not been started." << endl;
		return;
	}

	Login procLogin = (Login)GetProcAddress(instLib, "C_Login");
	if (procLogin == NULL)
	{ 
		cout << "Unable to load Login function" << endl;
		return;
	}
	CK_RV rv = procLogin(hSession, CKU_USER, pin, sizeof(pin) - 1);
}

void crypt::TokenLogout()
{
	if (hSession == NULL)
	{
		cout << "Unable to logout of session." << endl;
		return;
	}

	Logout procLogout = (Logout)GetProcAddress(instLib, "C_Logout");
	if (procLogout == NULL)
	{
		cout << "Unable to use "
	}
	CK_RV rv = procLogout(hSession);
}
#pragma endregion

