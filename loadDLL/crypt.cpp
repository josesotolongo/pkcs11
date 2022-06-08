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
	assert(result == CKR_OK);
	cout << "C_Initialize successful..." << endl;
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
#pragma endregion

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
	// TODO: Implement set pin functions if needed
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
	assert(rv == CKR_OK);
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
CK_RV crypt::TokenLogin()
{
	CK_UTF8CHAR pin[] = { "tokenTest2 " };
	CK_TOKEN_INFO tokenInfo = GetTokenInfo(GetSlotList());
	if (hSession == NULL)
	{
		cout << "Session has not been started." << endl;
		return CKR_SESSION_HANDLE_INVALID;
	}

	Login procLogin = (Login)GetProcAddress(instLib, "C_Login");
	if (procLogin == NULL)
	{ 
		cout << "Unable to load Login function" << endl;
		return CKR_FUNCTION_FAILED;
	}
	CK_RV rv = procLogin(hSession, CKU_USER, pin, sizeof(pin) - 1);
	return rv;
}

CK_RV crypt::TokenLogout()
{
	if (hSession == NULL)
	{
		cout << "Unable to logout of session." << endl;
		return CKR_SESSION_HANDLE_INVALID;
	}

	Logout procLogout = (Logout)GetProcAddress(instLib, "C_Logout");
	if (procLogout == NULL)
	{
		cout << "Unable to use Logout function" << endl;
		return CKR_FUNCTION_FAILED;
	}
	CK_RV rv = procLogout(hSession);
	return rv;
}
#pragma endregion

#pragma region Keys - Function
void crypt::KeyCreation()
{
	CK_RV rv;

	// Start Session
	Open();

	//Used to generate key
	GenerateKey generateKey = (GenerateKey)GetProcAddress(instLib, "C_GenerateKey");
	assert(generateKey != NULL);

	//Used to generate key/pair
	GenerateKeyPair generateKP = (GenerateKeyPair)GetProcAddress(instLib, "C_GenerateKeyPair");
	assert(generateKP != NULL);

	AttributeValue GetAttributeValue = (AttributeValue)GetProcAddress(instLib, "C_GetAttributeValue");
	assert(GetAttributeValue != NULL);

	// Login to Token
	rv = TokenLogin();

	if (rv == CKR_OK)
	{
		// Generate Single Key Example
		CK_OBJECT_HANDLE hKey;
		CK_MECHANISM mechanism = { CKM_DES_KEY_GEN, NULL_PTR, 0 };

		rv = generateKey(hSession, &mechanism, NULL_PTR, 0, &hKey);
		assert(rv == CKR_OK);

		CK_BYTE_PTR pModulus, pExponent;
		CK_ATTRIBUTE temp[] =
		{
			{CKA_MODULUS, NULL_PTR, 0},
			{CKA_PUBLIC_EXPONENT, NULL_PTR, 0}
		};
		rv = GetAttributeValue(hSession, hKey, temp, 2);
		assert(rv == CKR_OK);
	}

	if (rv == CKR_OK)
	{
		// Generate Key Pair Example
		CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
		CK_MECHANISM mechanism =
		{
			CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
		};
		CK_ULONG modulusBits = 768;
		CK_BYTE publicExponent[] = { 3 };
		CK_BYTE subject[] = { "subject test" };
		CK_BYTE id[] = { 123 };
		CK_BYTE True = CK_TRUE;
		CK_ATTRIBUTE publicKeyTemplate[]
		{
			{CKA_ENCRYPT, &True, sizeof(True)},
			{CKA_VERIFY, &True, sizeof(True)},
			{CKA_WRAP, &True, sizeof(True)},
			{CKA_MODULUS_BITS,  &modulusBits, sizeof(modulusBits)},
			{CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)}
		};
		CK_ATTRIBUTE privateKeyTemplate[] = {
			{CKA_TOKEN, &True, sizeof(true)},
			{CKA_PRIVATE, &True, sizeof(true)},
			{CKA_SUBJECT, subject, sizeof(subject)},
			{CKA_ID, id, sizeof(id)},
			{CKA_SENSITIVE, &True, sizeof(true)},
			{CKA_DECRYPT, &True, sizeof(true)},
			{CKA_SIGN, &True, sizeof(true)},
			{CKA_UNWRAP, &True, sizeof(true)}
		};
		rv = generateKP(hSession, &mechanism, publicKeyTemplate, 5, privateKeyTemplate, 8, &hPublicKey, &hPrivateKey);
		assert(rv == CKR_OK);
	}

	



}

#pragma endregion
