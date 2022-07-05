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
		LogAndDisplay(WARN, "Unable to initialize Cryptoki...");
	}
	CK_RV result = procInitialize((CK_VOID_PTR)&initArgs);
	assert(result == CKR_OK);
	LogAndDisplay(INFO, "Cryptoki has been initialized...");
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

void crypt::GetMechList()
{
	CK_SLOT_ID slotId = GetFirstSlotId();
	CK_ULONG ulCount;
	CK_MECHANISM_TYPE_PTR pMechList;
	
	GetMechanismList procMechList = (GetMechanismList)GetProcAddress(instLib, "C_GetMechanismList");
	if (procMechList == NULL)
	{
		cout << "Unable to load GetMechanismList" << endl;
		return;
	}

	CK_RV rv = procMechList(slotId, NULL_PTR, &ulCount);
	if ((rv == CKR_OK) && (ulCount > 0))
	{
		pMechList = (CK_MECHANISM_TYPE_PTR)malloc(ulCount * sizeof(CK_MECHANISM_TYPE));
		rv = procMechList(slotId, pMechList, &ulCount);
		assert(rv == CKR_OK);

		for (int i = 0; i < ulCount; i++)
		{
			cout << pMechList[i] << endl;
		}

		free(pMechList);
	}
}

void crypt::GetMechInfo()
{
	CK_SLOT_ID slotId = GetFirstSlotId();
	CK_MECHANISM_INFO info;
	CK_RV rv;

	GetMechanismInfo procGetMechInfo = (GetMechanismInfo)GetProcAddress(instLib, "C_GetMechanismInfo");
	assert(procGetMechInfo != NULL);

	rv = procGetMechInfo(slotId, CKM_EC_KEY_PAIR_GEN, &info);
	assert(rv == CKR_OK);

	if (info.flags & CKF_GENERATE_KEY_PAIR)
	{
		cout << "supports key pair" << endl;
	}
}

void crypt::LogAndDisplay(LogLevel severity, std::string message)
{
	std::string level = ConvertLogLevel(severity);
	cout << level << message << endl;
	return;
}

/// <summary>
/// Converts the LogLevel to string value.
/// </summary>
/// <param name="severity"></param>
/// <returns></returns>
std::string crypt::ConvertLogLevel(LogLevel severity)
{
	std::string level; 
	switch (severity)
	{
	case INFO:
		level = "INFO: ";
		break;
	case WARN:
		level = "WARN: ";
		break;
	default:
		level = "";
		break;
	}

	return level;
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
		LogAndDisplay(WARN, "Unable to load InitToken function");
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
		//Open();
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
		LogAndDisplay(WARN, "Slot List is empty, unable to retrieve first slot info");
		return CK_SLOT_ID{};
	}

	CK_SLOT_INFO slotInfo{};
	GetSlotInfo procGetSlotInfo = (GetSlotInfo)GetProcAddress(instLib, "C_GetSlotInfo");
	if (procGetSlotInfo == NULL)
	{
		LogAndDisplay(WARN, "Unable to access C_GetSlotInfo");
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
		LogAndDisplay(INFO, "Unable to load C_GetSlotList function...");
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
void crypt::open_session()
{
	CK_RV rv = CKR_OK;
	CK_SLOT_ID id = GetFirstSlotId();

	OpenSession procOpenSession = (OpenSession)GetProcAddress(instLib, "C_OpenSession");
	if (procOpenSession == NULL)
	{
		LogAndDisplay(WARN, "Unable to load open session...");
		return;
	}

	rv = procOpenSession(id, CKF_SERIAL_SESSION | CKF_RW_SESSION, 
								(CK_VOID_PTR)&hApp, NULL_PTR, &hSession);
	assert(rv == CKR_OK);
}

void crypt::close_session()
{
	if (hSession == NULL)
		return;

	token_logout();

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
CK_RV crypt::token_login()
{
	CK_UTF8CHAR pin[] = {"SafeNet#0"};
	
	tokenInfo = GetTokenInfo(GetSlotList());
	if (hSession == NULL)
	{
		LogAndDisplay(WARN, "Session has not been started...");
		return CKR_SESSION_HANDLE_INVALID;
	}

	Login procLogin = (Login)GetProcAddress(instLib, "C_Login");
	if (procLogin == NULL)
	{ 
		LogAndDisplay(WARN, "Unable to load Login function...");
		return CKR_FUNCTION_FAILED;
	}
	CK_RV rv = procLogin(hSession, CKU_SO, pin, sizeof(pin) - 1);
	return rv;
}

CK_RV crypt::token_logout()
{
	if (hSession == NULL)
	{
		LogAndDisplay(WARN, "Unable to logout of session...");
		return CKR_SESSION_HANDLE_INVALID;
	}

	Logout procLogout = (Logout)GetProcAddress(instLib, "C_Logout");
	if (procLogout == NULL)
	{
		LogAndDisplay(WARN, "Unable to use Logout function...");
		return CKR_FUNCTION_FAILED;
	}
	CK_RV rv = procLogout(hSession);
	return rv;
}
#pragma endregion

#pragma region Keys - Function
void crypt::KeyCreation()
{
	GenerateKey procGenKey = (GenerateKey)GetProcAddress(instLib, "C_GenerateKey");
	if (procGenKey == NULL)
	{
		LogAndDisplay(WARN, "Unable to load GenerateKey function...");
		return;
	}

	CK_RV rv = token_login();
	if (rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN)
	{
		CK_OBJECT_HANDLE hObject = CK_INVALID_HANDLE;

		char objLabel[32];

		static CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
		static CK_BBOOL ckTrue = TRUE;
		static CK_BBOOL ckFalse = FALSE;

		static CK_MECHANISM mechanism = { CKM_DES3_KEY_GEN, NULL, 0 };

		// DES3 Key Length
		static CK_BYTE usKeyLength = 24;
		CK_BYTE val[24] = {};

		CK_ATTRIBUTE objectTemplate[] =
		{
			
			{CKA_TOKEN,         &ckTrue,		sizeof(CK_BBOOL)},      /* Permanent Key -> set false for session key */
			{CKA_ENCRYPT,       &ckTrue,		sizeof(CK_BBOOL)},
			{CKA_DECRYPT,		&ckTrue,		sizeof(CK_BBOOL)},
			{CKA_SIGN,			&ckTrue,		sizeof(CK_BBOOL)},
			{CKA_VERIFY,		&ckTrue,		sizeof(CK_BBOOL)},
			{CKA_WRAP,			&ckTrue,		sizeof(CK_BBOOL)},
			{CKA_VALUE_LEN,		&usKeyLength,	sizeof(usKeyLength)},
			{CKA_LABEL,         NULL,   0},
		};
		CK_ULONG objectSize = sizeof(objectTemplate) / sizeof(CK_ATTRIBUTE);

		/* Fill in the key label */
		objectTemplate[objectSize - 1].pValue = objLabel;
		// strcpy( (char *)objLabel, "NewSecretKey" );
		strcpy((char*)objLabel, "DES3key");

		// Adjust size of label (ALWAYS LAST ENTRY IN ARRAY)
		objectTemplate[objectSize - 1].ulValueLen = strlen(objLabel);

		rv = procGenKey(hSession, &mechanism, objectTemplate, objectSize, &hObject);
		assert(rv == CKR_OK);
	}

	close_session();
}

#pragma endregion
