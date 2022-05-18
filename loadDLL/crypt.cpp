#include "crypt.h"


crypt::crypt(LPCWSTR libPath)
{
	LoadDLL(libPath);
}

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

void crypt::FreeCrypto()
{
	Finalize procFinalize = (Finalize)GetProcAddress(instLib, "C_Finalize");
	if (procFinalize == NULL)
	{
		cout << "Unable to free cryptoki library." << endl;
		return;
	}
	CK_RV result = procFinalize(NULL_PTR);
}

bool crypt::IsLoaded()
{
	return (instLib != NULL) ? true : false;
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
	CK_ULONG ulCount;
	CK_RV rv = procGetSlotList(CK_FALSE, NULL_PTR, &ulCount);
	if ((rv == CKR_OK) && (ulCount > 0))
	{
		pSlotList = (CK_SLOT_ID_PTR)malloc(ulCount * sizeof(CK_SLOT_ID));
		rv = procGetSlotList(CK_FALSE, pSlotList, &ulCount);
		return pSlotList;
	}

	return pSlotList;
}