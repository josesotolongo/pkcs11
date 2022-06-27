#pragma region Headers
#include "crypt.h"

#pragma endregion

using namespace std;

int main(void)
{
	// Load the DLLs
	crypt crypto(TEXT("eToken.dll"));
	cout << "Loading Cryptoki DLLs....." << endl;

	// Check if the DLLs have loaded successfully
	bool isLoaded = crypto.IsLoaded();
	if (!isLoaded)
	{
		cout << "Unable to load Cryptoki DLLs" << endl;
		return -1;
	}
	cout << "Cryptoki DLLs loaded successfully!" << endl;

	crypto.LogAndDisplay(INFO, "Test");


	crypto.InitializeCrypto();
	//crypto.GetMechInfo();
	crypto.KeyCreation();
	crypto.FreeCrypto();

	return 0;
}
