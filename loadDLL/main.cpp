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

	// Start cryptoki API 
	crypto.InitializeCrypto();
	
	// Open session with token
	crypto.open_session();

	// login to the toke

	crypto.KeyCreation();
	crypto.FreeCrypto();

	return 0;
}
