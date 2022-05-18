#pragma region Headers
#include "crypt.h"

#pragma endregion

using namespace std;

#pragma region func declaration
void DisplayMainMenu();
void Options(int optionNum, crypt crypto);
#pragma endregion

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

	// Initialize the cryptoki library
	crypto.InitializeCrypto();

	bool exit = false;
	while (!exit)
	{
		DisplayMainMenu();

		int userInput;
		cin >> userInput;

		Options(userInput, crypto);

		if (userInput == -1)
		{
			exit = true;
		}
	}

	crypto.FreeCrypto();

	return 0;
}

#pragma region Functions
void DisplayMainMenu()
{
	cout << "\nHSM Main Menu" << endl;
	cout << "1. Cryptoki information." << endl;
	cout << "2. Token information." << endl;
	cout << "3. Session Menu." << endl;
	cout << "\nEnter -1 to exit." << endl;
}

void Options(int optionNum, crypt crypto)
{
	switch (optionNum)
	{
		case 1:
			crypto.DisplayInfo();
			break;
		case 2:
			crypto.DisplayTokenInfo();
			break;
		default:
			break;
	}
}
#pragma endregion
