#include "session.h"

void session::DisplaySessionMenu()
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
		SessionOptions(userInput);

		if (userInput == 3)
			exit = true;
	}
}

#pragma region Private methods
void session::SessionOptions(int input)
{
	switch (input)
	{
		case 1:
			Open();
			break;
		case 2:
			break;
	}
}

void session::Open()
{
	CK_SLOT_INFO sInfo = lib.GetFirstSlotInfo();
}
#pragma endregion


