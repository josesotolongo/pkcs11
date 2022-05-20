#pragma once
#include "crypt.h"

typedef CK_RV(__cdecl* OpenSession)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR);


class session
{
public:
	crypt lib;
	session(crypt crypto) { lib = crypto; };

	void DisplaySessionMenu();

private:
	void SessionOptions(int input);
	void Open();
};