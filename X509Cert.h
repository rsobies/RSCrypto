#pragma once
#include "openssl_types.h"

class X509Cert
{
private:
	uniqeX509 x509_ptr = newX509();
	bool bSigned = false;
};

