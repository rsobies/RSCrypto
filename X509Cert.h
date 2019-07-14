#pragma once
#include "openssl_types.h"

class PairKey;

class X509Cert
{
public:
	X509Cert(const PairKey& pubKey);
	bool sign(const PairKey& caPrivKey);
private:
	uniqeX509 x509_ptr = newX509();
	bool bSigned = false;
};

