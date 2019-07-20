#pragma once
#include "openssl_types.h"

class PairKey;

class X509Cert
{
public:
	X509Cert(const PairKey& pubKey);
	bool sign(const PairKey& caPrivKey);
	bool verify(const PairKey& caPubKey);
	bool save(const string& filename);
	bool load(const string& filename);
private:
	uniqeX509 x509_ptr = newX509();
	bool bSigned = false;
};

