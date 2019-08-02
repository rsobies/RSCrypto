#pragma once
#include "openssl_types.h"
#include "CMS.h"

class PairKey;

class X509Cert
{
	friend class CMS;
public:
	X509Cert(const PairKey& pubKey);
	bool sign(const PairKey& caPrivKey);
	bool verify(const PairKey& caPubKey);
	bool save(const string& filename);
	bool load(const string& filename);
	void setSubject(const string& country, const string& organization, const string& commonName);
	void setIssuer(const string& country, const string& organization, const string& commonName);

private:
	void setIssuerOrSubject(const string& country, const string& organization, const string& commonName, int type);
	uniqeX509 x509_ptr = newX509();
	bool bSigned = false;
};

