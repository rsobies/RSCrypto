#pragma once

#include "openssl_types.h"

class PairKey;
class X509Cert;

class CMS
{
public:
	bool signedData(const X509Cert& cert, const PairKey& privKey, const string& dataFilename);
	bool saveSignedData(const string& filename);
	bool verifySignedData(const PairKey& caPubKey);
	bool readFromFile(const string& cmsFilename);
private:
	uniqeCMS cms_ptr;
	uniqeBIO bioData_ptr;
};

