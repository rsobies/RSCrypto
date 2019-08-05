#pragma once

#include "openssl_types.h"

class PairKey;
class X509Cert;

class CMS
{
public:
	bool signedData(const X509Cert& cert, const PairKey& privKey, const string& dataFilename);
	bool save(const string& filename);
	bool verifySignedData(const PairKey& caPubKey);
	bool readFromFile(const string& cmsFilename);
	bool toEnvelope(const string& dataFilename, const vector<X509Cert>& receipments);
private:
	uniqeCMS cms_ptr;
	uniqeBIO bioData_ptr;
};

