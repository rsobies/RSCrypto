#pragma once

#include "openssl_types.h"

class PairKey;
class X509Cert;

/// <summary>
/// wrapper class of cyptographic message syntax
/// </summary>
class CMS
{
public:
	bool signedData(const X509Cert& cert, const PairKey& privKey, const string& dataFilename);
	bool save(const string& filename);
	bool verifySignedData(const PairKey& caPubKey);
	bool readFromFile(const string& cmsFilename);
	bool toEnvelope(const string& dataFilename, const vector<X509Cert>& receipments);
	bool decodeEnvelope(const PairKey& privKey);
private:
	uniqeCMS cms_ptr;
	uniqeBIO bioData_ptr;
	uniqeBIO encodedData_ptr;
};

