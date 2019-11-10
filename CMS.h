#pragma once

//#include "openssl_types.h"

#include "PairKey.h"
class X509Cert;

/// <summary>
/// representation of cyptographic message syntax
/// </summary>
class CMS
{
public:

	/// <summary>
	/// creats a signed messaged
	/// </summary>
	/// <param name="cert">certifacate that will be included in cms</param>
	/// <param name="privKey">private key that will be used to sign message
	/// this key must match to cert param</param>
	/// <param name="dataFilename">message read from file</param>
	/// <returns>if operation was successful</returns>
	bool signedData(const X509Cert& cert, const PairKey& privKey, const string& dataFilename);
	
	/// <summary>
	/// write cms to a file
	/// </summary>
	/// <param name="filename">full path</param>
	/// <returns>if operation was successful</returns>
	bool save(const string& filename);

	/// <summary>
	/// verify cms
	/// </summary>
	/// <param name="caPubKey">ca public key. this key is used verify 
	/// public key certificate included in cms, a then public key is used
	/// to verify cms </param>
	/// <returns>cms is correct</returns>
	bool verifySignedData(const PairKey& caPubKey);

	/// <summary>
	/// reads cms from file
	/// </summary>
	/// <param name="cmsFilename">full path</param>
	/// <returns>if operation was successful</returns>
	bool readFromFile(const string& cmsFilename);

	/// <summary>
	/// creates envelope cms, content is encypted
	/// </summary>
	/// <param name="dataFilename">full path</param>
	/// <param name="receipments">list of public key of receipments,
	/// those keys will be used to encrypt message</param>
	/// <returns>if operation was successful</returns>
	bool toEnvelope(const string& dataFilename, const vector<X509Cert>& receipments);
	
	/// <summary>
	/// decrpyt cms
	/// </summary>
	/// <param name="privKey">private key to decode message</param>
	/// <returns>if operation was successful</returns>
	bool decodeEnvelope(const PairKey& privKey);
private:

	/// <summary>
	/// unique_ptr to internal openssl structure holding cms, 
	/// with custom delete function
	/// </summary>
	uniqeCMS cms_ptr;
};

