#pragma once
#include "openssl_types.h"
#include "CMS.h"

class PairKey;

/// <summary>
/// representation of public key certyficate
/// </summary>
class X509Cert
{
	friend class CMS;
public:
	/// <summary>
	/// creates public key certyfiacte (not signed)
	/// some dummy values for subject and issuer are set
	/// </summary>
	/// <param name="pubKey">public key that will be signed</param>
	X509Cert(const PairKey& pubKey);

	/// <summary>
	/// signs public key with given CA private key
	/// </summary>
	/// <param name="caPrivKey">ca key to sign with</param>
	/// <returns>true if operation succeed</returns>
	bool sign(const PairKey& caPrivKey);

	/// <summary>
	/// checks this certifacate
	/// </summary>
	/// <param name="caPubKey">ca public key, that was used to sing this key</param>
	/// <returns>true if public key is geniue</returns>
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

