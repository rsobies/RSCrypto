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

	/// <summary>
	/// writes certifact to a file, pem format
	/// </summary>
	/// <param name="filename">full path</param>
	/// <returns>true if operation succeed</returns>
	bool save(const string& filename);

	/// <summary>
	/// read certificat from a file
	/// </summary>
	/// <param name="filename">full path to file</param>
	/// <returns>true if operation succeed</returns>
	bool load(const string& filename);

	/// <summary>
	/// sets subject of the certifacate
	/// </summary>
	/// <param name="country"></param>
	/// <param name="organization"></param>
	/// <param name="commonName"></param>
	void setSubject(const string& country, const string& organization, const string& commonName);
	
	/// <summary>
	/// sets issuer of the certifacate
	/// </summary>
	/// <param name="country"></param>
	/// <param name="organization"></param>
	/// <param name="commonName"></param>
	void setIssuer(const string& country, const string& organization, const string& commonName);

private:
	/// <summary>
	/// common function setting subject or issuer
	/// </summary>
	/// <param name="country"></param>
	/// <param name="organization"></param>
	/// <param name="commonName"></param>
	/// <param name="type">if 0 subject is set, if 1 issuer is set</param>
	void setIssuerOrSubject(const string& country, const string& organization, const string& commonName, int type);
	
	/// <summary>
	/// unique_ptr to internal openssl structure holding certifiacte, 
	/// with custom delete function
	/// </summary>
	uniqeX509 x509_ptr = newX509();

	/// <summary>
	/// if certificate has been signed
	/// </summary>
	bool bSigned = false;
};

