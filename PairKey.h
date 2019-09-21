#pragma once
#include "openssl_types.h"
#include "X509Cert.h"
#include "CMS.h"

/// <summary>
/// list of supported keyalgorithms
/// </summary>
enum Key_t {RSA_key, EC_key, UNK};

/// <summary>
/// class representing a pair of keys, public and private
/// </summary>
class PairKey{
	friend class X509Cert;
	friend class CMS;
public:
	/// <summary>
	/// generate a private key/public key with given algorithm
	/// </summary>
	/// <param name="type">key algorithm, rsa, ec</param>
	PairKey(Key_t type=Key_t::RSA_key);

	/// <summary>
	/// write public key to a file in pem format
	/// </summary>
	/// <param name="filename">full path of file</param>
	/// <returns>true if operation succeed</returns>
	bool savePublicKey(const string& filename);

	bool savePrivateKey(const string& filename);
	bool readPublicKey(const string& filename);
	bool readPrivate(const string& filename);

	/// <summary>
	/// private key is present
	/// </summary>
	/// <returns>is private key present</returns>
	bool isPrivate();

	/// <summary>
	/// gets a key algorithm used to generate this key
	/// </summary>
	/// <returns>key algorithm type</returns>
	Key_t getType();

	/// <summary>
	/// signs a message
	/// </summary>
	/// <param name="msg">message to sign</param>
	/// <returns>signature of the message</returns>
	vector<unsigned char> sign(const vector<unsigned char>& msg);

	/// <summary>
	/// checks the signature with a given message
	/// </summary>
	/// <param name="sign">signature to verify</param>
	/// <param name="msg">message</param>
	/// <returns>true if signature matches message</returns>
	bool verifySign(const vector<unsigned char>& sign, const vector<unsigned char>& msg);
	
	
protected:
	/// <summary>
	/// is private key present
	/// </summary>
	bool bPrivate;

	/// <summary>
	/// unique_ptr holding openssl EVP structure with custom delete function
	/// </summary>
	uniqeEVP evp_ptr= newEvp();
};