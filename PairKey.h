#pragma once
#include "openssl_types.h"
#include "X509Cert.h"
#include "CMS.h"

/// <summary>
/// list of supported key algorithms
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
	/// generate a private/public key with given algorithm
	/// default is rsa
	/// </summary>
	/// <param name="type">key algorithm, rsa, ec</param>
	PairKey(Key_t type=Key_t::RSA_key);

	/// <summary>
	/// write public key to a file in pem format
	/// </summary>
	/// <param name="filename">full path of file</param>
	/// <returns>true if operation succeed</returns>
	bool savePublicKey(const string& filename);

	/// <summary>
	/// write private key to a file in pem format
	/// </summary>
	/// <param name="filename">full path of file</param>
	/// <returns>true if operation succeed</returns>
	bool savePrivateKey(const string& filename);

	/// <summary>
	/// read public key from pem file
	/// </summary>
	/// <param name="filename">full path of file</param>
	/// <returns>true if operation succeed</returns>
	bool readPublicKey(const string& filename);

	/// <summary>
	/// read private key from pem file
	/// </summary>
	/// <param name="filename">full path of file</param>
	/// <returns>true if operation succeed</returns>
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
	

	/// <summary>
	///  Reads public key from string.
	/// </summary>
	/// <param name="publicKey">Public key value in pem format.</param>
	/// <returns>>True if operation succeed.</returns>
	bool parsePublic(const string& publicKey);

	/// <summary>
	/// Reads private key from string
	/// </summary>
	/// <param name="privateKey">Private key value in pem format</param>
	/// <returns>True if operation succeed.</returns>
	bool parsePrivate(const string& privateKey);
	
protected:
	/// <summary>
	/// is private key present
	/// </summary>
	bool bPrivate;

	/// <summary>
	/// unique_ptr holding openssl EVP structure with custom delete function
	/// </summary>
	uniqeEVP evp_ptr= newEvp();

	/// <summary>
	/// Reads private key from bio.
	/// </summary>
	/// <param name="bioPtr">BIO with private key to read from.</param>
	/// <returns>True if operation succeed.</returns>
	bool readPrivate(uniqeBIO bioPtr);
};