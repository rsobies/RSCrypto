#pragma once

#include "openssl_types.h"

enum RSAPublic_t : char { RSA_PUBKEY , RSAPublicKey};

class RSAKey1
{	
public:
	RSAKey1();

	bool savePublicKey(const string& filename, RSAPublic_t keyType= RSAPublic_t::RSAPublicKey);

	bool savePrivateKey(const string& filename);

	bool readPublicKey(const string& filename, RSAPublic_t keyType = RSAPublic_t::RSAPublicKey);
	bool readPrivateKey(const string& filename);
	vector<unsigned char> encrypt(const vector<unsigned char>& msg);
	bool isPrivate();

	vector<unsigned char> sign(const vector<unsigned char>& msg);

	bool verifySign(const vector<unsigned char> sign, const vector<unsigned char>& msg);

private:
	bool bPrivate;
	//RSAUniqe rsa_ptr { RSA_new(), RSADeleter()};
};

