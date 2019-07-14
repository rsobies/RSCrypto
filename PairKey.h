#pragma once
#include "openssl_types.h"
#include "X509Cert.h"

enum Key_t {RSA_key, EC_key, UNK};

class PairKey{
public:
	PairKey(Key_t type=Key_t::RSA_key);
	bool savePublicKey(const string& filename);
	bool savePrivateKey(const string& filename);
	bool readPublicKey(const string& filename);
	bool readPrivate(const string& filename);
	bool isPrivate();
	Key_t getType();
	vector<unsigned char> sign(const vector<unsigned char>& msg);
	bool verifySign(const vector<unsigned char>& sign, const vector<unsigned char>& msg);
	friend class X509Cert;
protected:
	bool bPrivate;
	uniqeEVP evp_ptr= newEvp();
};