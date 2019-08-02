#pragma once
#include "openssl_types.h"
#include "X509Cert.h"
#include "CMS.h"

enum Key_t {RSA_key, EC_key, UNK};

class PairKey{
	friend class X509Cert;
	friend class CMS;
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
	
	
protected:
	bool bPrivate;
	uniqeEVP evp_ptr= newEvp();
};