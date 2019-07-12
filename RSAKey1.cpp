#include "pch.h"
#include "RSAKey1.h"
#include <openssl/pem.h>


RSAKey1::RSAKey1()
{
	/*
	int bits = 2048;

	unsigned long e = RSA_F4;
	uniqeBignum bn_ptr(BN_new(), BIGNUMDeleter());

	auto ret=BN_set_word(bn_ptr.get(), e);

	ret=RSA_generate_key_ex(rsa_ptr.get(), bits, bn_ptr.get(), nullptr);
	bPrivate = ret == 1 ? true : false;*/
}

bool RSAKey1::savePublicKey(const string& filename, RSAPublic_t keyType)
{
	
	uniqeBIO bio_ptr{ BIO_new_file(filename.c_str(), "w+") , BIODeleter() };
/*
	if (keyType == RSAPublic_t::RSAPublicKey) {
		return PEM_write_bio_RSAPublicKey(bio_ptr.get(), rsa_ptr.get());
	}

	return PEM_write_bio_RSA_PUBKEY(bio_ptr.get(), rsa_ptr.get());*/
	return false;
}

bool RSAKey1::savePrivateKey(const string& filename)
{
	return false;
	//uniqeBIO bio_ptr{ BIO_new_file(filename.c_str(), "w+") , BIODeleter() };
	//return PEM_write_bio_RSAPrivateKey(bio_ptr.get(), rsa_ptr.get(), nullptr, nullptr, 0, nullptr, nullptr);
}

bool RSAKey1::readPublicKey(const string& filename, RSAPublic_t keyType)
{
	
	uniqeBIO bio_ptr{ BIO_new_file(filename.c_str(), "r") , BIODeleter() };

	if (bio_ptr == nullptr) {
		return false;
	}

	if (keyType == RSAPublic_t::RSAPublicKey) {
		//rsa_ptr = RSAUniqe{ PEM_read_bio_RSAPublicKey(bio_ptr.get(), nullptr,nullptr, nullptr), RSADeleter() };
	}
	else{
		//rsa_ptr = RSAUniqe{ PEM_read_bio_RSA_PUBKEY(bio_ptr.get(), nullptr,nullptr, nullptr), RSADeleter() };
	}
	//bPrivate = rsa_ptr != nullptr ? false : bPrivate;

	//return rsa_ptr != nullptr;
	return false;
}

bool RSAKey1::readPrivateKey(const string& filename)
{
	uniqeBIO bio_ptr{ BIO_new_file(filename.c_str(), "r") , BIODeleter() };

	if (bio_ptr == nullptr) {
		return false;
	}

	//rsa_ptr = RSAUniqe{ PEM_read_bio_RSAPrivateKey(bio_ptr.get(), nullptr,nullptr, nullptr), RSADeleter() };

	//bPrivate = rsa_ptr != nullptr ? true : bPrivate;

	//return rsa_ptr != nullptr;
	return false;
}

vector<unsigned char> RSAKey1::encrypt(const vector<unsigned char>& msg)
{
	return vector<unsigned char>();
}

bool RSAKey1::isPrivate()
{
	return bPrivate;
}

vector<unsigned char> RSAKey1::sign(const vector<unsigned char>& msg)
{
	const int sha256Len = 32;
	unsigned char sha[sha256Len];
	
	SHA256(&(msg[0]), msg.size(), sha);

	//vector<unsigned char> ret(RSA_size(rsa_ptr.get()));
	unsigned int signLen=0;

	//if (RSA_sign(NID_sha1, sha, 
			//SHA_DIGEST_LENGTH,
			//&(ret[0]), &signLen,
			//rsa_ptr.get())) {
		//return ret;
	//}

	return vector<unsigned char>();
}

bool RSAKey1::verifySign(const vector<unsigned char> sign, const vector<unsigned char>& msg)
{
	unsigned char sha[SHA_DIGEST_LENGTH];

	SHA1(&(msg[0]), msg.size(), sha);

	//return RSA_verify(NID_sha1, sha, SHA_DIGEST_LENGTH, &sign[0], sign.size(), rsa_ptr.get());
	return false;
}
