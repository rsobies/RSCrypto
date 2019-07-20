#include "pch.h"
#include "X509Cert.h"
#include "PairKey.h"
#include <openssl/pem.h>

X509Cert::X509Cert(const PairKey& pubKey)
{
	X509_gmtime_adj(X509_get_notBefore(x509_ptr.get()), 0);
	X509_gmtime_adj(X509_get_notAfter(x509_ptr.get()), 31536000L);//365
	assert(1==X509_set_pubkey(x509_ptr.get(), pubKey.evp_ptr.get()));
}

bool X509Cert::sign(const PairKey& caPrivKey)
{
	auto ret=X509_sign(x509_ptr.get(), caPrivKey.evp_ptr.get(), EVP_sha256());
	bSigned = ret != 0;
	return bSigned;
}

bool X509Cert::verify(const PairKey& caPubKey)
{
	auto ret=X509_verify(x509_ptr.get(), caPubKey.evp_ptr.get());
	return ret==1;
}

bool X509Cert::save(const string& filename)
{
	auto bio_ptr = newBIO(filename.c_str(), "w+");

	auto ret=PEM_write_bio_X509(bio_ptr.get(), x509_ptr.get());
	return ret!=0;
}

bool X509Cert::load(const string& filename)
{
	auto bio_ptr = newBIO(filename.c_str(), "r");

	auto xCert=uniqeX509{ PEM_read_bio_X509(bio_ptr.get(), nullptr, nullptr, nullptr), X509Deleter() };
	
	if (xCert != nullptr) {
		x509_ptr = move(xCert);
		return true;
	}

	return false;
}
