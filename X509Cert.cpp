#include "pch.h"
#include "X509Cert.h"
#include "PairKey.h"

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
