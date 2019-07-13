#pragma once

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <memory>

using namespace std;

template<typename T>
struct OSSLDeleter {
	void operator()(T* p);
};

using EVPDeleter=OSSLDeleter<EVP_PKEY>;
using BIODeleter=OSSLDeleter<BIO>;
using BIGNUMDeleter=OSSLDeleter<BIGNUM>;
using ECGroupDeleter=OSSLDeleter<EC_GROUP>;
using EVPCTXDeleter=OSSLDeleter<EVP_PKEY_CTX>;
using X509Deleter=OSSLDeleter<X509>;

using uniqeEVP=unique_ptr<EVP_PKEY, EVPDeleter>;
using uniqeBIO=unique_ptr<BIO, BIODeleter>;
using uniqeBignum=unique_ptr<BIGNUM, BIGNUMDeleter>;
using uniqeECGroup=unique_ptr<EC_GROUP, ECGroupDeleter>;
using uniqeEVPCTX=unique_ptr< EVP_PKEY_CTX, EVPCTXDeleter>;
using uniqeX509=unique_ptr<X509, X509Deleter>;

uniqeEVP newEvp();
uniqeX509 newX509();
uniqeBIO newBIO(const string& filename, const string& mode);
uniqeEVPCTX newEVPCTX(uniqeEVP& evp);