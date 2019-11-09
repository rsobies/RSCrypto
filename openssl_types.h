#pragma once

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/cms.h>
#include <memory>

using namespace std;
/// <summary>
/// functional structure used as deletion function for openssl types
/// </summary>
template<typename T>
struct OSSLDeleter {
	/// <summary>
	/// invoke to release openssl types
	/// </summary>
	/// <param name="p">openssl object to free</param>
	void operator()(T* p);
};

using EVPDeleter=OSSLDeleter<EVP_PKEY>;
using BIODeleter=OSSLDeleter<BIO>;
using BIGNUMDeleter=OSSLDeleter<BIGNUM>;
using ECGroupDeleter=OSSLDeleter<EC_GROUP>;
using EVPCTXDeleter=OSSLDeleter<EVP_PKEY_CTX>;
using X509Deleter=OSSLDeleter<X509>;
using CMSDeleter=OSSLDeleter<CMS_ContentInfo>;
using X509STRDeleter=OSSLDeleter<X509_STORE>;
using X509StackDeleter=OSSLDeleter<stack_st_X509>;

using uniqeEVP=unique_ptr<EVP_PKEY, EVPDeleter>;
using uniqeBIO=unique_ptr<BIO, BIODeleter>;
using uniqeBignum=unique_ptr<BIGNUM, BIGNUMDeleter>;
using uniqeECGroup=unique_ptr<EC_GROUP, ECGroupDeleter>;
using uniqeEVPCTX=unique_ptr< EVP_PKEY_CTX, EVPCTXDeleter>;
using uniqeX509=unique_ptr<X509, X509Deleter>;
using uniqeCMS=unique_ptr<CMS_ContentInfo, CMSDeleter>;
using uniqeX509STR=unique_ptr<X509_STORE, X509STRDeleter>;
using uniqeX509Stack=unique_ptr<stack_st_X509, X509StackDeleter>;

/// <summary>
/// helper functions to create smart pointers for openssl types
/// </summary>
uniqeX509Stack newX509Stack();
uniqeBIO newBIO();
uniqeEVP newEvp();
uniqeX509STR newX509STR();
uniqeX509 newX509();
uniqeBIO newBIO(const string& filename, const string& mode);
uniqeEVPCTX newEVPCTX(const uniqeEVP& evp);