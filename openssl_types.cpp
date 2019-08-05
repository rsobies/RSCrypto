#include "pch.h"
#include "openssl_types.h"

template<typename T>
void OSSLDeleter<T>::operator()(T* p) {

	if constexpr (is_same<T, RSA>::value) {
		RSA_free(p);
	}
	else if constexpr (is_same<T, BIO>::value) {
		BIO_free(p);
	}
	else if constexpr (is_same<T, BIGNUM>::value) {
		BN_free(p);
	}
	else if constexpr (is_same<T, EVP_PKEY>::value) {
		EVP_PKEY_free(p);
	}
	else if constexpr (is_same<T, EC_GROUP>::value) {
		EC_GROUP_free(p);
	}
	else if constexpr (is_same<T, EVP_PKEY_CTX>::value) {
		EVP_PKEY_CTX_free(p);
	}
	else if constexpr (is_same<T, X509>::value) {
		X509_free(p);
	}
	else if constexpr (is_same < T, CMS_ContentInfo>::value) {
		CMS_ContentInfo_free(p);
	}
	else if constexpr (is_same < T, X509_STORE>::value) {
		X509_STORE_free(p);
	}
	else if constexpr (is_same < T, stack_st_X509>::value) {
		sk_X509_free(p);
	}
	
	else {
		static_assert(false, "OSSLDeleter<T>::operator() T must be type of stack_st_X509, X509_STORE, CMS_ContentInfo, X509, EVP_PKEY_CTX, EC_GROUP, RSA, BIO, BIGNUM, EVP_PKEY");
	}
}

uniqeEVP newEvp()
{
	return uniqeEVP{ EVP_PKEY_new(), EVPDeleter() };
}

uniqeX509STR newX509STR() {
	return uniqeX509STR{ X509_STORE_new(), X509STRDeleter ()};
}

uniqeX509 newX509()
{
	return uniqeX509{ X509_new(), X509Deleter() };
}

uniqeBIO newBIO(const string& filename, const string& mode) {
	return uniqeBIO{ BIO_new_file(filename.c_str(), mode.c_str()) , BIODeleter() };
}

uniqeBIO newBIO() {
	return uniqeBIO{ BIO_new(BIO_s_mem()) , BIODeleter() };
}

uniqeX509Stack newX509Stack() {
	return uniqeX509Stack{ sk_X509_new_null() , X509StackDeleter() };
}

uniqeEVPCTX newEVPCTX(uniqeEVP& evp) {
	return uniqeEVPCTX{ EVP_PKEY_CTX_new(evp.get(), nullptr), EVPCTXDeleter() };
}

//to avoid linking error
void dummyFunction()
{
	uniqeX509Stack{ sk_X509_new_null() , X509StackDeleter() };
	uniqeX509STR{ X509_STORE_new(), X509STRDeleter() };
	uniqeCMS{ nullptr, CMSDeleter() };
	uniqeX509 kk{ X509_new(), X509Deleter() };
	uniqeEVP evp_ptr{ EVP_PKEY_new(), EVPDeleter() };
	uniqeBIO{ BIO_new_file("ggg","j") , BIODeleter() };
	uniqeBignum bn_ptr(BN_new(), BIGNUMDeleter());
	uniqeECGroup ecGroup{ EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1) , ECGroupDeleter() };
	uniqeEVPCTX{ EVP_PKEY_CTX_new(nullptr, nullptr), EVPCTXDeleter() };
}
