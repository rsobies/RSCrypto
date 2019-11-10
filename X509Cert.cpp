#include "pch.h"
#include "X509Cert.h"
#include "PairKey.h"
#include <openssl/pem.h>
#include <openssl/err.h>

X509Cert::X509Cert(const PairKey& pubKey)
{
	X509_gmtime_adj(X509_get_notBefore(x509_ptr.get()), 0);
	X509_gmtime_adj(X509_get_notAfter(x509_ptr.get()), 31536000L);//365
	assert(1==X509_set_pubkey(x509_ptr.get(), pubKey.getEVP().get()));
	ASN1_INTEGER_set(X509_get_serialNumber(x509_ptr.get()), 1);
	setIssuerOrSubject("PL", "RSCrypto", "localhost", 2);
	
}

bool X509Cert::sign(const PairKey& caPrivKey)
{
	auto ret=X509_sign(x509_ptr.get(), caPrivKey.getEVP().get(), EVP_sha256());
	bSigned = ret != 0;
	return bSigned;
}

bool X509Cert::verify(const PairKey& caPubKey)
{
	auto ret=X509_verify(x509_ptr.get(), caPubKey.getEVP().get());
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

void X509Cert::setSubject(const string& country, const string& organization, const string& commonName)
{
	setIssuerOrSubject(country, organization, commonName, 0);
}

void X509Cert::setIssuer(const string& country, const string& organization, const string& commonName)
{
	setIssuerOrSubject(country, organization, commonName, 1);
}


void X509Cert::setIssuerOrSubject(const string& country, const string& organization, const string& commonName, int type)
{
	auto name = X509_NAME_new();

	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
		(unsigned char*)country.c_str(), -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
		(unsigned char*)organization.c_str(), -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
		(unsigned char*)commonName.c_str(), -1, -1, 0);

	if (type == 0) {
		assert(1 == X509_set_subject_name(x509_ptr.get(), name));
	}
	else if (type == 1) {
		assert(1 == X509_set_issuer_name(x509_ptr.get(), name));
	}
	else {
		assert(1==X509_set_subject_name(x509_ptr.get(), name));
		assert(1==X509_set_issuer_name(x509_ptr.get(), name));
	}
	
	X509_NAME_free(name);
}
