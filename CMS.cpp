#include "pch.h"
#include "CMS.h"
#include "X509Cert.h"
#include "PairKey.h"
#include <openssl/err.h>

bool CMS::signedData(const X509Cert& cert, const PairKey& privKey, const string& dataFilename)
{	
	auto bioDataIn_ptr =newBIO(dataFilename, "r");
	if (bioDataIn_ptr ==nullptr) {
		return false;
	}
	
	cms_ptr = uniqeCMS{ CMS_sign(cert.x509_ptr.get(), 
								 privKey.evp_ptr.get(), 
								 nullptr, 
								 bioDataIn_ptr.get(),
								 CMS_TEXT), 
			  CMSDeleter() };
	
	return cms_ptr!=nullptr;
}
bool CMS::toEnvelope(const string& dataFilename, const vector<X509Cert>& receipments)
{
	auto x509Stack = newX509Stack();

	for (auto& cert : receipments) {
		auto ret = sk_X509_push(x509Stack.get(), cert.x509_ptr.get());
	}
	
	auto BioIn=newBIO(dataFilename, "r");
	cms_ptr = uniqeCMS{ CMS_encrypt(x509Stack.get(), 
									BioIn.get(), 
									EVP_des_ede3_cbc(), 
									CMS_TEXT), 
						CMSDeleter() };

	return cms_ptr !=nullptr;
}

bool CMS::decodeEnvelope(const PairKey& privKey)
{
	encodedData_ptr = newBIO();
	auto ret=CMS_decrypt(cms_ptr.get(), 
						privKey.evp_ptr.get(), 
						nullptr, 
						nullptr, 
						encodedData_ptr.get(),
						CMS_TEXT);
	
	return ret == 1;
}


bool CMS::save(const string& filename)
{	
	auto bioOut=newBIO(filename, "w+");
	
	auto ret= SMIME_write_CMS(bioOut.get(), cms_ptr.get(), nullptr, CMS_TEXT);
	return ret==1;
}

bool CMS::verifySignedData(const PairKey& caPubKey)
{
	X509Cert certCA(caPubKey);
	
	auto x509Str=newX509STR();

	auto ret=X509_STORE_add_cert(x509Str.get(), certCA.x509_ptr.get());
	if (ret != 1) {
		return false;
	}

	ERR_clear_error();
	encodedData_ptr = newBIO();

	ret=CMS_verify(cms_ptr.get(), 
					nullptr, 
					x509Str.get(),
					nullptr, 
					encodedData_ptr.get(), 
					CMS_TEXT);
	/*
	if (ret != 1) {
		auto errF=newBIO("errors.txt", "w+");
		ERR_print_errors(errF.get());
	}
	*/
	return ret==1;
}

bool CMS::readFromFile(const string& cmsFilename)
{
	auto bioCms = newBIO(cmsFilename, "r");
	if (bioCms == nullptr) {
		return false;
	}

	cms_ptr = uniqeCMS{ SMIME_read_CMS(bioCms.get(), nullptr), 
						CMSDeleter() };
	return cms_ptr == nullptr;
	
}
