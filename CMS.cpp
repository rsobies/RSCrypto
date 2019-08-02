#include "pch.h"
#include "CMS.h"
#include "X509Cert.h"
#include "PairKey.h"
#include <openssl/err.h>

bool CMS::signedData(const X509Cert& cert, const PairKey& privKey, const string& dataFilename)
{	
	bioData_ptr =newBIO(dataFilename, "r");
	if (bioData_ptr==nullptr) {
		return false;
	}
	auto cms = CMS_sign(cert.x509_ptr.get(), privKey.evp_ptr.get(), nullptr, bioData_ptr.get(), CMS_TEXT);
	
	cms_ptr = uniqeCMS{ cms, CMSDeleter() };
	
	return cms_ptr!=nullptr;
}

bool CMS::saveSignedData(const string& filename)
{
	auto bioOut=newBIO(filename, "w+");
	auto ret=PEM_write_bio_CMS_stream(bioOut.get(), cms_ptr.get(), bioData_ptr.get(), CMS_TEXT);
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
	auto biop = newBIO();
	ret=CMS_verify(cms_ptr.get(), nullptr, x509Str.get(), nullptr, biop.get(), CMS_TEXT);
	/*
	if (ret != 1) {
		auto errF=newBIO("errors.txt", "w+");
		ERR_print_errors(errF.get());
	}*/
	
	return ret==1;
}

bool CMS::readFromFile(const string& cmsFilename)
{
	auto bioCms = newBIO(cmsFilename, "r");
	if (bioCms == nullptr) {
		return false;
	}

	cms_ptr = uniqeCMS{ SMIME_read_CMS(bioCms.get(), nullptr), CMSDeleter() };
	return cms_ptr == nullptr;
	
}
