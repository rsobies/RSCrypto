#include "pch.h"

#include "../PairKey.h"
#include "../X509Cert.h"
#include "../CMS.h"

#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#include <openssl/engine.h>
#include <openssl/conf.h>

class CrtCheckMemory
{
public:
	_CrtMemState state1;
	_CrtMemState state2;
	_CrtMemState state3;
	CrtCheckMemory()
	{
		{
			PairKey pubKey, cakey;

			X509Cert cert(pubKey);

			cert.sign(cakey);
			cert.verify(cakey);
		}
		{
			PairKey key;
			vector<unsigned char> msg = { 'a', 'd', 'f' };
			auto sign = key.sign(msg);

			key.verifySign(sign, msg);

			PairKey keyEc(Key_t::EC_key);
			auto signEc = keyEc.sign(msg);

			keyEc.verifySign(signEc, msg);
		}
		{
			PairKey pubKey, cakey;

			X509Cert cert(pubKey);

			cert.sign(cakey);

			CMS cms;
			cms.signedData(cert, pubKey, "pliczek.txt");
			cms.save("cms.pem");
		}
		_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

		_CrtMemCheckpoint(&state1);
	}
	~CrtCheckMemory()
	{
		_CrtMemCheckpoint(&state2);

		EXPECT_EQ(0, _CrtMemDifference(&state3, &state1, &state2));

		if (_CrtMemDifference(&state3, &state1, &state2))
			_CrtMemDumpStatistics(&state3);
	}
};

class RSCryptoTestUnit : public testing::Test {
public:

private:

	//CrtCheckMemory check;
};

TEST_F(RSCryptoTestUnit, rsakey_gen) {

	PairKey key(Key_t::RSA_key);
	ASSERT_EQ(key.getType(), Key_t::RSA_key);
	ASSERT_TRUE(key.savePublicKey("public.pem"));
	ASSERT_TRUE(key.savePrivateKey("private.pem"));
	ASSERT_TRUE(key.readPublicKey("public.pem"));
	ASSERT_FALSE(key.isPrivate());
	key.getType();
	ASSERT_TRUE(key.readPrivate("private.pem"));
	ASSERT_TRUE(key.isPrivate());
	ASSERT_EQ(key.getType(), Key_t::RSA_key);

}

TEST_F(RSCryptoTestUnit, sign) {

	PairKey key;
	vector<unsigned char> msg = { 'a', 'd', 'f' };
	auto sign = key.sign(msg);
	ASSERT_TRUE(sign.size() > 0);
	ASSERT_TRUE(key.verifySign(sign, msg));

	PairKey keyEc(Key_t::EC_key);
	auto signEc = keyEc.sign(msg);

	ASSERT_TRUE(signEc.size() > 0);
	ASSERT_TRUE(keyEc.verifySign(signEc, msg));

}

TEST_F(RSCryptoTestUnit, ec_gen) {

	PairKey key(Key_t::EC_key);
	ASSERT_EQ(key.getType(), Key_t::EC_key);
	ASSERT_TRUE(key.savePublicKey("public_ec.pem"));
	ASSERT_TRUE(key.savePrivateKey("private_ec.pem"));
}

TEST_F(RSCryptoTestUnit, x509) {

	PairKey pubKey, cakey;
	{
		X509Cert cert(pubKey);
		cert.setSubject("UK", "moja", "myhost");

		ASSERT_TRUE(cert.sign(cakey));

		ASSERT_TRUE(cert.save("cert.pem"));
	}
	
	X509Cert cert(pubKey);
	ASSERT_TRUE(cert.load("cert.pem"));

	ASSERT_TRUE(cert.verify(cakey));

	{
		X509Cert cert(pubKey);
		cert.setSubject("UK", "moja", "myhost");

		ASSERT_TRUE(cert.sign(pubKey));

		ASSERT_TRUE(cert.verify(pubKey));
	}
}

TEST_F(RSCryptoTestUnit, envelope) {

	PairKey pubKey, cakey;

	X509Cert cert(pubKey);
	cert.setSubject("UK", "moja", "myhost");
	ASSERT_TRUE(cert.sign(cakey));
	
	CMS cms;
	vector< X509Cert> certs;
	certs.push_back(move(cert));

	ASSERT_TRUE(cms.toEnvelope("pliczek.txt", certs));
	ASSERT_TRUE(cms.save("koperta.pem"));

	ASSERT_TRUE(cms.decodeEnvelope(pubKey));

}

TEST_F(RSCryptoTestUnit, cms) {
	PairKey pubKey, cakey, key;

	X509Cert cert(pubKey);
	cert.setSubject("UK", "moja", "myhost");
	ASSERT_TRUE(cert.sign(cakey));

	{
		CMS cms;
		PairKey key;
		ASSERT_FALSE(cms.signedData(cert, key, "pliczek.txt"));
	}

	{
		CMS cms;
		ASSERT_TRUE(cms.signedData(cert, pubKey, "pliczek.txt"));
		//ASSERT_TRUE(cms.saveSignedData("cms.pem"));
		ASSERT_TRUE(cms.verifySignedData(cakey));
	}

}
