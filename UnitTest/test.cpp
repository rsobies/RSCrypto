#include "pch.h"

#include "../PairKey.h"
#include "../X509Cert.h"

#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

class CrtCheckMemory
{
public:
	_CrtMemState state1;
	_CrtMemState state2;
	_CrtMemState state3;
	CrtCheckMemory()
	{
		{
			PairKey tmp;
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

	CrtCheckMemory check;
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

TEST_F(RSCryptoTestUnit, memLeak) {
	int start = 1;
	{
		auto eckeyPub = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		assert(1 == EC_KEY_generate_key(eckeyPub));
		assert(1 == EC_KEY_check_key(eckeyPub));

		auto evpPub = EVP_PKEY_new();
		assert(1 == EVP_PKEY_assign_EC_KEY(evpPub, eckeyPub));

		auto eckeyCA = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		assert(1 == EC_KEY_generate_key(eckeyCA));
		assert(1 == EC_KEY_check_key(eckeyCA));

		auto evpCA = EVP_PKEY_new();
		assert(1 == EVP_PKEY_assign_EC_KEY(evpCA, eckeyCA));

		auto cert = X509_new();

		assert(1 == X509_set_pubkey(cert, evpPub));

		auto ret1 = X509_sign(cert, evpCA, EVP_sha256());

		auto ret = X509_verify(cert, evpCA);

		EVP_PKEY_free(evpCA);
		EVP_PKEY_free(evpPub);
		X509_free(cert);
	}
	int end = 1;
}

TEST_F(RSCryptoTestUnit, saveload) {

	PairKey pubKey, cakey;
	{
		X509Cert cert(pubKey);

		ASSERT_TRUE(cert.sign(cakey));

		ASSERT_TRUE(cert.save("cert.pem"));
	}

	X509Cert cert(pubKey);
	ASSERT_TRUE(cert.load("cert.pem"));

	ASSERT_TRUE(cert.verify(cakey));
}



