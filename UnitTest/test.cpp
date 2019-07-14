#include "pch.h"

#include "../PairKey.h"
#include "../X509Cert.h"

TEST(TestCaseName, rsakey_gen) {
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

TEST(TestCaseName, sign) {

	PairKey key;
	vector<unsigned char> msg = { 'a', 'd', 'f' };
	auto sign=key.sign(msg);
	ASSERT_TRUE(sign.size() > 0);
	ASSERT_TRUE(key.verifySign(sign, msg));

	PairKey keyEc(Key_t::EC_key);
	auto signEc = keyEc.sign(msg);
	cout << "sig ec len: " << signEc.size() << endl;
	ASSERT_TRUE(signEc.size() > 0);
	ASSERT_TRUE(keyEc.verifySign(signEc, msg));
	
}

TEST(TestCaseName, ec_gen) {
	PairKey key(Key_t::EC_key);
	ASSERT_EQ(key.getType(), Key_t::EC_key);
	ASSERT_TRUE(key.savePublicKey("public_ec.pem"));
	ASSERT_TRUE(key.savePrivateKey("private_ec.pem"));
}

TEST(TestCaseName, x509) {
	PairKey key, cakey;
	X509Cert cert(key);
	ASSERT_TRUE(cert.sign(cakey));
}



