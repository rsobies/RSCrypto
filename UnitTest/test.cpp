#include "pch.h"

#include "../PairKey.h"

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
	PairKey key, keyEc(Key_t::EC_key);

	vector<unsigned char> msg = { 'a', 'd', 'f' };
	auto sign=key.sign(msg);
	auto signEc = keyEc.sign(msg);
	ASSERT_TRUE(sign.size() > 0);
	ASSERT_TRUE(signEc.size() > 0);

	ASSERT_TRUE(key.verifySign(sign, msg));
	ASSERT_TRUE(keyEc.verifySign(signEc, msg));
}

TEST(TestCaseName, ec_gen) {
	PairKey key(Key_t::EC_key);
	ASSERT_EQ(key.getType(), Key_t::EC_key);
	ASSERT_TRUE(key.savePublicKey("public_ec.pem"));
	ASSERT_TRUE(key.savePrivateKey("private_ec.pem"));
}

