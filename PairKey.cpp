#include "pch.h"
#include "PairKey.h"
#include <openssl/pem.h>
#include <assert.h>

PairKey::PairKey(Key_t type)
{
	int ret = -1;
	switch (type) {
	case Key_t::EC_key:
	{
		auto eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		assert(1 == EC_KEY_generate_key(eckey));
		assert(1 == EC_KEY_check_key(eckey));
		assert(1 == EVP_PKEY_assign_EC_KEY(evp_ptr.get(), eckey));

		break;
	}
	default:
		auto rsa = RSA_new();

		uniqeBignum bn_ptr(BN_new(), BIGNUMDeleter());

		assert(1 == BN_set_word(bn_ptr.get(), RSA_F4));

		assert(1 == RSA_generate_key_ex(rsa, 2048, bn_ptr.get(), nullptr));

		assert(1 == EVP_PKEY_assign_RSA(evp_ptr.get(), rsa));
	}

	bPrivate = true;
}

bool PairKey::savePublicKey(const string& filename)
{
	uniqeBIO bio_ptr = newBIO(filename.c_str(), "w+");

	return PEM_write_bio_PUBKEY(bio_ptr.get(), evp_ptr.get());
}

bool PairKey::savePrivateKey(const string& filename)
{
	uniqeBIO bio_ptr = newBIO(filename.c_str(), "w+");
	return PEM_write_bio_PrivateKey(bio_ptr.get(), evp_ptr.get(), nullptr, nullptr, 0, nullptr, nullptr);
}

bool PairKey::readPublicKey(const string& filename)
{
	uniqeBIO bio_ptr = newBIO(filename, "r");

	evp_ptr = uniqeEVP{ PEM_read_bio_PUBKEY(bio_ptr.get(), nullptr, nullptr, nullptr), EVPDeleter() };
	bPrivate = false;
	return evp_ptr != nullptr;
}

bool PairKey::readPrivate(const string& filename)
{
	uniqeBIO bio_ptr = newBIO(filename, "r");

	if (bio_ptr == nullptr) {
		return false;
	}

	evp_ptr = uniqeEVP{ PEM_read_bio_PrivateKey(bio_ptr.get(), nullptr,nullptr, nullptr), EVPDeleter() };

	bPrivate = evp_ptr != nullptr ? true : bPrivate;
	return evp_ptr != nullptr;
}

bool PairKey::isPrivate()
{
	return bPrivate;
}

Key_t PairKey::getType()
{
	if (evp_ptr == nullptr) {
		return Key_t::UNK;
	}

	switch (auto typeId = EVP_PKEY_base_id(evp_ptr.get())) {
	case EVP_PKEY_RSA:
		return Key_t::RSA_key;
	case EVP_PKEY_EC:
		return Key_t::EC_key;
	default:
		return Key_t::UNK;
	}
}

vector<unsigned char> PairKey::sign(const vector<unsigned char>& msg)
{
	const int sha256Len = 32;
	unsigned char sha[sha256Len];

	SHA256(&(msg[0]), msg.size(), sha);
	auto evpctx_ptr = newEVPCTX(evp_ptr);

	assert(1 == EVP_PKEY_sign_init(evpctx_ptr.get()));

	assert(1 == EVP_PKEY_CTX_set_signature_md(evpctx_ptr.get(), EVP_sha256()));

	size_t signLen = 0;
	assert(1 == EVP_PKEY_sign(evpctx_ptr.get(), NULL, &signLen, sha, sha256Len));

	vector<unsigned char> sig(signLen);

	auto ret = EVP_PKEY_sign(evpctx_ptr.get(), &(sig[0]), &signLen, sha, sha256Len);

	if (ret != 1) {
		return vector<unsigned char>(0);
	}

	if (signLen != sig.size()) {
		sig.resize(signLen);
	}

	return sig;
}

bool PairKey::verifySign(const vector<unsigned char>& sign, const vector<unsigned char>& msg)
{
	const int sha256Len = 32;
	unsigned char sha[sha256Len];

	SHA256(&(msg[0]), msg.size(), sha);
	auto evpctx_ptr = newEVPCTX(evp_ptr);

	assert(1 == EVP_PKEY_verify_init(evpctx_ptr.get()));

	assert(1 == EVP_PKEY_CTX_set_signature_md(evpctx_ptr.get(), EVP_sha256()));

	auto ret = EVP_PKEY_verify(evpctx_ptr.get(), &sign[0], sign.size(), sha, sha256Len);
	assert(ret != -2);
	return ret == 1;
}
