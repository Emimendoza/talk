#include <crypto/hash.h>

using namespace talk::crypto;

sha256::sha256() {
	context = new crypt_context("sha256");
}

sha512::sha512() {
	context = new crypt_context("sha512");
}

shake256::shake256() {
	context = new crypt_context("shake256");
}


