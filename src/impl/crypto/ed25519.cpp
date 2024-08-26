#include <crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace talk::internal;

struct Crypto::crypt_context{
	EVP_PKEY *key{};
	EVP_PKEY_CTX *ctx{};
};

uint16_t Ed25519::getType(){
	return Ed25519::type;
}



