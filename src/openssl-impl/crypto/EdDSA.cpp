#include <crypto/ed.h>

using namespace talk::crypto;

ed448::ed448() {
	context = new crypt_context(EVP_PKEY_ED448, "shake256");
}

ed25519::ed25519() {
	context = new crypt_context(EVP_PKEY_ED25519, "sha512");
}