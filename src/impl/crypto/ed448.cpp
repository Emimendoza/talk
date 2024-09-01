#include <crypto/ed.h>

using namespace talk::internal;
using talk::bytes;

constexpr Crypto::Type Ed448::getType() const {
	return Crypto::Type::ED448;
}

void Ed448::generateKeyPair() {
	context->generateKeyPair(EVP_PKEY_ED448);
}