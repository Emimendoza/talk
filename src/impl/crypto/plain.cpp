#include <crypto.h>

using namespace talk::internal;
using talk::bytes;

constexpr Crypto::Type Plain::getType() const {
	return Plain::type;
}

void Plain::encrypt(const bytes& data, bytes& out) {
	out = data;
}

void Plain::decrypt(const bytes& data, bytes& out) {
	out = data;
}
