#include <crypto.h>

using namespace talk::crypto;
using talk::bytes;

void plain::encryptIn(const bytes& data, bytes& out) {
	out = data;
}

void plain::decryptIn(const bytes& data, bytes& out) {
	out = data;
}
