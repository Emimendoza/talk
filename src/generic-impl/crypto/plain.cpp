#include <crypto.h>

using namespace talk::crypto;
using talk::bytes;

void plain::encrypt(const bytes& data, bytes& out) {
	out = data;
}

void plain::decrypt(const bytes& data, bytes& out) {
	out = data;
}
