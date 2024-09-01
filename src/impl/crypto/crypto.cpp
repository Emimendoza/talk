#include <crypto.h>

using namespace talk::internal;
using talk::bytes;

constexpr Crypto::Type Crypto::getType() const {
	return Crypto::type;
}

bytes Crypto::encrypt(const bytes& data) {
	bytes out{};
	encrypt(data, out);
	return out;
}

bytes Crypto::decrypt(const bytes& data) {
	bytes out{};
	decrypt(data, out);
	return out;
}
bytes Crypto::sign(const bytes& data) {
	bytes out{};
	sign(data, out);
	return out;
}

void Crypto::encrypt(const bytes& data, bytes& out) {
	throw std::domain_error("Encryption not supported by this crypto type");
}

void Crypto::decrypt(const bytes& data, bytes& out) {
	throw std::domain_error("Decryption not supported by this crypto type");
}

void Crypto::sign(const bytes& data, bytes& out) {
	throw std::domain_error("Signing not supported by this crypto type");
}

bool Crypto::verify(const bytes& data, const bytes& signature) {
	throw std::domain_error("Verification not supported by this crypto type");
}

void Crypto::generateKeyPair() {
	throw std::domain_error("Key generation not supported by this crypto type");
}

std::string Crypto::exportPublicKey() const {
	throw std::domain_error("Exporting public key not supported by this crypto type");
}

std::string Crypto::exportPrivateKey() const {
	throw std::domain_error("Exporting private key not supported by this crypto type");
}
