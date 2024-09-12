#include <crypto.h>

using namespace talk::crypto;
using talk::bytes;


// Types
type_t plain::getType() const {
	return plain::type;
}

type_t ed448::getType() const {
	return ed448::type;
}

type_t ed25519::getType() const {
	return ed25519::type;
}

type_t sha256::getType() const {
	return sha256::type;
}

type_t sha512::getType() const {
	return sha512::type;
}

type_t shake256::getType() const {
	return shake256::type;
}

type_t argon2d::getType() const {
	return argon2d::type;
}

type_t hkdf::getType() const {
	return hkdf::type;
}

type_t sRand::getType() const {
	return sRand::type;
}

type_t fRand::getType() const {
	return fRand::type;
}

bytes cipher::encrypt(const bytes &data){
	bytes out{};
	encryptIn(data, out);
	return out;
}

bytes cipher::decrypt(const talk::bytes &data) {
	bytes out{};
	decryptIn(data, out);
	return out;
}

bytes signature::sign(const talk::bytes &data) const {
	bytes out{};
	signIn(data, out);
	return out;
}

bytes hash::digestFinal() {
	bytes out{};
	digestFinalIn(out);
	return out;
}

bytes signature::generateSharedSecret(const talk::crypto::signature &other) const {
	bytes out{};
	generateSharedSecretIn(other, out);
	return out;
}

bytes kdf::deriveKey(const bytes &salt, const bytes &password) {
	bytes out{};
	deriveKeyIn(salt, password, out);
	return out;
}

bytes rand::random(size_t len) {
	bytes out{};
	randomIn(len, out);
	return out;
}