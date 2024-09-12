#ifndef TALK_CRYPTO_H
#define TALK_CRYPTO_H
#include <common.h>
#include <memory>
namespace talk::crypto{
	enum type_t : uint16_t {
		// Special (0b0000 uppermost)
		INVALID = 0x0000,
		FAST_RAND = 0x0001,
		SAFE_RAND = 0x0002,
		// Ciphers (0b0001 uppermost)
		PLAIN = 0x1000,

		// Signatures (0b0010 uppermost)
		ED448 = 0x2000,
		ED25519 = 0x2001,
		// Hashes (0b0011 uppermost)
		SHA256 = 0x3000,
		SHA512 = 0x3001,
		SHAKE256 = 0x3002,
		BLAKE2B = 0x3003,
		// Key Derivation Functions (0b0100 uppermost)
		ARGON2D = 0x4000,
		HKDF = 0x4001
	};

	class cipher {
	public:
		[[nodiscard]] virtual type_t getType() const = 0;
		[[nodiscard]] bytes encrypt(const bytes &data);
		virtual void encryptIn(const bytes &data, bytes &out) = 0;
		[[nodiscard]] bytes decrypt(const bytes &data);
		virtual void decryptIn(const bytes &data, bytes &out) = 0;
	};

	class signature {
	public:
		// Signature API
		[[nodiscard]] virtual type_t getType() const = 0;

		virtual void generateKeyPair() = 0;
		virtual void signIn(const bytes &data, bytes &out) const = 0;

		[[nodiscard]] virtual bool verify(const bytes &data, const bytes &signature) const = 0;
		// Key API
		[[nodiscard]] virtual std::string exportPublicKey() const = 0;
		[[nodiscard]] virtual std::string exportPrivateKey() const = 0;
		virtual void generateSharedSecretIn(const signature &other, bytes &out) const = 0;

		[[nodiscard]] bytes generateSharedSecret(const signature &other) const;
		[[nodiscard]] bytes sign(const bytes &data) const;
	};

	class hash {
	public:
		[[nodiscard]] virtual type_t getType() const = 0;
		// hash API
		virtual void digestUpdate(const bytes &data) = 0;
		virtual void digestFinalIn(bytes &out) = 0;
		bytes digestFinal();
		virtual void digestReset() = 0;
	};

	class kdf{
	public:
		[[nodiscard]] virtual type_t getType() const = 0;
		virtual void deriveKeyIn(const bytes &salt, const bytes &password, bytes &out) = 0;
		[[nodiscard]] bytes deriveKey(const bytes &salt, const bytes &password);
		[[nodiscard]] virtual size_t outLen() const = 0;
	};

	class rand{
	public:
		[[nodiscard]] virtual type_t getType() const = 0;
		virtual void randomIn(size_t len, bytes& out) = 0;
		[[nodiscard]] bytes random(size_t len);

		template<size_t N>
		inline byteArr<N> random();
	};

	// declaring sub classes

	// ciphers
	class cipher; // (abstract)
	class plain;

	// signatures
	class signature; // (abstract)
	class ed448;
	class ed25519;

	// hashes
	class hash; // (abstract)
	class sha256;
	class sha512;
	class shake256;
	class blake2b;

	// kdf
	class kdf; // (abstract)
	class argon2d;
	class hkdf;

	// pseudorandom number generators
	class rand; // (abstract)
	class fRand;
	class sRand;

}

#include "internal/crypto.h"
#endif //TALK_CRYPTO_H
