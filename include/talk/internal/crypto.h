#ifndef TALK_INTERNAL_CRYPTO_H
#define TALK_INTERNAL_CRYPTO_H
#ifndef TALK_CRYPTO_H
// Don't include this file directly, use 'crypto.h' instead
#error "include 'crypto.h' instead"
#endif //TALK_CRYPTO_H

namespace talk::crypto{
	// Declaration of implementations of the crypto interface
	// Moved to this header file to not clutter the main public header
	// as the main headers are meant to be a self documenting API

	class plain final : public cipher {
	private:
		static constexpr type_t type = PLAIN;
	public:
		[[nodiscard]]
		type_t getType() const override;
		void encrypt(const bytes& data, bytes& out) override;
		void decrypt(const bytes& data, bytes& out) override;
	};

	class ed : public signature {
	protected:
		class crypt_context;
		crypt_context *context;
	public:
		[[nodiscard]] type_t getType() const override = 0;

		~ed();

		void sign(const bytes& data, bytes& out) const override;
		[[nodiscard]] bool verify(const bytes& data, const bytes& signature) const override;
		void generateKeyPair() override;
		void generateSharedSecret(const signature& other, bytes& out) const override;

		[[nodiscard]] std::string exportPublicKey() const override;
		[[nodiscard]] std::string exportPrivateKey() const override;
	};

	class ed25519 final : public ed {
	private:
		static constexpr type_t type = ED25519;
	public:
		[[nodiscard]] type_t getType() const override;
		ed25519();
	};

	class ed448 final : public ed{
	private:
		static constexpr type_t type = ED448;
	public:
		[[nodiscard]] type_t getType() const override;
		ed448();

	};

	class sha256 final : public hash {
	private:
		static constexpr type_t type = SHA256;
	public:
		[[nodiscard]] type_t getType() const override;
		sha256();
	};

	class sha512 final : public hash {
	private:
		static constexpr type_t type = SHA512;
	public:
		[[nodiscard]] type_t getType() const override;
		sha512();
	};

	class shake256 final : public hash {
	private:
		static constexpr type_t type = SHAKE256;
	public:
		[[nodiscard]]  type_t getType() const override;
		shake256();
	};

	class argon2d final : public kdf {
	private:
		static constexpr type_t type = ARGON2D;
	public:
		[[nodiscard]] type_t getType() const override;
		argon2d(uint32_t threads, uint32_t lanes, uint32_t memory);
	};

	class hkdf final : public kdf {
	private:
		static constexpr type_t type = HKDF;
	public:
		[[nodiscard]] type_t getType() const override;
		hkdf();
	};

	class sRand final : public rand{
	private:
		static constexpr type_t type = SAFE_RAND;
	public:
		sRand();
		[[nodiscard]] type_t getType() const override;
		void random(size_t len, bytes& out) override;
	};

	class fRand final : public rand{
	private:
		static constexpr type_t type = SAFE_RAND;
	public:
		explicit fRand(uint32_t seed);
		fRand();
		[[nodiscard]] type_t getType() const override;
		void random(size_t len, bytes& out) override;
	};
}

#endif //TALK_INTERNAL_CRYPTO_H
