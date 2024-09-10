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
		void encryptIn(const bytes& data, bytes& out) override;
		void decryptIn(const bytes& data, bytes& out) override;
	};

	class ed25519 final : public signature {
	private:
		struct crypt_context;
		std::unique_ptr<crypt_context> ctx;
		static constexpr type_t type = ED25519;
	public:
		void signIn(const bytes& data, bytes& out) const override;
		[[nodiscard]] bool verify(const bytes& data, const bytes& signature) const override;
		void generateKeyPair() override;
		void generateSharedSecretIn(const signature& other, bytes& out) const override;

		[[nodiscard]] std::string exportPublicKey() const override;
		[[nodiscard]] std::string exportPrivateKey() const override;

		[[nodiscard]] type_t getType() const override;
		ed25519();
		~ed25519();
	};

	class ed448 final : public signature{
	private:
		struct crypt_context;
		std::unique_ptr<crypt_context> ctx;
		static constexpr type_t type = ED448;
	public:

		void signIn(const bytes& data, bytes& out) const override;
		[[nodiscard]] bool verify(const bytes& data, const bytes& signature) const override;
		void generateKeyPair() override;
		void generateSharedSecretIn(const signature& other, bytes& out) const override;

		[[nodiscard]] std::string exportPublicKey() const override;
		[[nodiscard]] std::string exportPrivateKey() const override;
		[[nodiscard]] type_t getType() const override;
		ed448();
		~ed448();

	};

	class sha256 final : public hash {
	private:
		struct crypt_context;
		std::unique_ptr<crypt_context> ctx;
		static constexpr type_t type = SHA256;
	public:
		[[nodiscard]] type_t getType() const override;
		void digestUpdate(const bytes &data) override;
		void digestFinalIn(bytes &out) override;
		void digestReset() override;
		sha256();
		~sha256();
	};

	class sha512 final : public hash {
	private:
		struct crypt_context;
		std::unique_ptr<crypt_context> ctx;
		static constexpr type_t type = SHA512;
	public:
		[[nodiscard]] type_t getType() const override;
		void digestUpdate(const bytes &data) override;
		void digestFinalIn(bytes &out) override;
		void digestReset() override;
		sha512();
		~sha512();
	};

	class shake256 final : public hash {
	private:
		struct crypt_context;
		std::unique_ptr<crypt_context> ctx;
		static constexpr type_t type = SHAKE256;
	public:
		[[nodiscard]]  type_t getType() const override;
		void digestUpdate(const bytes &data) override;
		void digestFinalIn(bytes &out) override;
		void digestReset() override;
		shake256();
		~shake256();
	};

	class argon2d final : public kdf {
	private:
		struct crypt_context;
		std::unique_ptr<crypt_context> ctx;
		static constexpr type_t type = ARGON2D;
	public:
		[[nodiscard]] type_t getType() const override;
		void deriveKeyIn(const bytes &salt, const bytes &password, size_t length, bytes &out) override;
		argon2d(uint32_t threads, uint32_t lanes, uint32_t memory, uint32_t iterations);
		~argon2d();

	};

	class hkdf final : public kdf {
	private:
		struct crypt_context;
		std::unique_ptr<crypt_context> ctx;
		static constexpr type_t type = HKDF;
	public:
		[[nodiscard]] type_t getType() const override;
		void deriveKeyIn(const bytes &salt, const bytes &password, size_t length, bytes &out) override;
		hkdf();
		~hkdf();
	};

	class sRand final : public rand{
	private:
		struct crypt_context;
		std::unique_ptr<crypt_context> ctx;
		static constexpr type_t type = SAFE_RAND;
	public:
		sRand();
		~sRand();
		[[nodiscard]] type_t getType() const override;
		void randomIn(size_t len, bytes &out) override;
	};

	class fRand final : public rand{
	private:
		struct crypt_context;
		std::unique_ptr<crypt_context> ctx;
		static constexpr type_t type = SAFE_RAND;
	public:
		explicit fRand(uint32_t seed);
		fRand();
		~fRand();
		[[nodiscard]] type_t getType() const override;
		void randomIn(size_t len, bytes &out) override;
	};

	template<size_t N>
	std::array<byte, N> rand::random(){
		bytes out{};
		randomIn(N, out);
		return out.toArray<N>();
	}
}

#endif //TALK_INTERNAL_CRYPTO_H
