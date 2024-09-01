#ifndef TALK_CRYPTO_H
#define TALK_CRYPTO_H
#include <common.h>
#include <memory>
namespace talk::internal{
	class Crypto{
	public:
		enum Type : uint16_t {
			BASE = 0x00,
			PLAIN = 0x01,
			ED25519 = 0x02,
			ED448 = 0x03
		};
	private:
		static constexpr Type type = BASE;
	public:
		virtual ~Crypto() = default;

		[[nodiscard]] virtual constexpr Type getType() const;
		virtual bytes encrypt(const bytes& data);
		virtual void encrypt(const bytes& data, bytes& out);
		virtual bytes decrypt(const bytes& data);
		virtual void decrypt(const bytes& data, bytes& out);

		virtual void sign(const bytes& data, bytes& out);
		virtual bytes sign(const bytes& data);
		virtual bool verify(const bytes& data, const bytes& signature);

		virtual void generateKeyPair();
		[[nodiscard]] virtual std::string exportPublicKey() const;
		[[nodiscard]] virtual std::string exportPrivateKey() const;
	};

	class Plain final : public Crypto {
	private:
		static constexpr Type type = PLAIN;
	public:
		[[nodiscard]] constexpr Type getType() const override;
		void encrypt(const bytes& data, bytes& out) override;
		void decrypt(const bytes& data, bytes& out) override;
	};

	class Ed : public Crypto {
	protected:
		class crypt_context;
		crypt_context *context;
	public:
		[[nodiscard]] constexpr Type getType() const override = 0;

		Ed();
		~Ed() override;

		void sign(const bytes& data, bytes& out) override = 0;
		bool verify(const bytes& data, const bytes& signature) override = 0;
		void generateKeyPair() override = 0;

		[[nodiscard]] std::string exportPublicKey() const override;
		[[nodiscard]] std::string exportPrivateKey() const override;
	};

	class Ed25519 final : public Ed {
	private:
		static constexpr Type type = ED25519;
	public:
		[[nodiscard]] constexpr Type getType() const override;

		void sign(const bytes& data, bytes& out) override;
		bool verify(const bytes& data, const bytes& signature) override;
		void generateKeyPair() override;

	};

	class Ed448 final : public Ed{
	private:
		static constexpr Type type = ED448;
	public:
		[[nodiscard]] constexpr Type getType() const override;
		void sign(const bytes& data, bytes& out) override;
		bool verify(const bytes& data, const bytes& signature) override;

		void generateKeyPair() override;
	};
}

#endif //TALK_CRYPTO_H
