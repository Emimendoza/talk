#ifndef TALK_CRYPTO_H
#define TALK_CRYPTO_H
#include <common.h>
#include <memory>
namespace talk::internal{
	class Crypto{
	public:
		struct crypt_context;
		enum Type : uint16_t {
			PLAIN = 0x00,
			ED25519 = 0x01
		};
	private:
		static constexpr Type type = PLAIN; // Plain text
	public:
		virtual ~Crypto() = default;

		virtual uint16_t getType() {return Crypto::type;}
		virtual bytes encrypt(const bytes& data) {return data;}
		virtual bytes decrypt(const bytes& data) {return data;}
		virtual bytes sign(const bytes& data) {return {};}
		virtual bool verify(const bytes& data, const bytes& signature) {return false;}

		virtual crypt_context* getContext(){return nullptr;}
		virtual crypt_context* generateKeyPair() {return nullptr;}
	};

	class Ed25519 final : public Crypto{
	private:
		static constexpr Type type = ED25519;
	public:

		uint16_t getType() override;
		bytes encrypt(const bytes& data) override;
		bytes decrypt(const bytes& data) override;
		bytes sign(const bytes& data) override;
		bool verify(const bytes& data, const bytes& signature) override;

		crypt_context* getContext() override;
		crypt_context* generateKeyPair() override;
	};
}

#endif //TALK_CRYPTO_H
