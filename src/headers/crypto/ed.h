#ifndef TALK_ED_H
#define TALK_ED_H
#include <crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

namespace talk::internal{
	class Ed::crypt_context{
		friend class Ed448;
		friend class Ed25519;
		friend class Ed;

		EVP_PKEY *key;

		crypt_context();
		~crypt_context();
		void recreate();

		void generateKeyPair(int type);
	};
}

#endif //TALK_ED_H
