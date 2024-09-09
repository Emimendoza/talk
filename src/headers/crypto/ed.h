#ifndef TALK_ED_H
#define TALK_ED_H
#include <crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

namespace talk::crypto{
	class ed::crypt_context{
		friend class ed448;
		friend class ed25519;
		friend class ed;

		EVP_PKEY *key;
		EVP_MD *digest_type;
		const int type;

		explicit crypt_context(const int &type, const char *digest_name);
		~crypt_context();
	};
}

#endif //TALK_ED_H
