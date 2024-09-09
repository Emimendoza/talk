#ifndef TALK_HASH_H
#define TALK_HASH_H
#include <crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>

namespace talk::crypto{
	class hash::crypt_context{
		friend class sha512;
		friend class sha256;
		friend class shake256;
		friend class hash;

		EVP_MD_CTX *ctx;
		EVP_MD *type;
		bool is_finalized = false;

		explicit crypt_context(const char *type_name);
		~crypt_context();
	};

}

#endif //TALK_HASH_H
