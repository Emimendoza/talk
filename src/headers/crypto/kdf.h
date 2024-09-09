#ifndef TALK_KDF_H
#define TALK_KDF_H
#include "crypto.h"

#include <openssl/kdf.h>
#include <openssl/params.h>

namespace talk::internal{
	static const OSSL_PARAM OSSL_END = OSSL_PARAM_construct_end();
}

namespace talk::crypto{
	class kdf::crypt_context{
		friend class kdf;
		friend class argon2d;
		friend class hkdf;

		EVP_KDF *kdf;
		EVP_KDF_CTX *ctx;
		std::vector<OSSL_PARAM> params;

		uint32_t* values{};

		crypt_context(const char* kdf_name,const std::vector<OSSL_PARAM>& def_params);
		~crypt_context();
	};
}


#endif //TALK_KDF_H
