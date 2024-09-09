#include <crypto/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <cstring>

using namespace talk::crypto;



kdf::crypt_context::crypt_context(const char* kdf_name, const std::vector<OSSL_PARAM>& def_params) : params(def_params){
	kdf = EVP_KDF_fetch(nullptr, kdf_name, nullptr);
	if (!kdf) {
		throw std::runtime_error("Failed to fetch kdf");
	}

	ctx = EVP_KDF_CTX_new(kdf);
	if (!ctx) {
		throw std::runtime_error("Failed to create kdf context");
	}
}

kdf::crypt_context::~crypt_context() {
	EVP_KDF_CTX_free(ctx);
	delete[] values;
	EVP_KDF_free(kdf);
}

kdf::~kdf() {
	delete context;
}

void kdf::deriveKey(const bytes &salt, const bytes &password, size_t length, bytes &out) {
	if (!salt.empty()){
		context->params.push_back(OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *) salt.data(),
																	salt.size()));
	}
	context->params.push_back(OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *) password.data(),
																password.size()));
	context->params.push_back(internal::OSSL_END);

	auto ret = EVP_KDF_derive(context->ctx, out.dataU8(), out.size(), context->params.data());

	EVP_KDF_CTX_reset(context->ctx);

	context->params.pop_back();
	context->params.pop_back();
	if (!salt.empty()){
		context->params.pop_back();
	}

	if(ret != 1){
		throw std::runtime_error("Failed to derive key");
	}
}
