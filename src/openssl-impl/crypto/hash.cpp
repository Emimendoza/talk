#include <crypto/hash.h>


using namespace talk::crypto;
using talk::bytes;

// Crypt context

hash::crypt_context::crypt_context(const char *type_name) : ctx(EVP_MD_CTX_new()) {
	type = EVP_MD_fetch(nullptr, type_name, nullptr);
	if (!type){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to fetch digest type");
	}
	if (!ctx){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to allocate memory for context");
	}
	if (!EVP_DigestInit_ex(ctx,  type, nullptr)){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to initialize context");
	}
}

hash::crypt_context::~crypt_context() {
	EVP_MD_CTX_free(ctx);
	EVP_MD_free(type);
}


// hash

hash::~hash() {
	delete context;
}

void hash::digestUpdate(const bytes &data) {
	if (context->is_finalized){
		throw std::domain_error("Context is finalized");
	}
	if (!EVP_DigestUpdate(context->ctx, data.data(), data.size())){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to update context");
	}
}

void hash::digestFinal(bytes& out) {
	out.resize(EVP_MD_size(context->type));
	if (!EVP_DigestFinal_ex(context->ctx, out.dataU8(), nullptr)){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to finalize context");
	}
	context->is_finalized = true;
}

void hash::digestReset() {
	if (!EVP_DigestInit_ex2(context->ctx, context->type, nullptr)){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to reset context");
	}
	context->is_finalized = false;
}