#include <crypto/ed.h>

using namespace talk::internal;
using talk::bytes;

constexpr Crypto::Type Ed25519::getType() const {
	return Ed25519::type;
}

void Ed25519::generateKeyPair() {
	context->generateKeyPair(EVP_PKEY_ED25519);
}

void Ed25519::sign(const bytes &data, bytes &out) {
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if (!mdctx){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to allocate memory for message digest context");
	}
	if (!EVP_DigestSignInit(mdctx, nullptr, EVP_sha512(), nullptr, context->key)){
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(mdctx);
		throw std::runtime_error("Failed to initialize message digest context");
	}
	if (!EVP_DigestSignUpdate(mdctx, data.data(), data.size())){
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(mdctx);
		throw std::runtime_error("Failed to update message digest context");
	}
	size_t sig_len;
	if (!EVP_DigestSignFinal(mdctx, nullptr, &sig_len)){
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(mdctx);
		throw std::runtime_error("Failed to get signature length");
	}
	out.resize(sig_len);
	if (!EVP_DigestSignFinal(mdctx, out.data_u8(), &sig_len)){
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(mdctx);
		throw std::runtime_error("Failed to sign data");
	}
	EVP_MD_CTX_free(mdctx);
}

bool Ed25519::verify(const bytes &data, const bytes &signature) {
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if (!mdctx){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to allocate memory for message digest context");
	}
	if (!EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha512(), nullptr, context->key)){
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(mdctx);
		throw std::runtime_error("Failed to initialize message digest context");
	}
	if (!EVP_DigestVerifyUpdate(mdctx, data.data(), data.size())){
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(mdctx);
		throw std::runtime_error("Failed to update message digest context");
	}
	int ret = EVP_DigestVerifyFinal(mdctx, signature.data_u8(), signature.size());

	// No errors on openssl side but the signature is invalid
	if (ret == 0){
		EVP_MD_CTX_free(mdctx);
		return false;
	}
	// More serious error
	if (ret != 1){
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(mdctx);
		throw std::runtime_error("Failed to verify signature");
	}
	// Signature is valid
	EVP_MD_CTX_free(mdctx);
	return true;
}




