#include <crypto/ed.h>

using namespace talk::internal;
using talk::bytes;

void Ed::crypt_context::recreate() {
	EVP_PKEY_free(key);
	key = EVP_PKEY_new();
	if (!key){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to allocate memory for key");
	}
}

void Ed::crypt_context::generateKeyPair(int type) {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(type, nullptr);
	if (!ctx){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to create key generation context");
	}

	if(!EVP_PKEY_keygen_init(ctx)){
		EVP_PKEY_CTX_free(ctx);
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to initialize key generation context");
	}
	if (!EVP_PKEY_keygen(ctx, &key)){
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		throw std::runtime_error("Failed to generate key pair");
	}
	EVP_PKEY_CTX_free(ctx);
}

Ed::crypt_context::crypt_context() : key(EVP_PKEY_new()) {
	if (!key){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to allocate memory for key");
	}
}

Ed::crypt_context::~crypt_context() {
	EVP_PKEY_free(key);
}

Ed::Ed() : context(new crypt_context) {}

Ed::~Ed(){
	delete context;
}

std::string Ed::exportPublicKey() const {
	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to allocate memory for BIO");
	}
	if (!PEM_write_bio_PUBKEY(bio, context->key)){
		ERR_print_errors_fp(stderr);
		BIO_free(bio);
		throw std::runtime_error("Failed to write public key to BIO");
	}
	char *data;
	size_t len = BIO_get_mem_data(bio, &data);
	std::string out(data, len);
	BIO_free(bio);
	return out;
}

std::string Ed::exportPrivateKey() const {
	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to allocate memory for BIO");
	}
	if (!PEM_write_bio_PrivateKey(bio, context->key, nullptr, nullptr, 0, nullptr, nullptr)){
		ERR_print_errors_fp(stderr);
		BIO_free(bio);
		throw std::runtime_error("Failed to write private key to BIO");
	}
	char *data;
	size_t len = BIO_get_mem_data(bio, &data);
	std::string out(data, len);
	BIO_free(bio);
	return out;
}
