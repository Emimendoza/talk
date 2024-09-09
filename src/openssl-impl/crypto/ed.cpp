#include <crypto/ed.h>

using namespace talk::crypto;
using talk::bytes;

ed::crypt_context::crypt_context(const int &type, const char *digest_name) : key(EVP_PKEY_new()), type(type) {
	if (!digest_name){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Digest name is null");
	}
	digest_type = EVP_MD_fetch(nullptr, digest_name, nullptr);
	if (!digest_type) {
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to allocate memory for digest type");
	}
	if (!key){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to allocate memory for key");
	}
}

ed::crypt_context::~crypt_context() {
	EVP_PKEY_free(key);
	EVP_MD_free(digest_type);
}

ed::~ed(){
	delete context;
}

std::string ed::exportPublicKey() const {
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

std::string ed::exportPrivateKey() const {
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

void ed::sign(const bytes &data, bytes &out) const {
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if (!mdctx){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to allocate memory for message digest context");
	}
	if (!EVP_DigestSignInit(mdctx, nullptr, context->digest_type, nullptr, context->key)){
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
	if (!EVP_DigestSignFinal(mdctx, out.dataU8(), &sig_len)){
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(mdctx);
		throw std::runtime_error("Failed to sign data");
	}
	EVP_MD_CTX_free(mdctx);
}

bool ed::verify(const bytes &data, const bytes &signature) const {
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if (!mdctx){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to allocate memory for message digest context");
	}
	if (!EVP_DigestVerifyInit(mdctx, nullptr, context->digest_type, nullptr, context->key)){
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(mdctx);
		throw std::runtime_error("Failed to initialize message digest context");
	}
	if (!EVP_DigestVerifyUpdate(mdctx, data.data(), data.size())){
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(mdctx);
		throw std::runtime_error("Failed to update message digest context");
	}
	int ret = EVP_DigestVerifyFinal(mdctx, signature.dataU8(), signature.size());
	EVP_MD_CTX_free(mdctx);

	// No errors on openssl side but the signature is invalid
	if (ret == 0){
		return false;
	}

	// Error on openssl side
	if (ret != 1){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to verify signature");
	}

	return true;
}

void ed::generateKeyPair() {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(context->type, nullptr);
	if (!ctx){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to create key generation context");
	}

	if(!EVP_PKEY_keygen_init(ctx)){
		EVP_PKEY_CTX_free(ctx);
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to initialize key generation context");
	}
	if (!EVP_PKEY_keygen(ctx, &context->key)){
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		throw std::runtime_error("Failed to generate key pair");
	}
	EVP_PKEY_CTX_free(ctx);
}

void ed::generateSharedSecret(const signature &other, talk::bytes &out) const {
	if (this->getType() != other.getType()){
		throw std::domain_error("Different crypto types");
	}
	const ed &other_ed = dynamic_cast<const ed&>(other);
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(context->key, nullptr);
	if (!ctx){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to create key derivation context");
	}
	if (!EVP_PKEY_derive_init(ctx)){
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		throw std::runtime_error("Failed to initialize key derivation context");
	}
	if (!EVP_PKEY_derive_set_peer(ctx, other_ed.context->key)){
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		throw std::runtime_error("Failed to set peer key");
	}
	size_t len;
	if (!EVP_PKEY_derive(ctx, nullptr, &len)){
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		throw std::runtime_error("Failed to get shared secret length");
	}
	out.resize(len);
	if (!EVP_PKEY_derive(ctx, out.dataU8(), &len)){
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		throw std::runtime_error("Failed to derive shared secret");
	}
	EVP_PKEY_CTX_free(ctx);
}
