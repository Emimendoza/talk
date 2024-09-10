#include <crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace talk::crypto;
using talk::bytes;

// we do all this in an anonymous namespace to avoid polluting the global namespace
// and to factor out the common code between ed448 and ed25519
// and we let the optimizer inline the functions
namespace{
	struct sig{
		EVP_PKEY *key;
		EVP_MD *digest_type;
		const int type;

		inline sig(const int &type, const char *digest_name);
		inline ~sig();

		[[nodiscard]] inline std::string exportPublicKey() const;
		[[nodiscard]] inline std::string exportPrivateKey() const;
		inline void sign(const bytes &data, bytes &out) const;
		[[nodiscard]] inline bool verify(const bytes &data, const bytes &signature) const;

		inline void generateKeyPair();

		inline void generateSharedSecret(const sig &other, talk::bytes &out) const;
	};
};

inline std::string sig::exportPublicKey() const {
	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to allocate memory for BIO");
	}
	if (!PEM_write_bio_PUBKEY(bio, key)){
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

inline std::string sig::exportPrivateKey() const  {
	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to allocate memory for BIO");
	}
	if (!PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr)){
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

inline void sig::sign(const talk::bytes &data, talk::bytes &out) const {
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if (!mdctx){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to allocate memory for message digest ctx");
	}
	if (!EVP_DigestSignInit(mdctx, nullptr, digest_type, nullptr, key)){
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(mdctx);
		throw std::runtime_error("Failed to initialize message digest ctx");
	}
	if (!EVP_DigestSignUpdate(mdctx, data.data(), data.size())){
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(mdctx);
		throw std::runtime_error("Failed to update message digest ctx");
	}
	size_t sig_len;
	if (!EVP_DigestSignFinal(mdctx, nullptr, &sig_len)){
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(mdctx);
		throw std::runtime_error("Failed to get signature length");
	}
	out.resize(sig_len);
	if (!EVP_DigestSignFinal(mdctx, out.data(), &sig_len)){
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(mdctx);
		throw std::runtime_error("Failed to signIn data");
	}
	EVP_MD_CTX_free(mdctx);
}

inline bool sig::verify(const bytes &data, const bytes &signature) const {
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if (!mdctx){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to allocate memory for message digest ctx");
	}
	if (!EVP_DigestVerifyInit(mdctx, nullptr, digest_type, nullptr, key)){
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(mdctx);
		throw std::runtime_error("Failed to initialize message digest ctx");
	}
	if (!EVP_DigestVerifyUpdate(mdctx, data.data(), data.size())){
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(mdctx);
		throw std::runtime_error("Failed to update message digest ctx");
	}
	int ret = EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size());
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

inline void sig::generateKeyPair() {
	EVP_PKEY_CTX* pCtx = EVP_PKEY_CTX_new_id(type, nullptr);
	if (!pCtx){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to create key generation pCtx");
	}

	if(!EVP_PKEY_keygen_init(pCtx)){
		EVP_PKEY_CTX_free(pCtx);
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to initialize key generation pCtx");
	}
	if (!EVP_PKEY_keygen(pCtx, &key)){
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(pCtx);
		throw std::runtime_error("Failed to generate key pair");
	}
	EVP_PKEY_CTX_free(pCtx);
}

inline void sig::generateSharedSecret(const sig &other, talk::bytes &out) const {
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, nullptr);
	if (!ctx){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to create key derivation ctx");
	}
	if (!EVP_PKEY_derive_init(ctx)){
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		throw std::runtime_error("Failed to initialize key derivation ctx");
	}
	if (!EVP_PKEY_derive_set_peer(ctx, other.key)){
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
	if (!EVP_PKEY_derive(ctx, out.data(), &len)){
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		throw std::runtime_error("Failed to derive shared secret");
	}
	EVP_PKEY_CTX_free(ctx);
}

inline sig::sig(const int &type, const char *digest_name) : key(EVP_PKEY_new()), type(type) {
	if (!digest_name){
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

inline sig::~sig() {
	EVP_PKEY_free(key);
	EVP_MD_free(digest_type);
}

// Instantiating the classes

// inheriting from sig
struct ed448::crypt_context : public sig{
	// Inheriting the constructor
	using sig::sig;
};

struct ed25519::crypt_context : public sig{
	// Inheriting the constructor
	using sig::sig;
};


void ed448::signIn(const bytes& data, bytes& out) const {
	ctx->sign(data, out);
}

bool ed448::verify(const bytes& data, const bytes& signature) const {
	return ctx->verify(data, signature);
}

void ed448::generateKeyPair() {
	ctx->generateKeyPair();
}

void ed448::generateSharedSecretIn(const signature& other, bytes& out) const {
	if (type != other.getType()){
		throw std::domain_error("Different crypto types");
	}

	const auto& other_448 = dynamic_cast<const ed448&>(other);

	ctx->generateSharedSecret(*other_448.ctx, out);
}

std::string ed448::exportPublicKey() const {
	return ctx->exportPublicKey();
}

std::string ed448::exportPrivateKey() const {
	return ctx->exportPrivateKey();
}

void ed25519::signIn(const bytes& data, bytes& out) const {
	ctx->sign(data, out);
}

bool ed25519::verify(const bytes& data, const bytes& signature) const {
	return ctx->verify(data, signature);
}

void ed25519::generateKeyPair() {
	ctx->generateKeyPair();
}

void ed25519::generateSharedSecretIn(const signature& other, bytes& out) const {
	if (type != other.getType()){
		throw std::domain_error("Different crypto types");
	}

	const auto& other_25519 = dynamic_cast<const ed25519&>(other);

	ctx->generateSharedSecret(*other_25519.ctx, out);
}

std::string ed25519::exportPublicKey() const {
	return ctx->exportPublicKey();
}

std::string ed25519::exportPrivateKey() const {
	return ctx->exportPrivateKey();
}


ed25519::~ed25519() = default;
ed448::~ed448() = default;

ed448::ed448() {
	ctx = std::make_unique<crypt_context>(EVP_PKEY_ED448, "shake256");
}

ed25519::ed25519() {
	ctx = std::make_unique<crypt_context>(EVP_PKEY_ED25519, "sha512");
}

