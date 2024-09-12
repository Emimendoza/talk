#include <crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>

using namespace talk::crypto;
using talk::bytes, talk::byteArr;

namespace {
	struct hash_ctx{
		EVP_MD_CTX *ctx;
		EVP_MD *type;
		bool is_finalized = false;
		size_t size;

		explicit inline hash_ctx(const char *type_name);
		inline ~hash_ctx();

		inline void digestUpdate(const bytes &data) const;
		inline void digestFinal(bytes& out);

		template<size_t N>
		inline void digestFinal(byteArr<N>& out);

		inline void digestReset();
	};
}


// Crypt ctx

inline hash_ctx::hash_ctx(const char *type_name) : ctx(EVP_MD_CTX_new()) {
	if (!ctx){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to allocate memory for ctx");
	}
	type = EVP_MD_fetch(nullptr, type_name, nullptr);
	if (!type){
		EVP_MD_CTX_free(ctx);
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to fetch digest type");
	}

	if (!EVP_DigestInit_ex(ctx,  type, nullptr)){
		EVP_MD_CTX_free(ctx);
		EVP_MD_free(type);
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to initialize ctx");
	}
	size = EVP_MD_size(type);
}

inline hash_ctx::~hash_ctx() {
	EVP_MD_CTX_free(ctx);
	EVP_MD_free(type);
}

inline void hash_ctx::digestUpdate(const bytes &data) const {
	if (is_finalized){
		throw std::domain_error("Context is finalized");
	}
	if (!EVP_DigestUpdate(ctx, data.data(), data.size())){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to update ctx");
	}
}

inline void hash_ctx::digestFinal(bytes& out) {
	out.resize(size);
	if (!EVP_DigestFinal_ex(ctx, out.data(), nullptr)){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to finalize ctx");
	}
	is_finalized = true;
}

template<size_t N>
inline void hash_ctx::digestFinal(byteArr<N> &out) {
	if (!EVP_DigestFinal_ex(ctx, out.data(), nullptr)){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to finalize ctx");
	}
	is_finalized = true;
}

inline void hash_ctx::digestReset() {
	if (!EVP_DigestInit_ex2(ctx, type, nullptr)){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to reset ctx");
	}
	is_finalized = false;
}

// Instances

struct sha256::crypt_context : public hash_ctx{
	using hash_ctx::hash_ctx;
};

struct sha512::crypt_context : public hash_ctx{
	using hash_ctx::hash_ctx;
};

struct shake256::crypt_context : public hash_ctx{
	using hash_ctx::hash_ctx;
};

struct blake2b::crypt_context : public hash_ctx{
	using hash_ctx::hash_ctx;
};

sha256::sha256() {
	ctx = std::make_unique<crypt_context>("sha256");
}

sha512::sha512() {
	ctx = std::make_unique<crypt_context>("sha512");
}

shake256::shake256() {
	ctx = std::make_unique<crypt_context>("shake256");
}

blake2b::blake2b() {
	ctx = std::make_unique<crypt_context>("blake2b");
}

sha256::~sha256() = default;
sha512::~sha512() = default;
shake256::~shake256() = default;
blake2b::~blake2b() = default;

void sha256::digestUpdate(const bytes &data) {
	ctx->digestUpdate(data);
}

void sha256::digestFinalIn(bytes &out) {
	ctx->digestFinal(out);
}

void sha256::digestFinalArrIn(byteArr<32> &out) {
	ctx->digestFinal(out);
}

void sha256::digestReset() {
	ctx->digestReset();
}

void sha512::digestUpdate(const bytes &data) {
	ctx->digestUpdate(data);
}

void sha512::digestFinalIn(bytes &out) {
	ctx->digestFinal(out);
}

void sha512::digestFinalArrIn(byteArr<64> &out) {
	ctx->digestFinal(out);
}

void sha512::digestReset() {
	ctx->digestReset();
}

void shake256::digestUpdate(const bytes &data) {
	ctx->digestUpdate(data);
}

void shake256::digestFinalIn(bytes &out) {
	ctx->digestFinal(out);
}

void shake256::digestFinalArrIn(byteArr<32> &out) {
	ctx->digestFinal(out);
}

void shake256::digestReset() {
	ctx->digestReset();
}

void blake2b::digestUpdate(const bytes &data) {
	ctx->digestUpdate(data);
}

void blake2b::digestFinalIn(bytes &out) {
	ctx->digestFinal(out);
}

void blake2b::digestFinalArrIn(byteArr<64> &out) {
	ctx->digestFinal(out);
}

void blake2b::digestReset() {
	ctx->digestReset();
}
