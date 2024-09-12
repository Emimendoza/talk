#include <crypto.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <cstring>
#include <argon2.h>
#include <openssl/err.h>

using namespace talk::crypto;
using talk::bytes;

// see sig.cpp for the rationale of this
namespace{
	const OSSL_PARAM OSSL_END = OSSL_PARAM_construct_end();
	template<size_t N>
	struct kdf_ctx{
		EVP_KDF *kdf;
		EVP_KDF_CTX *ctx;
		std::array<OSSL_PARAM ,N+3> params{};
		std::array<uint32_t, N> values;
		size_t outLen{};

		inline kdf_ctx(const char* kdf_name, const std::array<const char*, N>& keys, const std::array<uint32_t, N>& vals);
		inline ~kdf_ctx();

		inline void deriveKey(const bytes &salt, const bytes &password, bytes &out);
	};
}

template<size_t N>
inline kdf_ctx<N>::kdf_ctx(const char* kdf_name, const std::array<const char*, N>& keys,
						   const std::array<uint32_t, N>& vals) : values(vals) {
	kdf = EVP_KDF_fetch(nullptr, kdf_name, nullptr);
	if (!kdf) {
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to fetch kdf");
	}
	ctx = EVP_KDF_CTX_new(kdf);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to create kdf ctx");
	}
	for (size_t i = 0; i < N; i++) {
		params[i] = OSSL_PARAM_construct_uint32(keys[i], &values[i]);
	}
}

template<size_t N>
inline kdf_ctx<N>::~kdf_ctx() {
	EVP_KDF_CTX_free(ctx);
	EVP_KDF_free(kdf);
}

template<size_t N>
inline void kdf_ctx<N>::deriveKey(const bytes &salt, const bytes &password, bytes &out) {
	size_t i = N;
	if (!salt.empty()){
		params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *) salt.data(),
																salt.size());
	}
	params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *) password.data(),
															password.size());
	params[i] = OSSL_END;

	out.resize(outLen);
	auto ret = EVP_KDF_derive(ctx, out.data(), out.size(), params.data());

	//EVP_KDF_CTX_reset(ctx);

	if(ret != 1){
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to derive key");
	}
}

// Instantiate the classes

// constants
namespace {
	// hkdf
	constexpr size_t HKDF_PARAMS = 0;
	constexpr std::array<const char*, HKDF_PARAMS> HKDF_PARAMS_STR = {};
}

struct hkdf::crypt_context : public kdf_ctx<HKDF_PARAMS>{
	// Inheriting the constructor
	using kdf_ctx::kdf_ctx;
};

hkdf::hkdf(size_t out_len) {
	constexpr std::array<uint32_t, HKDF_PARAMS>vals = {};
	ctx = std::make_unique<crypt_context>("HKDF", HKDF_PARAMS_STR, vals);
	ctx->outLen = out_len;
}

size_t hkdf::outLen() const {
	return ctx->outLen;
}

hkdf::~hkdf() = default;

void hkdf::deriveKeyIn(const bytes &salt, const bytes &password, bytes &out) {
	ctx->deriveKey(salt, password, out);
}

#ifndef TALK_BUILTIN_ARGON2
namespace {
	// argon2d
	constexpr uint32_t ARGON2_VERSION = 0x13;
	constexpr size_t ARGON2_PARAMS = 5;
	constexpr std::array<const char*, ARGON2_PARAMS> ARGON2_PARAMS_STR = {
			OSSL_KDF_PARAM_ARGON2_VERSION,
			OSSL_KDF_PARAM_THREADS,
			OSSL_KDF_PARAM_ARGON2_LANES,
			OSSL_KDF_PARAM_ARGON2_MEMCOST,
			OSSL_KDF_PARAM_ITER
	};
}

struct argon2d::crypt_context : public kdf_ctx<ARGON2_PARAMS>{
	// Inheriting the constructor
	using kdf_ctx::kdf_ctx;
};

argon2d::argon2d(uint32_t lanes, uint32_t memory, uint32_t iterations, uint32_t out_size) {
	const std::array<uint32_t, ARGON2_PARAMS>vals = {
			ARGON2_VERSION,
			OSSL_get_max_threads(nullptr),
			lanes,
			memory,
			iterations
	};
	ctx = std::make_unique<crypt_context>("ARGON2D", ARGON2_PARAMS_STR, vals);
	ctx->outLen = out_size;
}

size_t argon2d::outLen() const {
	return ctx->outLen;
}

void argon2d::deriveKeyIn(const bytes &salt, const bytes &password, bytes &out) {
	ctx->deriveKey(salt, password, out);
}

argon2d::~argon2d() = default;
#endif
