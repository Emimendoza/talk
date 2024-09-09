#include <crypto/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

using namespace talk::crypto;

argon2d::argon2d(uint32_t threads, uint32_t lanes, uint32_t memory) {
	auto vals = new uint32_t[3];
	vals[0] = threads;
	vals[1] = lanes;
	vals[2] = memory;

	const auto params = {
			OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &vals[0]),
			OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &vals[1]),
			OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &vals[2]),
	};
	context = new crypt_context("ARGON2D", params);
	context->values = vals;
}

hkdf::hkdf() {
	context = new crypt_context("HKDF", {});
}



