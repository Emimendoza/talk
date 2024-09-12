#ifdef TALK_BUILTIN_ARGON2
#include <crypto.h>
#include <parallel.h>
#include "internal/crypto.h"

// argon2d 1.3.0

using namespace talk::crypto;
using namespace talk;
using talk::bytes;

namespace{
	constexpr byteArr<4> ZEROS = {0, 0, 0, 0};
	constexpr byteArr<4> ONES = {0xff, 0xff, 0xff, 0xff};
	constexpr byteArr<4> VERSION_LE = serializeLE(0x13);

	struct argon2_ctx{
		poolHandle<void()> workers;
		blake2b blake2b_ctx;
		const byteArr<40> H0_in_init;
		bytes H0_IN;
		uint32_t lanes{};
		uint32_t memory{};
		uint32_t columns{};
		uint32_t iterations{};
		uint32_t outLen{};
		std::unique_ptr<std::unique_ptr<byte[]>[]> memoryBlocks;
		byteArr<64> H0{};
		explicit argon2_ctx(const byteArr<40>& H0_init);
	};
}

argon2_ctx::argon2_ctx(const byteArr<40>& H0_init) : workers(cryptoPool), H0_in_init(H0_init){}

struct argon2d::crypt_context : public argon2_ctx{
public:
	using argon2_ctx::argon2_ctx;
};

size_t argon2d::outLen() const {
	return ctx->outLen;
}

argon2d::~argon2d() = default;
argon2d::argon2d(uint32_t lanes, uint32_t memory, uint32_t iterations, uint32_t out_size) {
	byteArr<40> H0_init{};
	auto lanesLE = serializeLE(lanes);
	auto memoryLE = serializeLE(memory);
	auto iterationsLE = serializeLE(iterations);
	auto outLenLE = serializeLE(out_size);
	size_t i = 0;
	for(const auto& byte : lanesLE){
		H0_init[i++] = byte;
	}
	for(const auto& byte : outLenLE){
		H0_init[i++] = byte;
	}
	for(const auto& byte : memoryLE){
		H0_init[i++] = byte;
	}
	for(const auto& byte : iterationsLE){
		H0_init[i++] = byte;
	}
	for(const auto& byte : VERSION_LE){
		H0_init[i++] = byte;
	}
	// The type is argon2d which is 0x00
	for(const auto& byte : ZEROS){
		H0_init[i++] = byte;
	}


	ctx = std::make_unique<crypt_context>(H0_init);
	ctx->lanes = lanes;
	ctx->memory = memory;
	ctx->iterations = iterations;
	ctx->outLen = out_size;
	ctx->columns = (memory/(4*lanes))*4*1024;
	ctx->memoryBlocks = std::make_unique<std::unique_ptr<byte[]>[]>(lanes);
	for (i = 0; i < lanes; i++){
		ctx->memoryBlocks[i] = std::make_unique<byte[]>(ctx->columns);
	}
}

void argon2d::deriveKeyIn(const bytes &salt, const bytes &password, bytes &out) {
	ctx->H0_IN.clear();
	ctx->H0_IN += ctx->H0_in_init;
	ctx->H0_IN += serializeLE((uint32_t)password.size());
	ctx->H0_IN += password;
	ctx->H0_IN += serializeLE((uint32_t)salt.size());
	ctx->H0_IN += salt;
	ctx->H0_IN += ZEROS; //〈K〉
	// NOTHING (K)
	ctx->H0_IN += ZEROS; //〈X〉
	// NOTHING (X)
}


#endif //TALK_BUILTIN_ARGON2