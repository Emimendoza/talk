#include <crypto.h>
#include <cstdlib>
#include <sys/random.h>
#include <mutex>

using namespace talk::crypto;

namespace {
	std::mutex randMutex;
	sRand _seedingRand{};
	talk::crypto::rand& seedingRand = _seedingRand;

	struct sRand_ctx{
		std::array<char, 256> buf{};
		size_t buf_pos{};
	};

	struct fRand_ctx{
		random_data rand_state{};
		std::array<char, 256> buf{};
		size_t buf_pos{};
	};
}

struct sRand::crypt_context : public sRand_ctx{};
struct fRand::crypt_context : public fRand_ctx{};

sRand::~sRand() = default;
fRand::~fRand() = default;

sRand::sRand() {
	ctx = std::make_unique<crypt_context>();
	auto ret = getrandom(ctx->buf.data(), ctx->buf.size(), 0);
	if (ret != ctx->buf.size()) {
		throw std::runtime_error("Failed to get randomIn data");
	}
}

fRand::fRand(uint32_t seed){
	ctx = std::make_unique<crypt_context>();
	initstate_r(seed, ctx->buf.data(), ctx->buf.size(), &ctx->rand_state);
}

fRand::fRand() {
	ctx = std::make_unique<crypt_context>();
	std::lock_guard<std::mutex> lock(randMutex);
	auto seedB = seedingRand.random<4>();
	auto seed = deserialize<uint32_t>(seedB);
	initstate_r(seed, ctx->buf.data(), ctx->buf.size(), &ctx->rand_state);
}

void fRand::randomIn(size_t len, bytes &out) {
	out.resize(len);
	int32_t result;
	for (size_t i = 0; i < len; i += sizeof (result)) {
		random_r(&ctx->rand_state, &result);
		memcpy(out.data() + i, &result, std::min(len - i, sizeof(result)));
	}
}

void sRand::randomIn(size_t len, bytes &out) {
	out.resize(len);
	if (len <= ctx->buf.size() - ctx->buf_pos) {
		memcpy(out.data(), ctx->buf.data() + ctx->buf_pos, len);
		ctx->buf_pos += len;
		return;
	}

	while (len > 0) {
		size_t to_copy = std::min(len, ctx->buf.size() - ctx->buf_pos);
		memcpy(out.data() + out.size() - len, ctx->buf.data() + ctx->buf_pos, to_copy);
		len -= to_copy;
		ctx->buf_pos = 0;
		auto ret = getrandom(ctx->buf.data(), ctx->buf.size(), 0);
		if (ret != ctx->buf.size()) {
			throw std::runtime_error("Failed to get randomIn data");
		}
	}
}