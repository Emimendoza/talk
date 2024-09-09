#include <crypto.h>
#include <cstdlib>
#include <sys/random.h>
#include <mutex>

using namespace talk::crypto;

namespace {
	std::mutex randMutex;
	sRand _seedingRand{};
	talk::crypto::rand& seedingRand = _seedingRand;
}

class rand::crypt_context{
public:
	random_data* rand_state{};
	std::array<char, 256> buf{};
	size_t buf_pos{};
	~crypt_context(){
		delete rand_state;
	}
};

rand::~rand(){
	delete context;
}

sRand::sRand() {
	context = new crypt_context;
	auto ret = getrandom(context->buf.data(), context->buf.size(), 0);
	if (ret != context->buf.size()) {
		throw std::runtime_error("Failed to get random data");
	}
}

fRand::fRand(uint32_t seed){
	context = new crypt_context;
	context->rand_state = new random_data;
	initstate_r(seed, context->buf.data(), context->buf.size(), context->rand_state);
}

fRand::fRand() {
	context = new crypt_context;
	context->rand_state = new random_data;
	std::lock_guard<std::mutex> lock(randMutex);
	auto seedB = seedingRand.random(4).toArray<4>();
	auto seed = deserialize<uint32_t>(seedB);
	initstate_r(seed, context->buf.data(), context->buf.size(), context->rand_state);
}

void fRand::random(size_t len, talk::bytes &out) {
	out.resize(len);
	int32_t result;
	for (size_t i = 0; i < len; i += sizeof (result)) {
		random_r(context->rand_state, &result);
		memcpy(out.data() + i, &result, std::min(len - i, sizeof(result)));
	}
}

void sRand::random(size_t len, talk::bytes &out) {
	out.resize(len);
	if (len <= context->buf.size() - context->buf_pos) {
		memcpy(out.data(), context->buf.data() + context->buf_pos, len);
		context->buf_pos += len;
		return;
	}

	while (len > 0) {
		size_t to_copy = std::min(len, context->buf.size() - context->buf_pos);
		memcpy(out.data() + out.size() - len, context->buf.data() + context->buf_pos, to_copy);
		len -= to_copy;
		context->buf_pos = 0;
		auto ret = getrandom(context->buf.data(), context->buf.size(), 0);
		if (ret != context->buf.size()) {
			throw std::runtime_error("Failed to get random data");
		}
	}
}