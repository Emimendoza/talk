#include <crypto.h>
#include <openssl/thread.h>
#include <mutex>
#include <atomic>

using namespace talk;

static std::atomic<size_t> max_threads;
static std::mutex max_threads_mutex;

void crypto::setMaxThreads(size_t threads) {
	std::lock_guard<std::mutex> lock(max_threads_mutex);
	OSSL_set_max_threads(nullptr, threads);
	max_threads = OSSL_get_max_threads(nullptr);
}

size_t crypto::getMaxThreads() {
	return max_threads;
}
