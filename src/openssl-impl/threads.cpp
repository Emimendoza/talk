#include <crypto.h>
#include <talk-private/threads.h>
#include <openssl/thread.h>
#include <mutex>

using namespace talk;
using namespace talk::internal;

namespace talk::internal{
	class openssl_threads final : public threads{
	private:
		std::mutex mutex{};
	public:
		void setMaxThreads(size_t threads) override{
			std::lock_guard<std::mutex> lock(mutex);
			OSSL_set_max_threads(nullptr, threads);
		}
		size_t getMaxThreads() override{
			std::lock_guard<std::mutex> lock(mutex);
			return OSSL_get_max_threads(nullptr);
		}
	};
	openssl_threads _ot{};
}