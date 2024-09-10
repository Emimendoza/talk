#ifndef TALK_PRIVATE_THREADS_H
#define TALK_PRIVATE_THREADS_H
#include <mutex>
#include <vector>

namespace talk::internal{
	class threads{
	protected:
		static std::mutex& getMutex();
		static std::vector<threads*>& getThreads();
	public:
		static void SMT(size_t threads);
		virtual void setMaxThreads(size_t threads) = 0;
		virtual size_t getMaxThreads();
	};
}

#endif //TALK_INTERNAL_CRYPTO_H
