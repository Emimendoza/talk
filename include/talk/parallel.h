#ifndef TALK_PARALLEL_H
#define TALK_PARALLEL_H
#include <future>
#include <queue>
namespace talk{
	template <typename T>
	class queue{
	private:
		std::recursive_mutex mutex;
		std::condition_variable cv;
		std::condition_variable cv_empty;
		std::queue<T> queue;
	public:
		// Non-blocking
		void push(T t);
		// Blocking
		T pop();
		// Blocking with timeout
		bool pop(std::chrono::milliseconds timeout, T& out);

		// Non-blocking
		bool TryPop(T& out);

		// Non-blocking
		bool empty();
		size_t size();

		// Blocking until empty
		void empty_block();
	};

	class pool{
	private:
		struct impl;
		std::unique_ptr<impl> pimpl;
	public:
		void queue(std::function<void(void*)> f);
		pool(size_t threads);
		~pool();
	};

	template <typename T, typename... Args>
	class poolHandle{
	private:
		static void step(void* data);
		queue<std::packaged_task<T(Args...)>> tasks;
		std::shared_ptr<pool> p;
	public:
		poolHandle() = delete;
		inline explicit poolHandle(const std::shared_ptr<pool>& p);

		inline std::future<T> async(std::function<T(Args...)> f, Args... args);

		inline std::vector<std::future<T>> async(std::function<T(Args...)> f, std::vector<Args...> args);

		inline ~poolHandle();
	};
	
	extern std::shared_ptr<pool> defaultPool;
}

#include "internal/parallel.h"
#endif //TALK_PARALLEL_H
