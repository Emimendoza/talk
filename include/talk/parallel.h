#ifndef TALK_PARALLEL_H
#define TALK_PARALLEL_H
#include <future>
#include <queue>
#include <unordered_set>

namespace talk{
	class pool;
	template <typename T>
	class queue;
}

namespace talk::internal{
	template <typename Signature>
	class poolHandle{
	protected:
		static void step(void* data);
		queue<std::packaged_task<Signature>> tasks;
		std::shared_ptr<pool> p;
	public:
		poolHandle() = delete;
		inline ~poolHandle();
		inline explicit poolHandle(const std::shared_ptr<pool>& p);
	};
}

namespace talk{
	template <typename T>
	class queue{
	private:
		std::recursive_mutex mutex;
		std::condition_variable_any cv;
		std::condition_variable_any cv_empty;
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
		// Returns false if pool is not accepting new tasks (stopped or stopping)
		bool queue(const std::function<void(void*)>& f, void* data);
		pool() = delete;
		explicit pool(size_t threads);
		~pool();

		[[nodiscard]] const std::unordered_set<std::thread::id>& getThreadIds() const;
	};

	template <typename Signature>
	class poolHandle;

	template <typename T, typename... Args>
	class poolHandle<T(Args...)> : public internal::poolHandle<T(Args...)>{
	public:
		// Inherit constructors
		using internal::poolHandle<T(Args...)>::poolHandle;

		inline std::future<T> async(std::function<T(Args...)> f, Args... args);
		inline std::vector<std::future<T>> async(std::function<T(Args...)> f, std::vector<Args...> args);
	};

	template <typename T>
	class poolHandle<T(void)> : public internal::poolHandle<T(void)>{
	public:
		// Inherit constructors
		using internal::poolHandle<T(void)>::poolHandle;

		inline std::future<T> async(std::function<T(void)> f);
		inline std::vector<std::future<T>> async(std::function<T(void)> f, size_t count);
	};
}

#include "internal/parallel.h"
#endif //TALK_PARALLEL_H
