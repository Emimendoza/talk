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
	template <typename T>
	class poolHandle{
	protected:
		static void step(void* data);
		queue<std::packaged_task<T()>> tasks;
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
		inline void push(T t);
		inline void pushMov(T&& t);
		// Blocking
		inline T pop();
		inline T popMov();
		// Blocking with timeout
		inline bool pop(std::chrono::milliseconds timeout, T& out);

		// Non-blocking
		inline bool TryPop(T& out);

		// Non-blocking
		inline bool empty();
		inline size_t size();

		// Blocking until empty
		inline void empty_block();
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
	class poolHandle<T(Args...)> : public internal::poolHandle<T>{
	public:
		typedef std::tuple<Args...> argPack;
	private:
		static T call(const std::function<T(Args...)>& f, argPack& args){
			return std::apply(f, args);
		}
	public:
		// Inherit constructors
		using internal::poolHandle<T>::poolHandle;


		inline std::future<T> async(const std::function<T(Args...)> &f, argPack &args);
		inline std::vector<std::future<T>> async(const std::function<T(Args...)> &f, std::vector<argPack> &args);
		inline void async(const std::function<T(Args...)> &f, std::vector<argPack> &args, std::vector<std::future<T>>& futures);
	};

	template <typename T>
	class poolHandle<T(void)> : public internal::poolHandle<T>{
	public:
		// Inherit constructors
		using internal::poolHandle<T>::poolHandle;

		inline std::future<T> async(const std::function<T(void)> &f);
		inline std::vector<std::future<T>> async(const std::function<T(void)> &f, size_t count);
		inline void async(const std::function<T(void)> &f, size_t count, std::vector<std::future<T>>& futures);
	};
}

#include "internal/parallel.h"
#endif //TALK_PARALLEL_H
