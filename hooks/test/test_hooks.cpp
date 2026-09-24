// The delivery base of hooks/ (spec 008): order, the bounded queue's drops, a failing sink isolated, Stop
// delivering what is queued. Header-only pieces only - no duckdb library to link.
#include "ext_hooks.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>

// the two out-of-line helpers duckdb's containers call on misuse: defined here, as this test links no duckdb
namespace duckdb {
void ThrowVectorIndexOutOfBounds(idx_t index, idx_t size) {
	std::abort();
}
void ThrowNullSharedPtrDereference() {
	std::abort();
}
} // namespace duckdb

using namespace duckdb;
using namespace duckdb::ext_common;

static int failures = 0;
static void Check(bool ok, const char *what) {
	std::printf("  %s: %s\n", ok ? "ok" : "FAIL", what);
	failures += ok ? 0 : 1;
}

struct Event {
	int64_t seq = 0;
};

struct Recorder : Sink<Event> {
	std::mutex lock;
	vector<int64_t> seen;
	std::atomic<bool> hold {false};
	std::atomic<int> flushed {0};
	void OnEvent(const Event &event) override {
		while (hold) {
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
		std::lock_guard<std::mutex> guard(lock);
		seen.push_back(event.seq);
	}
	void Flush() override {
		flushed++;
	}
};

struct Thrower : Sink<Event> {
	void OnEvent(const Event &) override {
		throw std::runtime_error("a failing sink");
	}
};

int main() {
	auto recorder = make_shared_ptr<Recorder>();
	auto thrower = make_shared_ptr<Thrower>();
	Counters counters;
	{
		recorder->hold = true;
		Delivery<Event> delivery(
		    4,
		    [&]() {
			    return vector<shared_ptr<Sink<Event>>> {thrower, recorder};
		    },
		    [&](const string &what) {
			    counters.Add("delivery", {{"what", what}});
		    });
		int accepted = 0;
		for (int64_t i = 1; i <= 20; i++) {
			accepted += delivery.Push(Event {i}) ? 1 : 0;
		}
		Check(accepted < 20 && counters.Get("delivery", {{"what", "dropped"}}) == 20 - accepted,
		      "a full queue drops, and counts what it dropped");
		recorder->hold = false;
		delivery.Stop();
		Check(!delivery.Push(Event {99}), "nothing is accepted after Stop");
	}
	{
		std::lock_guard<std::mutex> guard(recorder->lock);
		bool ordered = true;
		for (size_t i = 1; i < recorder->seen.size(); i++) {
			ordered = ordered && recorder->seen[i - 1] < recorder->seen[i];
		}
		Check(!recorder->seen.empty() && ordered, "delivered in order, what was queued before Stop included");
	}
	Check(counters.Get("delivery", {{"what", "sink_failed"}}) > 0,
	      "a failing sink is counted, the others still served");
	Check(recorder->flushed >= 1, "Stop flushes the sinks");
	Gauges gauges;
	int64_t state = 7;
	gauges.Register("g", {{"a", "b"}}, "1", "a gauge", [&]() { return state; });
	Check(gauges.Snapshot().size() == 1 && gauges.Snapshot()[0].value == 7, "a gauge reads its owner's state");
	gauges.Remove("g");
	Check(gauges.Snapshot().empty(), "a removed gauge is gone");
	std::printf("%s test_hooks\n", failures ? "FAIL" : "PASS");
	return failures ? 1 : 0;
}
