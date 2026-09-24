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

struct StopsItself : Sink<Event> {
	Delivery<Event> *delivery = nullptr;
	std::atomic<int> seen {0};
	void OnEvent(const Event &) override {
		seen++;
		delivery->Stop(); // on the delivery thread: must not join itself (or terminate)
	}
};

int main() {
	auto recorder = make_shared_ptr<Recorder>();
	auto thrower = make_shared_ptr<Thrower>();
	Counters counters;
	int accepted = 0;
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
		for (int64_t i = 1; i <= 20; i++) {
			accepted += delivery.Push(Event {i}) ? 1 : 0;
		}
		Check(accepted < 20 && counters.Get("delivery", {{"what", "dropped"}}) == 20 - accepted,
		      "a full queue drops, and counts what it dropped");
		recorder->hold = false;
		delivery.Stop();
		Check(!delivery.Push(Event {99}), "nothing is accepted after Stop");
		Check(counters.Get("delivery", {{"what", "dropped"}}) == 21 - accepted, "a push after Stop is counted");
	}
	{
		std::lock_guard<std::mutex> guard(recorder->lock);
		bool ordered = true;
		for (size_t i = 1; i < recorder->seen.size(); i++) {
			ordered = ordered && recorder->seen[i - 1] < recorder->seen[i];
		}
		Check(int(recorder->seen.size()) == accepted && ordered,
		      "every accepted event delivered, in order - what was queued at Stop included");
	}
	Check(counters.Get("delivery", {{"what", "sink_failed"}}) == accepted,
	      "a failing sink is counted per event, the others still served");
	Check(recorder->flushed == 1, "Stop flushes the sinks, once");
	{
		auto self = make_shared_ptr<StopsItself>();
		{
			Delivery<Event> delivery(
			    8, [&]() { return vector<shared_ptr<Sink<Event>>> {self}; }, nullptr);
			self->delivery = &delivery;
			delivery.Push(Event {1});
			while (self->seen == 0) {
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
			}
		}
		Check(self->seen == 1, "Stop from a sink, on the delivery thread, neither joins itself nor terminates");
	}
	{
		// a null sinks function and a throwing one are survived
		Delivery<Event> none(2, nullptr, nullptr);
		none.Push(Event {1});
		Delivery<Event> throwing(
		    2, []() -> vector<shared_ptr<Sink<Event>>> { throw std::runtime_error("no sinks"); }, nullptr);
		throwing.Push(Event {1});
		Check(true, "a missing or throwing sinks function does not end the process");
	}
	Counters keys;
	keys.Add("c", {{"a", "b=c"}});
	keys.Add("c", {{"a=b", "c"}});
	Check(keys.Get("c", {{"a", "b=c"}}) == 1 && keys.Get("c", {{"a=b", "c"}}) == 1,
	      "attribute tuples that print alike are distinct counters");
	Gauges gauges;
	int64_t state = 7;
	gauges.Register("g", {{"service", "corp"}}, "1", "a gauge", [&]() { return state; });
	gauges.Register("g", {{"service", "dev"}}, "1", "a gauge", [&]() { return state + 1; });
	gauges.Register("g", {{"service", "corp"}}, "1", "a gauge", [&]() { return state; }); // again: replaced
	Check(gauges.Snapshot().size() == 2 && gauges.Snapshot()[0].value == 7,
	      "a gauge reads its owner's state; registering again replaces");
	gauges.Remove("g", {{"service", "corp"}});
	auto left = gauges.Snapshot();
	Check(left.size() == 1 && left[0].value == 8, "a removed gauge is gone, the same name's others stay");
	gauges.Register("t", {}, "1", "throws", []() -> int64_t { throw std::runtime_error("x"); });
	Check(gauges.Snapshot().size() == 1, "a throwing reader is left out of the snapshot");
	std::printf("%s test_hooks\n", failures ? "FAIL" : "PASS");
	return failures ? 1 : 0;
}
