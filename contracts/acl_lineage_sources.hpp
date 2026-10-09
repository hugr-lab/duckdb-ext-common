//===----------------------------------------------------------------------===//
// acl_lineage_sources.hpp — who names a source in lineage (spec 015, duckdb-acl spec 112 §9)
//
// duckdb-acl names the datasets of an attached catalog in its lineage events. By itself it knows
// only the ATTACH alias (`<ns>/source/<alias>` + `<schema>.<table>`). Everyone else names the same
// table by its real address, OpenLineage's naming spec (`postgres://pg.prod:5432` +
// `sales.public.orders`), so the graphs do not join. The extension that owns a source knows its real
// name: hugr_node holds the platform's source registry and, for a federated platform (type `hugr`),
// the remote cluster's namespace. Through this registry it answers acl:
//
//   provider side (hugr_node, at load):
//     string why;
//     auto sources = AclLineageSources::Reach(db.GetObjectCache(), why);
//     if (sources) { sources->AddProvider(my_provider); }
//
//   acl side, naming a physical dataset on its lineage worker:
//     LineageSourceName name;
//     if (sources->Name({"pg", catalog.GetCatalogType(), "public", "orders"}, name)) { ... name.ns, name.name ... }
//
// The first provider that knows the source answers. acl then falls back to an identity the operator
// declared, and last to the alias form. Header-only, reached by name and stamped (charter R1-R3):
// the registry carries MAGIC ("ACLS") and VERSION as its first members, and only Reach() hands it
// out. Bump the version on any change to what this header lays out. Owned by duckdb-acl (R6).
//
// An answer is a name, never a credential: a provider must not put userinfo into it, and acl
// refuses one that does. A provider is called on acl's lineage worker, off every query's path, but
// must answer from what it already holds (no I/O). A provider that throws counts as "no answer".
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/shared_ptr.hpp"
#include "duckdb/common/string.hpp"
#include "duckdb/common/vector.hpp"
#include "duckdb/storage/object_cache.hpp"

#include <atomic>
#include <cstdint>
#include <mutex>

namespace duckdb {
namespace acl {

//! What acl asks about: a dataset of an attached catalog. An empty schema and name ask about the
//! catalog itself (a source's NAMESPACE event).
struct LineageSourceDataset {
	string catalog;      // the attached catalog's name (its ATTACH alias)
	string catalog_type; // its type, as `Catalog::GetCatalogType()` answers it (duckdb, hugr, a scanner's)
	string schema;       // the dataset's schema inside the catalog, or empty
	string name;         // the dataset's name inside the schema, or empty
};

//! The answer: the dataset's OpenLineage namespace and name (for a catalog question, the name may
//! be empty). Never userinfo or any credential.
struct LineageSourceName {
	string ns;
	string name;
};

//! What a provider implements. Called on acl's lineage worker; answers from memory, never blocks.
class LineageSourceProvider {
public:
	virtual ~LineageSourceProvider() = default;
	//! true with `out` filled when this provider owns the source; false to let the next one answer
	virtual bool Name(const LineageSourceDataset &dataset, LineageSourceName &out) = 0;
};

//! The registry, one per DatabaseInstance in its ObjectCache under ObjectType().
class AclLineageSources : public ObjectCacheEntry {
public:
	static constexpr int32_t CONTRACT_MAGIC = 0x41434C53; // "ACLS"
	static constexpr int32_t CONTRACT_VERSION = 1;        // 1: spec 015
	int32_t contract_magic = CONTRACT_MAGIC;
	int32_t contract_version = CONTRACT_VERSION;

	static string ObjectType() {
		return "acl_lineage_sources";
	}
	string GetObjectType() override {
		return ObjectType();
	}
	//! Never evicted: a provider registration must outlive cache pressure.
	optional_idx GetEstimatedCacheMemory() const override {
		return optional_idx();
	}

	//! The registry of an instance, from either side in either load order - created here when absent,
	//! and checked: null with `why` when the object under the key is stamped with another magic or
	//! version (built from another revision of this header) or is not this registry. Must not be used.
	static shared_ptr<AclLineageSources> Reach(ObjectCache &cache, string &why) {
		auto sources = cache.GetOrCreate<AclLineageSources>(ObjectType());
		if (!sources) {
			why = "the object cache holds something else under '" + ObjectType() + "'";
			return nullptr;
		}
		if (sources->contract_magic != CONTRACT_MAGIC || sources->contract_version != CONTRACT_VERSION) {
			why = "the lineage source registry is stamped with another acl_lineage_sources contract (" +
			      std::to_string(sources->contract_version) + "); this build speaks " +
			      std::to_string(CONTRACT_VERSION);
			return nullptr;
		}
		why.clear();
		return sources;
	}

	void AddProvider(shared_ptr<LineageSourceProvider> provider) {
		std::lock_guard<std::mutex> guard(lock);
		providers.push_back(std::move(provider));
	}
	void RemoveProvider(const shared_ptr<LineageSourceProvider> &provider) {
		std::lock_guard<std::mutex> guard(lock);
		for (auto it = providers.begin(); it != providers.end(); ++it) {
			if (*it == provider) {
				providers.erase(it);
				return;
			}
		}
	}

	//! Ask the providers in registration order; the first answer wins. A provider that throws counts
	//! as no answer (and in `failures`). Called outside the registry's lock, on a copy of the list:
	//! a provider may be removed while acl asks.
	bool Name(const LineageSourceDataset &dataset, LineageSourceName &out) {
		vector<shared_ptr<LineageSourceProvider>> current;
		{
			std::lock_guard<std::mutex> guard(lock);
			current = providers;
		}
		for (auto &provider : current) {
			try {
				LineageSourceName answer;
				if (provider && provider->Name(dataset, answer) && !answer.ns.empty()) {
					out = std::move(answer);
					return true;
				}
			} catch (...) {
				failures++;
			}
		}
		return false;
	}

	//! How many provider calls threw (acl reports it as a gauge)
	std::atomic<int64_t> failures {0};

private:
	std::mutex lock;
	vector<shared_ptr<LineageSourceProvider>> providers;
};

} // namespace acl
} // namespace duckdb
