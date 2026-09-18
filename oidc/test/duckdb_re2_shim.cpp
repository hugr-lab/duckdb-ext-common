// A test-only stand-in for duckdb's thin RegexMatch wrapper (src/common/re2_regex.cpp): the bundled
// httplib parses status lines and query strings through it, and the real one reaches into duckdb's
// exception machinery, which a duckdb-free test must not link. Same semantics over the same bundled
// re2, minus the throws; a consumer links duckdb's own. Identical on the v1.5.5 and 2.0 lines.
#include "duckdb/common/exception.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/re2_regex.hpp"

#include "re2/re2.h"

#include <cstdlib>

namespace duckdb {
[[noreturn]] void ThrowNullUniquePtrDereference() {
	std::abort();
}
[[noreturn]] void ThrowNullSharedPtrDereference() {
	std::abort();
}
[[noreturn]] void ThrowVectorIndexOutOfBounds(idx_t, idx_t) {
	std::abort();
}
// duckdb's checked vector (Match::groups) throws InternalException on a bad index, which the
// sanitizer builds keep as a real reference: the exception's shape, without its formatting
Exception::Exception(ExceptionType, const string &message) : std::runtime_error(message) {
}
InternalException::InternalException(const string &msg) : Exception(ExceptionType::INTERNAL, msg) {
}
string Exception::ConstructMessageRecursive(const string &msg, std::vector<ExceptionFormatValue> &) {
	return msg;
}
hugeint_t::hugeint_t(int64_t value) : lower(static_cast<uint64_t>(value)), upper(value < 0 ? -1 : 0) {
}
ExceptionFormatValue::ExceptionFormatValue(int64_t int_val_p)
    : type(ExceptionFormatValueType::FORMAT_VALUE_TYPE_INTEGER), int_val(int_val_p) {
}
ExceptionFormatValue::ExceptionFormatValue(idx_t uint_val)
    : type(ExceptionFormatValueType::FORMAT_VALUE_TYPE_INTEGER), int_val(static_cast<int64_t>(uint_val)) {
}
} // namespace duckdb

namespace duckdb_re2 {

Regex::Regex(const std::string &pattern, RegexOptions options) {
	RE2::Options o;
	o.set_case_sensitive(options == RegexOptions::CASE_INSENSITIVE);
	regex = duckdb::make_shared_ptr<duckdb_re2::RE2>(StringPiece(pattern), o);
}

static bool SearchInternal(const char *input_data, size_t input_size, Match &match, const RE2 &regex,
                           RE2::Anchor anchor) {
	std::vector<StringPiece> target_groups;
	auto group_count = static_cast<size_t>(regex.NumberOfCapturingGroups() + 1);
	target_groups.resize(group_count);
	match.groups.clear();
	if (!regex.Match(StringPiece(input_data, input_size), 0, input_size, anchor, target_groups.data(),
	                 static_cast<int>(group_count))) {
		return false;
	}
	for (auto &group : target_groups) {
		GroupMatch group_match;
		group_match.text = group.ToString();
		group_match.position = group.data() != nullptr ? static_cast<uint32_t>(group.data() - input_data) : 0;
		match.groups.emplace_back(group_match);
	}
	return true;
}

bool RegexSearch(const std::string &input, Match &match, const Regex &regex) {
	return SearchInternal(input.c_str(), input.size(), match, regex.GetRegex(), RE2::UNANCHORED);
}

bool RegexMatch(const std::string &input, Match &match, const Regex &regex) {
	return SearchInternal(input.c_str(), input.size(), match, regex.GetRegex(), RE2::ANCHOR_BOTH);
}

bool RegexMatch(const char *start, const char *end, Match &match, const Regex &regex) {
	return SearchInternal(start, static_cast<size_t>(end - start), match, regex.GetRegex(), RE2::ANCHOR_BOTH);
}

bool RegexMatch(const std::string &input, const Regex &regex) {
	Match nop_match;
	return SearchInternal(input.c_str(), input.size(), nop_match, regex.GetRegex(), RE2::ANCHOR_BOTH);
}

} // namespace duckdb_re2
