#ifndef S2E_PLUGINS_UTILITY_H
#define S2E_PLUGINS_UTILITY_H

#include <klee/Expr.h>
#include <llvm/ADT/Statistic.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Utils.h>

#include <boost/icl/closed_interval.hpp>
#include <boost/icl/interval_set.hpp>
#include <map>

namespace b_ival = boost::icl;
typedef boost::icl::interval_set<long> ival_set_signed;
typedef boost::icl::interval_set<uint64_t> ival_set_unsigned;
typedef boost::icl::discrete_interval<uint64_t> ival_abs;
typedef boost::icl::discrete_interval<long> ival_rel;
constexpr auto new_ival_abs = boost::icl::discrete_interval<uint64_t>::closed;
constexpr auto new_ival_rel = boost::icl::discrete_interval<long>::closed;

namespace s2e {
namespace plugins {

uint regStrToIdx(std::string regName);

std::string getPtrStoreKeyFromName(std::string rawName, std::string prefix);

/*
 * Given a map with non-overlapping intervals map<interval_start, element> and an addr within some interval,
 * return the <interval_start, element> for the interval in which addr might lie.
 */
template <typename K, typename V>
std::optional<std::pair<K, V>> getFloorElemPair(std::map<K, V> &coll, K addr) {
    assert(std::is_sorted(coll.begin(), coll.end()));

    auto it = coll.upper_bound(addr);
    if (it == coll.begin()) {
        // addr is before start of any item in the collection
        return std::nullopt;
    }
    return *std::prev(it);
}

/*
 * Given a map with non-overlapping intervals map<interval_start, element> and an addr within some interval,
 * return the element for the interval in which addr might lie.
 */
template <typename K, typename V>
std::optional<V> getFloorElem(std::map<K, V> &coll, K addr) {
    if (auto floorElemPair = getFloorElemPair(coll, addr)) {
        return floorElemPair->second;
    }
    return std::nullopt;
}

}  // namespace plugins
}  // namespace s2e

// For the LLVM Statistics
#define DEBUG_TYPE "oob-checker"
#undef LLVM_FORCE_ENABLE_STATS
#define LLVM_FORCE_ENABLE_STATS 1

#endif