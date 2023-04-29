#ifndef S2E_PLUGINS_OOBANALYZER_H
#define S2E_PLUGINS_OOBANALYZER_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>

#include <nlohmann/json.hpp>

#include "MemoryTracker.h"
#include "containers.h"
#include "util.h"

namespace s2e {
namespace plugins {

class OOBAnalyzer : public Plugin {
    S2E_PLUGIN
   public:
    OOBAnalyzer(S2E *s2e) : Plugin(s2e) {}

    void initialize();

    nlohmann::ordered_json *generateJson();

    void handleOOBWrite(S2EExecutionState *state, uint64_t addr, unsigned int accessSize, uint64_t vulnSiteAddr,
                        const BoundsRecord &br);

   private:
    nlohmann::ordered_json jsonifyComposite(ival_abs intersection, ival_abs obj_ival, PuT_GenericTypeSpec *typeSpec);

    std::map<uint64_t, OOBRecord *> oobWrites;
    MemoryTracker *m_memTracker;
};

}  // namespace plugins
}  // namespace s2e

#endif  // S2E_PLUGINS_OOBANALYZER_H