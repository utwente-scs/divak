#ifndef S2E_PLUGINS_MEMORYTRACKER_H
#define S2E_PLUGINS_MEMORYTRACKER_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>

#include <nlohmann/json.hpp>

#include "containers.h"

namespace s2e {
namespace plugins {

enum MemRegion { mr_data, mr_bss, mr_text, mr_static_other, mr_heap, mr_dynlib, mr_stack, mr_unknown };

class MemoryTracker : public Plugin {
    S2E_PLUGIN
   public:
    MemoryTracker(S2E *s2e) : Plugin(s2e) {}

    void initialize();

    std::optional<std::string> isPtrCreationSite(uint64_t addr) {
        auto it = pointerCreationSites.find(addr);
        if (it == pointerCreationSites.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    std::optional<PuT_Function *> isStaticWriteSite(uint64_t addr);

    std::optional<PuT_BoundsNarrowingInst *> isBoundsNarrowingInst(uint64_t addr);

    bool isInnocuousWrite(uint64_t addr) { return innocuousWrites.count(addr); }

    // If the address is the topmost address of a tracked function, return the pointer to the corresponding entry.
    // Otherwise, return nullptr.
    PuT_Function *getFuncIfKnownHead(uint64_t addr);

    std::optional<std::string> getFunNameIfKnownLibFunCallAddr(uint64_t addr);

    PuT_Var *getPointee(S2EExecutionState *state, uint64_t addr, PuT_Function *currFunc);

    bool findPointeeBounds(S2EExecutionState *state, uint64_t addr, std::vector<unsigned> boundsNarrowingIndices,
                           BoundsRecord *boundsRecord);

    MemRegion getAddrMemRegion(uint64_t addr);
    MemRegion getAddrMemRegion(S2EExecutionState *state, uint64_t addr);

    bool isMonitoredRegion(MemRegion mr) {
        switch (mr) {
            case mr_data:
            case mr_bss:
            case mr_stack:
                return true;
            default:
                return false;
        }
    }

    uint64_t getMainFuncAddr();

    // Return the function on top of the stack or nullptr if the stack is empty or the function is untracked
    PuT_Function *getCurrentFunc(S2EExecutionState *state);

    void processJSON(std::string jsonPath);

    PuT_GenericTypeSpec *getTypeSpec(uint64_t);

    PuT_Section *getStaticSectionByAddr(uint64_t addr);

    CallStack getCallStack(S2EExecutionState *state);

    // TODO: Could improve call stack manitenance by handling onTranslateRegisterAccessEnd

    void onCall(S2EExecutionState *state, const ModuleDescriptorConstPtr &source, const ModuleDescriptorConstPtr &dest,
                uint64_t callerPc, uint64_t calleePc, const FunctionMonitor::ReturnSignalPtr &returnSignal);

    void onRet(S2EExecutionState *state, const ModuleDescriptorConstPtr &source, const ModuleDescriptorConstPtr &dest,
               uint64_t returnSite, bool moniitoredCaller, uint64_t frameTop);

    //  This being a vector really isn't great, should be a map to make lookup faster. But we need a multi-index map
    //  (spatial and temporal), too complex for now.
    std::vector<PuT_StaticVar *> put_staticVars;

   private:
    json j;
    std::map<uint64_t, PuT_Function *> put_funcs;

    std::map<uint64_t, PuT_GenericTypeSpec *> put_typeSpecs;
    std::map<uint64_t, PuT_Section *> put_sections;
    std::map<uint64_t, std::string> pointerCreationSites;
    std::map<uint64_t, std::string> libFunCallAddrs;
    std::map<uint64_t, PuT_Function *> staticWriteSites;
    std::map<uint64_t, PuT_BoundsNarrowingInst *> boundsNarrowingInsts;

    std::unordered_set<uint64_t> innocuousWrites;

    ProcessExecutionDetector *m_procDetector;

    bool findPointeeBoundsRec(S2EExecutionState *state, uint64_t ptrAddr, uint64_t baseAddr, PuT_GenericTypeSpec *type,
                              std::vector<unsigned> boundsNarrowingIndices, bool sanCheck, BoundsRecord *boundsRecord,
                              PuT_Var *var);

    std::optional<PuT_StaticVar *> getStaticVarAtAddr(S2EExecutionState *state, uint64_t addr);
    std::optional<PuT_AutoVar *> getAutoVarAtOffset(S2EExecutionState *state, std::vector<PuT_AutoVar *> &autoVars,
                                                    long offset);
};

}  // namespace plugins
}  // namespace s2e

#endif