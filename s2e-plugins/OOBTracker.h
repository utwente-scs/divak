#ifndef S2E_PLUGINS_OOBTRACKER_H
#define S2E_PLUGINS_OOBTRACKER_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/MemoryMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/Plugins/Support/Screenshot.h>

#include <chrono>  // For measuring wall clock time

#include "MemoryTracker.h"
#include "OOBAnalyzer.h"

namespace s2e {
namespace plugins {

class OOBTracker : public Plugin {
    S2E_PLUGIN
   public:
    OOBTracker(S2E *s2e) : Plugin(s2e) {}

    void initialize();

    void onTranslateInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                   uint64_t pc);

    void onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                     uint64_t pc);

    void onTranslateInstructionStartSecondary(S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                                              bool *forcePcUpdate);

    void onTranslateSpecialInstructionEnd(ExecutionSignal *, S2EExecutionState *, TranslationBlock *, uint64_t,
                                          enum special_instruction_t, const special_instruction_data_t *);

    void jumpToSymbolic(S2EExecutionState *state, uint64_t pc) { state->jumpToSymbolicCpp(); }

    void onPointerCreatingOrBoundsNarrowingInstruction(S2EExecutionState *state, uint64_t pc,
                                                       std::optional<PuT_BoundsNarrowingInst *> bni,
                                                       std::optional<std::string> pci_reg);

    void onBeforeSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> addr,
                                          klee::ref<klee::Expr> value, bool isWrite);

    void onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t addr, uint64_t value, uint8_t size,
                                    unsigned flags);

    void onCall(S2EExecutionState *state, const ModuleDescriptorConstPtr &source, const ModuleDescriptorConstPtr &dest,
                uint64_t callerPc, uint64_t calleePc, const FunctionMonitor::ReturnSignalPtr &returnSignal);

    void onSyscall(S2EExecutionState *state, uint64_t pc);

    void onLibcFunctionCall(S2EExecutionState *state, uint64_t callerPc, std::string funName);

    void onEngineShutdown();

    void onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, const std::string &ImageFileName);

   private:
    MemoryTracker *m_memTracker;
    OOBAnalyzer *m_oobAnalyzer;
    MemoryMap *m_memMap;
    LinuxMonitor *m_linuxMon;
    ProcessExecutionDetector *m_procDetector;

    std::chrono::_V2::system_clock::time_point putExecutionStartTime;

    bool taintPointer(S2EExecutionState *state, unsigned int regOffset, BoundsRecord *br);

    void onMainRet(S2EExecutionState *state, const ModuleDescriptorConstPtr &returner,
                   const ModuleDescriptorConstPtr &returnee, uint64_t returnSite);

    void checkWriteToPointer(S2EExecutionState *state, klee::ref<klee::Expr> addr, unsigned int accessSize,
                             uint64_t pc);

    void concretizeFunArgRegs(S2EExecutionState *state);

    void concretizeRegs(S2EExecutionState *state, std::set<std::string> regNames);

    bool narrowPointerBounds(S2EExecutionState *state, BoundsRecord *br_old, BoundsRecord *br_new,
                             PuT_BoundsNarrowingInst *bni);

    BoundsRecord getBoundsRecordByName(S2EExecutionState *state, std::string name);

    int findSymBase(S2EExecutionState *state, klee::ref<klee::Expr> expr, klee::ref<klee::ReadExpr> &ret,
                    std::string prefix);

    void collectReadIt(S2EExecutionState *state, std::set<ref<ReadExpr>> &collection, ref<Expr> expr);
};

}  // namespace plugins
}  // namespace s2e

#endif  // S2E_PLUGINS_OOBTRACKER_H