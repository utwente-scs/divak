#include "OOBTracker.h"

#include <llvm/Support/raw_os_ostream.h>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>

#include <stack>

#include "util.h"

using namespace klee;

namespace s2e {
namespace plugins {

STATISTIC(N_UNCHECKED_WRITES,
          "Number of writes for which checking was completely missed. Excludes writes in unmonitored sections.");
STATISTIC(N_CHECKED_INDEPENDENT_WRITES, "Number of independent writes checked");
STATISTIC(N_CHECKED_DEPENDENT_WRITES, "Number of dependent writes checked");
STATISTIC(N_FAILED_TAINT_RECOVERY,
          "Number of times the taint could not be recovered from a pointer due to overtainting");

STATISTIC(N_OTHER_ERROR, "Number of rare, possibly very bad errors that occured.");
STATISTIC(N_TAINTED_POINTER_PCI_NO_BNI_SKIPPED,
          "Number of times we encountered non-BNI pointer-creating instructions that had an already-tainted pointer.");

STATISTIC(N_POINTEE_DETERMINED_FROM_MEM_LAYOUT,
          "Number of times the pointee of a pointer has been successfully determined from the memory layout.");

STATISTIC(N_BOUNDS_NARROWING_FAILED_TYPE_MISMATCH, "Number of times bounds narrowing failed due to a type mismatch");
STATISTIC(N_BOUNDS_NARROWING_FAILED_OTHER, "Number of times bounds-narrowing failed for other reasons");
STATISTIC(N_BOUNDS_NARROWING_UNNECESSARY, "Number of times bounds-narrowing is deemed unnecessary.");
STATISTIC(N_BOUNDS_NARROWING_FAILED_UNKNOWN_POINTEE,
          "Number of times bounds-narrowing failed at a pointer-creating instruction because the pointee couldn't be "
          "determined.");
STATISTIC(N_BOUNDS_NARROWING_SUCCESSFUL_EMITTING,
          "Number of times emitting bounds narrowing was successfully performed.");
STATISTIC(N_BOUNDS_NARROWING_SUCCESSFUL_INTERNAL,
          "Number of times internal bounds narrowing was successfully performed.");
STATISTIC(N_FAILED_BN_FRAGMENTED_OBJECT, "Number of times that bounds narrowing of a fragmented object was attempted");

class OOBTrackerState : public PluginState {
   public:
    uint64_t ptrCounter = 0;
    std::map<std::string, BoundsRecord> ptrBoundsStore;
    bool setupDone = false;
    bool mainActive = false;
    uint64_t eatNextConcreteMemAccess;

   public:
    static PluginState *factory(Plugin *p, S2EExecutionState *s) { return new OOBTrackerState(); }

    virtual ~OOBTrackerState() {
        // Destroy any object if needed
    }

    virtual OOBTrackerState *clone() const { return new OOBTrackerState(*this); }

    uint64_t getNewPointerId() { return ptrCounter++; }
};

S2E_DEFINE_PLUGIN(OOBTracker, "Detects Out-of-bounds Writes", "", );

void OOBTracker::initialize() {
    llvm::EnableStatistics();
    // Need high priority as we want to be notified before MemoryTracker to get the call stack as is before the
    // call
    s2e()->getPlugin<FunctionMonitor>()->onCall.connect(sigc::mem_fun(*this, &OOBTracker::onCall),
                                                        sigc::signal_base::HIGH_PRIORITY);

    s2e()->getCorePlugin()->onTranslateInstructionEnd.connect(
        sigc::mem_fun(*this, &OOBTracker::onTranslateInstructionEnd));

    s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
        sigc::mem_fun(*this, &OOBTracker::onTranslateInstructionStart));  // dummy

    s2e()->getCorePlugin()->onTranslateInstructionStartSecondary.connect(
        sigc::mem_fun(*this, &OOBTracker::onTranslateInstructionStartSecondary));

    s2e()->getCorePlugin()->onTranslateSpecialInstructionEnd.connect(
        sigc::mem_fun(*this, &OOBTracker::onTranslateSpecialInstructionEnd));

    s2e()->getCorePlugin()->onBeforeSymbolicDataMemoryAccess.connect(
        sigc::mem_fun(*this, &OOBTracker::onBeforeSymbolicDataMemoryAccess));

    s2e()->getCorePlugin()->onConcreteDataMemoryAccess.connect(
        sigc::mem_fun(*this, &OOBTracker::onConcreteDataMemoryAccess));

    s2e()->getCorePlugin()->onEngineShutdown.connect(sigc::mem_fun(*this, &OOBTracker::onEngineShutdown));

    // Create/get all the required plugins
    m_oobAnalyzer = s2e()->getPlugin<OOBAnalyzer>();
    assert(m_oobAnalyzer);
    m_memTracker = s2e()->getPlugin<MemoryTracker>();
    assert(m_memTracker);
    m_memMap = s2e()->getPlugin<MemoryMap>();
    assert(m_memMap);
    m_linuxMon = s2e()->getPlugin<LinuxMonitor>();
    assert(m_linuxMon);
    m_procDetector = s2e()->getPlugin<ProcessExecutionDetector>();
    assert(m_procDetector);

    m_linuxMon->onProcessLoad.connect(sigc::mem_fun(*this, &OOBTracker::onProcessLoad));
}

void OOBTracker::onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t pid,
                               const std::string &ImageFileName) {
    if (m_procDetector->isTracked(ImageFileName)) {
        putExecutionStartTime = std::chrono::system_clock::now();
    }
}

void OOBTracker::onEngineShutdown() {
    std::chrono::duration<double> putsExecutionDuration = (std::chrono::system_clock::now() - putExecutionStartTime);
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(putsExecutionDuration);
    getInfoStream() << "Finished in " << seconds.count() << " seconds [Wall Clock]"
                    << "\n";

    // Print and save collected statistics
    llvm::PrintStatistics(getInfoStream());
    if (s2e()->getConfig()->hasKey(getConfigKey() + ".statsPath")) {
        std::string statsPath = s2e()->getConfig()->getString(getConfigKey() + ".statsPath");
        std::ofstream statsFile(statsPath);
        llvm::raw_os_ostream file_raw(statsFile);
        llvm::PrintStatisticsJSON(file_raw);
        statsFile.close();
        getInfoStream() << "Wrote statistics to " << statsPath << "\n";

	/*
        std::string timePath = statsPath.substr(0, statsPath.find_last_of("/") + 1) + "time";
        std::ofstream timeFile(timePath);
        timeFile << seconds.count() << "\n";
        timeFile.close();
        */
    }

    //s2e()->getPlugin<Screenshot>()->takeScreenShot("/home/linus/Desktop/s2e-dbg/projects/last-screenshot.png");

    getInfoStream() << "*********OOBTracker results*********\n";

    auto j = m_oobAnalyzer->generateJson();
    if (j->empty()) {
        getInfoStream() << "No Out-of-bounds writes detected during execution\n";
        getInfoStream() << "************************************\n";
        return;
    }
    getInfoStream() << "Detected Out-of bounds writes at " << j->size() << " location(s) in the program\n";
    getInfoStream() << j->dump(2) + "\n";
    getInfoStream() << "************************************\n";

    // Write the results to file
    if (s2e()->getConfig()->hasKey(getConfigKey() + ".resultsPath")) {
        std::string resultsPath = s2e()->getConfig()->getString(getConfigKey() + ".resultsPath");
        std::ofstream file(resultsPath);
        file << j->dump(2) << std::endl;
        file.close();
        getInfoStream() << "Wrote results to " << resultsPath << "\n";
    }
}

void OOBTracker::onBeforeSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> addr,
                                                  klee::ref<klee::Expr> value, bool isWrite) {
    if (!isWrite) {
        return;
    }

    if (!m_procDetector->isTracked(state)) {
        return;
    }

    DECLARE_PLUGINSTATE(OOBTrackerState, state);
    if (!plgState->mainActive) {
        return;
    }
    getInfoStream() << "onBeforeSymbolicDataMemoryAccess at " << hexval(state->regs()->getPc()) << "\n";

    auto accessSize = Expr::getMinBytesForWidth(value->getWidth());

    auto pc = state->regs()->getPc();

    if (m_memTracker->isStaticWriteSite(pc)) {
        return;
    } else {
        plgState->eatNextConcreteMemAccess = pc;
    }

    if (m_memTracker->isInnocuousWrite(pc)) {
        // Instructions like AND can access relative to a pointer but still be innocuous
        return;
    }

    checkWriteToPointer(state, addr, accessSize, pc);
}

void OOBTracker::checkWriteToPointer(S2EExecutionState *state, klee::ref<klee::Expr> addr, unsigned int accessSize,
                                     uint64_t pc) {
    ref<ReadExpr> sym_base;
    std::string prefix = "memobj_";
    DECLARE_PLUGINSTATE(OOBTrackerState, state);

    auto concAddr = state->toConstantSilent(addr)->getZExtValue();

    int n_matches = findSymBase(state, addr, sym_base, prefix);
    if (n_matches == 0) {
        getDebugStream() << "Symbolic pointers annihilated each other, nothing to check.\n";
        //  The symbolic pointers annihilated each other
        //  TODO: This might not work as expected, concrete write callback doesn't seem to be invoked reliably
        plgState->eatNextConcreteMemAccess = 0;  // Let the concrete write checker handle this
        return;
    } else if (n_matches > 1) {
        getWarningsStream(state) << "Failed to find unique base of the symbolic address at " << hexval(pc) << ", "
                                 << n_matches << " matches!\n";
        if (m_memTracker->isMonitoredRegion(m_memTracker->getAddrMemRegion(state, concAddr)) ||
            m_memTracker->isMonitoredRegion(m_memTracker->getAddrMemRegion(state, concAddr + accessSize - 1))) {
            N_UNCHECKED_WRITES++;
        }

        N_FAILED_TAINT_RECOVERY++;
        return;
    }
    N_CHECKED_DEPENDENT_WRITES++;

    std::string name = sym_base->getUpdates()->getRoot()->getName();
    getDebugStream(state) << "Dependent write to pointer " << hexval(concAddr) << " with taint " << name << "\n";

    auto ptrStoreKey = getPtrStoreKeyFromName(name, "memobj_");
    auto it = plgState->ptrBoundsStore.find(ptrStoreKey);
    if (it == plgState->ptrBoundsStore.end()) {
        std::cout << "pointer store key: " << ptrStoreKey << "\n";
        assert(false && "Pointer identifier extracted from symbolic value is not in ptrBoundsStore!");
    }

    auto boundsRecord = it->second;

    if (auto bni = m_memTracker->isBoundsNarrowingInst(pc)) {
        getDebugStream(state) << "Dependent write at " << hexval(pc)
                              << " is also bounds-narrowing for type with mnemonic " << (*bni)->typeMnemonic << "\n";

        assert((*bni)->resReg.empty() && "Emitting BNI at write");

        BoundsRecord boundsRecordNew;

        if ((*bni)->typeMnemonic != boundsRecord.typeSpec->mnemonic) {
            getWarningsStream(state) << "Type mnemonic mismatch when narrowing pointer: " << (*bni)->typeMnemonic
                                     << " vs. " << boundsRecord.typeSpec->mnemonic << "\n";
            N_BOUNDS_NARROWING_FAILED_TYPE_MISMATCH++;
            return;
        }

        if (narrowPointerBounds(state, &boundsRecord, &boundsRecordNew, *bni)) {
            boundsRecord = boundsRecordNew;
            N_BOUNDS_NARROWING_SUCCESSFUL_INTERNAL++;

        } else {
            getWarningsStream(state) << "Internal bounds-narrowing of dependent write at " << hexval(pc) << " failed\n";
        }
    }

    if (!(boundsRecord.lower <= concAddr && concAddr + accessSize - 1 <= boundsRecord.upper)) {
        getWarningsStream(state) << "pointer " << hexval(concAddr) << " with access size " << accessSize
                                 << " is out of bounds [" << hexval(boundsRecord.lower) << ", "
                                 << hexval(boundsRecord.upper) << "] at PC=" << hexval(pc) << "\n";

        m_oobAnalyzer->handleOOBWrite(state, concAddr, accessSize, pc, boundsRecord);

        return;
    }
    getDebugStream(state) << "pointer " << hexval(concAddr) << " is in bounds [" << hexval(boundsRecord.lower) << ", "
                          << hexval(boundsRecord.upper) << "] at " << hexval(pc) << "\n";
}

void OOBTracker::concretizeRegs(S2EExecutionState *state, std::set<std::string> regNames) {
    for (auto regName : regNames) {
        unsigned regOffset = CPU_OFFSET(regs) + regStrToIdx(regName) * 8;

        bool isConcrete;
        if (!state->regs()->getRegType(regOffset, 8, &isConcrete)) {
            getWarningsStream(state) << "Failed to obtain register type before concretization\n";
            continue;
        }
        if (!isConcrete) {
            klee::ref<klee::Expr> regVal_s = state->regs()->read(regOffset, Expr::Width(64));
            if (!regVal_s) {
                getWarningsStream(state) << "Failed to obtain symbolic value of register to concretize\n";
                continue;
            }
            uint64_t regVal_c = state->toConstantSilent(regVal_s)->getZExtValue();

            if (!state->regs()->write(regOffset, &regVal_c, sizeof(regVal_c))) {
                getWarningsStream(state) << "Failed to write concrete value to register\n";
                continue;
            }
            getDebugStream(state) << "Concretized " << regName << " to " << regVal_c << "\n";
        }
    }
}

void OOBTracker::concretizeFunArgRegs(S2EExecutionState *state) {
    std::set<std::string> argRegs{"RDI", "RSI", "RDX", "RCX", "R8", "R9"};
    concretizeRegs(state, argRegs);
}

void OOBTracker::onCall(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                        const ModuleDescriptorConstPtr &dest, uint64_t callerPc, uint64_t calleePc,
                        const FunctionMonitor::ReturnSignalPtr &returnSignal) {
    if (!m_procDetector->isTracked(state)) {
        return;
    }

    DECLARE_PLUGINSTATE(OOBTrackerState, state);

    if (!plgState->mainActive && m_memTracker->getMainFuncAddr() == calleePc) {
        plgState->mainActive = true;
        returnSignal->connect(sigc::mem_fun(*this, &OOBTracker::onMainRet));
    }

    if (auto funName = m_memTracker->getFunNameIfKnownLibFunCallAddr(calleePc)) {
        onLibcFunctionCall(state, callerPc, *funName);
    }
}

void OOBTracker::onLibcFunctionCall(S2EExecutionState *state, uint64_t callerPc, std::string funName) {
    // helper function to avoid code repetition
    auto getSymbolicReg =
        [&](int reg) {
            bool regIsConcrete;
            klee::ref<klee::Expr> regVal;

            if (!state->regs()->getRegType(CPU_OFFSET(regs[reg]), 8, &regIsConcrete)) {
                getWarningsStream(state) << "Failed to obtain symbolic/concrete status of register\n";
                return klee::ref<klee::Expr>(nullptr);
            }
            if (regIsConcrete) {
                uint64_t concAddr;
                if (!state->regs()->read(CPU_OFFSET(regs[reg]), &concAddr, sizeof(concAddr), false)) {
                    getWarningsStream(state)
                        << "Destination address register is concrete but couldn't get concrete value\n";
                    return klee::ref<klee::Expr>(nullptr);
                }
                switch (m_memTracker->getAddrMemRegion(state, concAddr)) {
                    case mr_bss:
                    case mr_data:
                    case mr_text:
                    case mr_static_other:
                        getWarningsStream(state)
                            << "Destination address register is concrete but points to monitored region\n";
                    default:
                        return klee::ref<klee::Expr>(nullptr);
                }

                return klee::ref<klee::Expr>(nullptr);
            }
            regVal = state->regs()->read(CPU_OFFSET(regs[reg]), Expr::Width(64));
            assert(regVal);
            return regVal;
        };

    auto getConcreteReg = [&](int reg) -> std::optional<uint64_t> {
        bool isConcrete;
        if (!state->regs()->getRegType(CPU_OFFSET(regs[reg]), 8, &isConcrete)) {
            getWarningsStream(state) << "Failed to obtain register type before fetching concrete value\n";
            return std::nullopt;
        }
        if (isConcrete) {
            uint64_t regVal_c;
            if (!state->regs()->read(CPU_OFFSET(regs[reg]), &regVal_c, sizeof(regVal_c), false)) {
                getWarningsStream(state) << "Failed to obtain concrete value in register\n";
                return std::nullopt;
            }
            return regVal_c;
        } else {
            auto regVal_s = state->regs()->read(CPU_OFFSET(regs[reg]), Expr::Width(64));
            return state->toConstantSilent(regVal_s)->getZExtValue();
        }
    };

    std::set<std::string> harmless_libc_funcs({"printf", "vprintf", "fprintf", "malloc", "realloc", "free", "fopen"});

    if (harmless_libc_funcs.find(funName) != harmless_libc_funcs.end()) {
        concretizeFunArgRegs(state);
        if (!state->isRunningConcrete()) {
            state->switchToConcrete();
        }

    } else if (funName == "exit") {
        auto exit_code = getConcreteReg(R_EDI);
        if (!exit_code) {
            getInfoStream(state) << "Called exit but couldnt get code. Terminating prematurely.\n";
        }
        getInfoStream(state) << "Called exit with code " << (int)*exit_code << ". Terminating prematurely.\n";

        s2e()->getExecutor()->terminateState(*state);
        return;

    } else if (funName == "strcpy") {
        auto dstAddr = getSymbolicReg(R_EDI);
        if (!dstAddr) {
            concretizeFunArgRegs(state);
            return;
        }

        std::string s;
        auto rsi = getConcreteReg(R_ESI);
        if (!rsi) {
            return;
        }

        if (!state->mem()->readString(*rsi, s, (unsigned)-1)) {
            getWarningsStream(state) << "Failed to obtain arguments of strcpy call\n";
            return;
        }

        assert(s.length() < (unsigned)-1);
        checkWriteToPointer(state, dstAddr, s.length() + 1, callerPc);
        concretizeFunArgRegs(state);

    } else if (funName == "strncpy" || funName == "memcpy" || funName == "memset") {
        auto dstAddr = getSymbolicReg(R_EDI);
        if (!dstAddr) {
            concretizeFunArgRegs(state);
            return;
        }

        auto n_bytes = getConcreteReg(R_EDX);
        if (!n_bytes) {
            return;
        }
        // strncpy always writes n_bytes. If the string is shorter, the rest is padded with 0x00
        checkWriteToPointer(state, dstAddr, *n_bytes, callerPc);
        concretizeFunArgRegs(state);

    } else if (funName == "sprintf" || funName == "snprintf" || funName == "vsnprintf") {
        // Determining the string length before is tricky, so concretize all but the destination address and let S2E
        // figure it out
        std::set<std::string> nonDstArgRegs{"RSI", "RDX", "RCX", "R8", "R9"};
        concretizeRegs(state, nonDstArgRegs);
    } else if (funName == "strcat" || funName == "strncat") {
        auto dstStrAddr_s = getSymbolicReg(R_EDI);
        if (!dstStrAddr_s) {
            concretizeFunArgRegs(state);
            return;
        }
        uint64_t dstStrAddr_c = state->toConstantSilent(dstStrAddr_s)->getZExtValue();

        auto srcStrAddr_c = getConcreteReg(R_ESI);
        if (!srcStrAddr_c) {
            return;
        }

        std::string dstStr, srcStr;
        if (!state->mem()->readString(dstStrAddr_c, dstStr, (unsigned)-1)) {
            getWarningsStream(state) << "Failed to obtain destination string\n";
            return;
        }
        if (!state->mem()->readString(*srcStrAddr_c, srcStr, (unsigned)-1)) {
            getWarningsStream(state) << "Failed to obtain source string\n";
            return;
        }

        uint64_t total_len = dstStr.length() + srcStr.length() + 1;
        if (funName == "strncat") {
            auto n_bytes = getConcreteReg(R_ESI);
            if (!n_bytes) {
                return;
            }
            total_len = std::min(total_len, *n_bytes + 1);
        }

        checkWriteToPointer(state, dstStrAddr_s, total_len, callerPc);
        concretizeFunArgRegs(state);
    } else if (funName == "sscanf" || funName == "fscanf") {
        std::set<std::string> nonDstArgRegs{"RDI", "RSI"};
        concretizeRegs(state, nonDstArgRegs);
    }
}

void OOBTracker::onMainRet(S2EExecutionState *state, const ModuleDescriptorConstPtr &returner,
                           const ModuleDescriptorConstPtr &returnee, uint64_t returnSite) {
    getInfoStream(state) << "Returning from main(), terminating state...\n";
    s2e()->getExecutor()->terminateState(*state);
}

void OOBTracker::onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                             uint64_t pc) {
    if (!m_procDetector->isTracked(state)) {
        return;
    }
    DECLARE_PLUGINSTATE(OOBTrackerState, state);
    if (!plgState->mainActive) {
        return;
    }

    // If we perform pointer tainting in the callback, we must make sure we're in symbolic mode
    if (m_memTracker->isBoundsNarrowingInst(pc) || m_memTracker->isPtrCreationSite(pc)) {
        signal->connect(sigc::mem_fun(*this, &OOBTracker::jumpToSymbolic));
    }
}

void OOBTracker::onTranslateInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                           uint64_t pc) {
    if (!m_procDetector->isTracked(state)) {
        return;
    }
    DECLARE_PLUGINSTATE(OOBTrackerState, state);
    if (!plgState->mainActive) {
        return;
    }

    auto bni = m_memTracker->isBoundsNarrowingInst(pc);
    auto pci = m_memTracker->isPtrCreationSite(pc);
    if ((*bni)->resReg.empty()) {
        bni = std::nullopt;
    }

    if (bni || pci) {
        signal->connect(
            sigc::bind(sigc::mem_fun(*this, &OOBTracker::onPointerCreatingOrBoundsNarrowingInstruction), bni, pci));
    }
}

void OOBTracker::onTranslateInstructionStartSecondary(S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                                                      bool *forcePcUpdate) {
    if (!m_procDetector->isTracked(state)) {
        return;
    }
    DECLARE_PLUGINSTATE(OOBTrackerState, state);
    if (!plgState->mainActive) {
        return;
    }
    if (m_memTracker->getAddrMemRegion(pc) == mr_text) {
        *forcePcUpdate = true;
    }
}

void OOBTracker::onTranslateSpecialInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                  TranslationBlock *tb, uint64_t pc,
                                                  enum special_instruction_t instr_type,
                                                  const special_instruction_data_t *instr_data) {
    if (instr_type != SYSCALL) {
        return;
    }
    if (!m_procDetector->isTracked(state)) {
        return;
    }
    DECLARE_PLUGINSTATE(OOBTrackerState, state);
    if (!plgState->mainActive) {
        return;
    }
    signal->connect(sigc::mem_fun(*this, &OOBTracker::onSyscall));
}

void OOBTracker::onSyscall(S2EExecutionState *state, uint64_t pc) {
    uint64_t rax, rdi;

    bool ok = state->regs()->read(CPU_OFFSET(regs[R_EAX]), &rax, sizeof(rax));
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EDI]), &rdi, sizeof(rdi));
    if (!ok) {
        getWarningsStream(state) << "Couldn't read syscall arguments\n";
        return;
    }

    if (rax == 59) {  // sys_execve
        std::string filename;
        bool ok = state->mem()->readString(rdi, filename, (unsigned)-1);
        if (!ok) {
            getWarningsStream(state) << "Failed to read filename for execve syscall\n";
            return;
        }
        if (filename == "/bin/sh") {
            getInfoStream(state) << "Detected execve syscall to /bin/sh, killing state...\n";
            s2e()->getExecutor()->terminateState(*state);
        }
    }
}

void OOBTracker::onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t addr, uint64_t value, uint8_t accessSize,
                                            unsigned flags) {
    if (!(flags & MEM_TRACE_FLAG_WRITE)) {
        return;
    }
    if (!m_procDetector->isTracked(state)) {
        return;
    }
    DECLARE_PLUGINSTATE(OOBTrackerState, state);
    if (!plgState->mainActive) {
        return;
    }

    uint64_t pc = state->regs()->getPc();

    // Filter out kernel address space accesses, these are definitely not from the program under test
    if (addr > 0x7fffffffffff) {
        return;
    }

    if (plgState->eatNextConcreteMemAccess != 0) {
        if (plgState->eatNextConcreteMemAccess == pc) {
            plgState->eatNextConcreteMemAccess = 0;
            return;
        }

        getWarningsStream(state)
            << "PC during discardable concrete write doesn't match PC at previous symbolic write! (" << hexval(pc)
            << " vs. " << hexval(plgState->eatNextConcreteMemAccess) << ")\n";
        plgState->eatNextConcreteMemAccess = 0;
    }

    if (m_memTracker->getAddrMemRegion(pc) != mr_text) {
        return;
    }

    auto put_func = m_memTracker->isStaticWriteSite(pc);
    if (!put_func) {
        if (!m_memTracker->isInnocuousWrite(pc)) {
            if (m_memTracker->isMonitoredRegion(m_memTracker->getAddrMemRegion(state, addr)) ||
                m_memTracker->isMonitoredRegion(m_memTracker->getAddrMemRegion(state, addr + accessSize - 1))) {
                N_UNCHECKED_WRITES++;
                getDebugStream(state) << "unchecked write at " << hexval(pc) << " to " << hexval(addr) << " with val "
                                      << hexval(value) << " of size " << hexval(accessSize) << "\n";
            }
        }
        return;
    }
    N_CHECKED_INDEPENDENT_WRITES++;

    auto func = *put_func;
    auto it = func->staticWrites.find(pc);
    assert(it != func->staticWrites.end());
    auto staticWrite = it->second;

    uint64_t lower;
    uint64_t upper;

    if (staticWrite->staticWriteToAutoVar) {
        // Read value of the function base register to which the bounds are relative
        uint64_t baseRegVal;
        unsigned int regOffset = CPU_OFFSET(regs) + regStrToIdx(func->baseReg) * 8;
        if (!state->regs()->read(regOffset, &baseRegVal, 8, false)) {
            getWarningsStream(state) << "Couldn't read concrete value in " << func->baseReg << " at RIP=" << hexval(pc)
                                     << ". (part of) the value seems to be symbolic!\n";
            return;
        }

        lower = baseRegVal + staticWrite->lowerBound.rel;
        upper = baseRegVal + staticWrite->upperBound.rel;
    } else {
        lower = staticWrite->lowerBound.abs;
        upper = staticWrite->upperBound.abs;
    }

    if (!(lower <= addr && addr + accessSize - 1 <= upper)) {
        getWarningsStream(state) << "static write to " << hexval(addr) << " with access size " << accessSize
                                 << " is out of bounds [" << hexval(lower) << ", " << hexval(upper)
                                 << "] at PC=" << hexval(pc) << "\n";
        BoundsRecord br = {lower, upper, staticWrite->dstVar->type, false};
        m_oobAnalyzer->handleOOBWrite(state, addr, accessSize, pc, br);
    } else {
        getDebugStream(state) << "static write to " << hexval(addr) << " with access size " << accessSize
                              << " is in bounds [" << hexval(lower) << ", " << hexval(upper) << "] at PC=" << hexval(pc)
                              << "\n";
    }
}

BoundsRecord OOBTracker::getBoundsRecordByName(S2EExecutionState *state, std::string name) {
    DECLARE_PLUGINSTATE(OOBTrackerState, state);
    auto ptrStoreKey = getPtrStoreKeyFromName(name, "memobj_");
    auto it_br = plgState->ptrBoundsStore.find(ptrStoreKey);
    if (it_br == plgState->ptrBoundsStore.end()) {
        getWarningsStream(state) << "pointer store key: " << ptrStoreKey << "\n";
        assert(false && "Pointer identifier extracted from symbolic value is not in ptrBoundsStore!");
    }
    return it_br->second;
}

bool OOBTracker::narrowPointerBounds(S2EExecutionState *state, BoundsRecord *br_old, BoundsRecord *br_new,
                                     PuT_BoundsNarrowingInst *bni) {
    if (br_old->varIsFragmented) {
        getWarningsStream(state) << "Tried to narrow bounds of fragmented object at " << hexval(state->regs()->getPc())
                                 << ", not supported!\n";
        N_FAILED_BN_FRAGMENTED_OBJECT++;
        return false;
    }
    // Sanity check on the bounds record
    assert(br_old->upper - br_old->lower + 1 == br_old->typeSpec->size);

    if (bni->narrowingFieldIndices.size() > 1) {
        // TODO: Implement nested narrowing here
        getWarningsStream(state) << "Bounds-narrowing instruction at " << hexval(state->regs()->getPc())
                                 << " requires nested narrowing, currently not implemented!\n";
        N_BOUNDS_NARROWING_FAILED_OTHER++;
        return false;
    }

    // Populate the new, narrowed bounds record
    unsigned narrowingIndex = bni->narrowingFieldIndices[0];
    switch (br_old->typeSpec->cat) {
        case ts_struct: {
            auto structType = static_cast<PuT_StructTypeSpec *>(br_old->typeSpec);
            if (structType->members.size() <= narrowingIndex) {
                // shouldn't happen because mnemonic checking should filter out these cases
                getWarningsStream(state) << "Struct type of pointee (DWARF offset " << br_old->typeSpec->dwarfOffset
                                         << ") has fewer members than narrowing index (" << structType->members.size()
                                         << " vs. " << narrowingIndex << " ). Something went wrong.\n";
                N_BOUNDS_NARROWING_FAILED_OTHER++;
                return false;
            }
            auto it_sm = structType->members.begin();
            std::advance(it_sm, narrowingIndex);  // move iterator to the correct field

            br_new->typeSpec = it_sm->second->type;
            br_new->lower = br_old->lower + it_sm->first;
            br_new->upper = br_new->lower + br_new->typeSpec->size - 1;
            br_new->varIsFragmented = false;
            assert(br_new->typeSpec);

            break;
        }
        case ts_array: {
            auto arrayType = static_cast<PuT_ArrayTypeSpec *>(br_old->typeSpec);
            if (arrayType->n_elems <= narrowingIndex) {
                // shouldn't happen because mnemonic checking should filter out these cases
                getWarningsStream(state) << "Array type of pointee (DWARF offset " << br_old->typeSpec->dwarfOffset
                                         << ") has fewer elements than narrowing index (" << arrayType->n_elems
                                         << " vs. " << narrowingIndex << " ). Something went wrong.\n";
                N_BOUNDS_NARROWING_FAILED_OTHER++;
                return false;
            }

            br_new->typeSpec = arrayType->elemType;
            // TODO: This doesn't work if stride!=elem_size, use stride!
            br_new->lower = br_old->lower + arrayType->elemType->size * narrowingIndex;
            br_new->upper = br_new->lower + br_new->typeSpec->size - 1;
            br_new->varIsFragmented = false;
            assert(br_new->typeSpec);

            break;
        }
        default: {
            // shouldn't happen because mnemonic checking should filter out these cases
            getWarningsStream(state) << "Current type of pointee (DWARF offset " << br_old->typeSpec->dwarfOffset
                                     << ") is not composite, cannot narrow bounds!\n";
            N_BOUNDS_NARROWING_FAILED_OTHER++;
            return false;
        }
    }
    return true;
}

void OOBTracker::onPointerCreatingOrBoundsNarrowingInstruction(S2EExecutionState *state, uint64_t pc,
                                                               std::optional<PuT_BoundsNarrowingInst *> bni,
                                                               std::optional<std::string> pci_reg) {
    assert(bni || pci_reg);

    if (bni && pci_reg) {
        assert((*bni)->resReg == *pci_reg);
    }
    std::string resReg = bni ? (*bni)->resReg : *pci_reg;
    unsigned int regOffset = CPU_OFFSET(regs) + regStrToIdx(resReg) * 8;

    bool isConcrete;
    if (!state->regs()->getRegType(regOffset, 8, &isConcrete)) {
        getWarningsStream(state)
            << "Failed to obtain register taintedness during onPointerCreatingOrBoundsNarrowingInstruction\n";
        return;
    }
    uint64_t regVal_c;
    BoundsRecord br_old;

    // Get concrete value from register and old bounds record if value is tainted
    if (isConcrete) {
        if (!state->regs()->read(regOffset, &regVal_c, 8, false)) {
            getWarningsStream(state) << "Failed to read concrete value in " << resReg << " at RIP=" << hexval(pc)
                                     << "\n";
            return;
        }
    } else {
        klee::ref<klee::Expr> regVal_s = state->regs()->read(regOffset, Expr::Width(64));
        regVal_c = state->toConstantSilent(regVal_s)->getZExtValue();

        ref<ReadExpr> sym_base;
        int n_matches = findSymBase(state, regVal_s, sym_base, "memobj_");
        if (n_matches == 0) {
            // The symbolic pointers annihilated each other
            isConcrete = true;
        } else if (n_matches > 1) {
            getWarningsStream(state) << "Failed to find unique base of the symbolic address at " << hexval(pc) << ", "
                                     << n_matches << " matches!\n";
            N_FAILED_TAINT_RECOVERY++;
            return;
        } else {
            std::string name = sym_base->getUpdates()->getRoot()->getName();
            br_old = getBoundsRecordByName(state, name);
            getDebugStream(state) << "Previous identifier of bounds narrowing instruction result: " << name << "\n";
        }
    }

    if (br_old.lower == 0 && br_old.upper == 0) {
        // Most certainly a pointer to a non-data/bss global section, no need to narrow
        return;
    }

    BoundsRecord br_new;

    if (!isConcrete && bni) {  // Tainted and BNI or BNI+PCI
        if ((*bni)->typeMnemonic != br_old.typeSpec->mnemonic) {
            getWarningsStream(state) << "Type mnemonic mismatch when narrowing pointer: " << (*bni)->typeMnemonic
                                     << " vs. " << br_old.typeSpec->mnemonic << "\n";
            N_BOUNDS_NARROWING_FAILED_TYPE_MISMATCH++;
            return;
        }

        if (!narrowPointerBounds(state, &br_old, &br_new, *bni)) {
            getWarningsStream(state) << "Failed to narrow bounds of pointer " << hexval(regVal_c) << " at "
                                     << hexval(pc) << " \n";
            return;
        }
        assert(br_new.typeSpec);
        N_BOUNDS_NARROWING_SUCCESSFUL_EMITTING++;
    } else if (!isConcrete && pci_reg) {  // Tainted and PCI but not BNI - error
        getWarningsStream(state) << "Encountered tainted pointer " << hexval(regVal_c)
                                 << " at non-bni pointer-creating instruction at " << hexval(pc) << ". Skipping...\n";
        N_TAINTED_POINTER_PCI_NO_BNI_SKIPPED++;
        return;
    } else if (isConcrete) {  // Untainted
        auto memRegion = m_memTracker->getAddrMemRegion(state, regVal_c);
        if (!m_memTracker->isMonitoredRegion(memRegion) && memRegion != mr_static_other) {
            getDebugStream(state) << "Pointer" << hexval(regVal_c)
                                  << " does not point to a monitored region or another static section.\n";
            N_BOUNDS_NARROWING_UNNECESSARY += (bni ? 1 : 0);
            return;
        }
        std::vector<unsigned> dummyBoundsNarrowingIndices;
        if (!m_memTracker->findPointeeBounds(state, regVal_c, dummyBoundsNarrowingIndices, &br_new)) {
            if (memRegion == mr_stack) {
                getWarningsStream(state) << "Failed to find pointee bounds for pointer " << hexval(regVal_c) << " at "
                                         << hexval(pc) << " (function " << m_memTracker->getCurrentFunc(state)->name
                                         << ", RBP-" << hexval(state->regs()->getBp() - regVal_c) << ")\n";
            } else {
                getWarningsStream(state) << "Failed to find pointee bounds for pointer " << hexval(regVal_c) << " at "
                                         << hexval(pc) << "\n";
            }

            N_BOUNDS_NARROWING_FAILED_UNKNOWN_POINTEE += (bni ? 1 : 0);
            return;
        }
        N_POINTEE_DETERMINED_FROM_MEM_LAYOUT++;

        if (bni && br_new.lower == 0 && br_new.upper == 0) {
            // Pointer to a read-only section, no need to narrow bounds
            N_BOUNDS_NARROWING_UNNECESSARY++;
        } else if (bni) {  // Untainted and BNI or BNI+PCI (and no zero-bounds)
            BoundsRecord br_tmp;
            if (!narrowPointerBounds(state, &br_new, &br_tmp, *bni)) {
                getWarningsStream(state) << "Failed to narrow bounds of pointer " << hexval(regVal_c) << " at "
                                         << hexval(pc) << " \n";
                return;
            }
            br_new = br_tmp;
            N_BOUNDS_NARROWING_SUCCESSFUL_EMITTING++;
        }
        // Else: Untainted and PCI

    } else {
        assert(false && "Unhandled case (probably illegal?)");
    }

    if (!taintPointer(state, regOffset, &br_new)) {
        getWarningsStream(state) << "Failed to (re-)taint pointer " << hexval(regVal_c) << " in " << resReg << " at "
                                 << hexval(pc) << "\n";
        N_OTHER_ERROR++;
        return;
    }
}

bool OOBTracker::taintPointer(S2EExecutionState *state, unsigned int regOffset, BoundsRecord *br) {
    DECLARE_PLUGINSTATE(OOBTrackerState, state);
    std::stringstream ss;
    ss << "memobj_" << hexval(br->lower) << "_" << plgState->getNewPointerId() << "_";
    auto ptrIdentifier = ss.str();

    ref<Expr> symb;

    // We can only make values symbolic when executing in symbolic mode. The jumpToSymbolic function called via
    // OnTranslateInstructionStart should have taken care of that.
    assert(!state->isRunningConcrete());

    // Find the concrete value of the register
    uint64_t regVal;
    bool isConcrete;
    if (!state->regs()->getRegType(regOffset, 8, &isConcrete)) {
        getWarningsStream(state) << "Failed to obtain register type\n";
        return false;
    }
    if (isConcrete) {
        if (!state->regs()->read(regOffset, &regVal, sizeof(regVal), false)) {
            getWarningsStream(state) << "Failed reading concrete value at " << regOffset << "\n";
            return false;
        }

    } else {
        auto regVal_s = state->regs()->read(regOffset, Expr::Width(64));
        regVal = state->toConstantSilent(regVal_s)->getZExtValue();
    }

    // Make the register symbolic
    symb = state->createSymbolicValue<target_ulong>(ptrIdentifier, regVal);
    if (!state->regs()->write(regOffset, symb)) {
        getWarningsStream(state) << "Failed to write symbolic value at " << regOffset << "\n";
        return false;
    }

    plgState->ptrBoundsStore.insert({ptrIdentifier, *br});

    getDebugStream(state) << "Tainted pointer " << hexval(regVal) << " at PC=" << hexval(state->regs()->getPc())
                          << " with identifier " << ptrIdentifier << "\n";

    state->disableForking();

    return true;
}

void OOBTracker::collectReadIt(S2EExecutionState *state, std::set<ref<ReadExpr>> &collection, ref<Expr> expr) {
    std::stack<ref<Expr>> stack;
    std::set<ref<Expr>> handled;

    stack.push(expr);
    ref<Expr> currExpr;

    ref<SubExpr> se;
    uint64_t subOp1Conc, subOp2Conc;

    while (!stack.empty()) {
        currExpr = stack.top();
        stack.pop();

        if (handled.count(currExpr)) {
            continue;
        }

        handled.insert(currExpr);

        switch (currExpr->getKind()) {
            case Expr::Extract:
                stack.push(dyn_cast<ExtractExpr>(currExpr)->getExpr());
                break;
            case Expr::Constant:
                break;
            case Expr::Read:
                collection.insert(dyn_cast<ReadExpr>(currExpr));
                break;
            case Expr::Sub:
                se = dyn_cast<SubExpr>(currExpr);

                subOp1Conc = state->toConstantSilent(se->getKid(0))->getZExtValue();
                subOp2Conc = state->toConstantSilent(se->getKid(1))->getZExtValue();

                if (subOp1Conc - subOp2Conc > 0x300000 && subOp2Conc - subOp1Conc > 300000) {
                    stack.push(se->getKid(0));
                    stack.push(se->getKid(1));
                }
                break;

            default:
                for (unsigned i = 0; i < currExpr->getNumKids(); i++) {
                    stack.push(currExpr->getKid(i));
                }
                break;
        }
    }
}

/*
 * Returns the number of matches found. If there are zero matches, the pointer is not tainted, the symbolic values
 * annihilate each other.
 */
int OOBTracker::findSymBase(S2EExecutionState *state, ref<Expr> expr, ref<ReadExpr> &ret, std::string prefix) {
    std::set<ref<ReadExpr>> collection;
    std::set<std::string> matches;

    collectReadIt(state, collection, expr);

    for (auto &rexpr : collection) {
        std::string name = rexpr->getUpdates()->getRoot()->getName();
        size_t pos = name.find(prefix);
        if (pos == std::string::npos) {
            continue;
        }
        ret = rexpr;
        matches.insert(name);
    }

    return matches.size();
}

}  // namespace plugins
}  // namespace s2e
