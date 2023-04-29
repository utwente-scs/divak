#include "MemoryTracker.h"

#include <s2e/Utils.h>

#include "util.h"

namespace s2e {
namespace plugins {

STATISTIC(N_POINTEE_SEARCH_INHIBITED_FRAGMENTED_OBJ,
          "Number of times a fragmented variable prevented determining the exact pointee of a pointer");
STATISTIC(N_MULTIPLE_OBJECTS_AT_LOCATION_AND_TIME,
          "Number of times we couldn't find the object at an address because there are multiple overlapping objects at "
          "the location and time.");
STATISTIC(N_POINTEE_NOT_DETERMINED_NO_OBJECT,
          "Number of times the pointee of a pointer couldn't be determined from the memory layout because there is no "
          "object as the location.");

class MemoryTrackerState : public PluginState {
   public:
    CallStack callStack;
    bool setupDone = false;

    static PluginState *factory(Plugin *p, S2EExecutionState *s) { return new MemoryTrackerState(); }

    virtual ~MemoryTrackerState() {
        // Destroy any object if needed
    }

    virtual MemoryTrackerState *clone() const { return new MemoryTrackerState(*this); }
};

S2E_DEFINE_PLUGIN(MemoryTracker, "Tracks the current memory layout", "", );

void MemoryTracker::initialize() {
    s2e()->getPlugin<FunctionMonitor>()->onCall.connect(sigc::mem_fun(*this, &MemoryTracker::onCall));

    m_procDetector = s2e()->getPlugin<ProcessExecutionDetector>();
    assert(m_procDetector);

    // Load auxiliary data from JSON
    std::string auxiliaryDataPath = s2e()->getConfig()->getString(getConfigKey() + ".auxiliaryDataPath");
    processJSON(auxiliaryDataPath);
}

void MemoryTracker::processJSON(std::string jsonPath) {
    std::ifstream ifs(jsonPath);
    if (ifs.fail()) {
        throw std::runtime_error("Failed to open JSON file");
    }
    json j = json::parse(ifs);

    // Ingest type specs
    for (auto j_typeSpec : j["dwarf_type_specs"]) {
        if (j_typeSpec["type"] == "struct") {
            auto structTypeSpec = new PuT_StructTypeSpec();
            *structTypeSpec = j_typeSpec.get<PuT_StructTypeSpec>();
            put_typeSpecs.insert({structTypeSpec->dwarfOffset, structTypeSpec});

        } else if (j_typeSpec["type"] == "array") {
            auto arrayTypeSpec = new PuT_ArrayTypeSpec();
            *arrayTypeSpec = j_typeSpec.get<PuT_ArrayTypeSpec>();
            put_typeSpecs.insert({arrayTypeSpec->dwarfOffset, arrayTypeSpec});

        } else if (j_typeSpec["type"] == "generic") {
            auto genericTypeSpec = new PuT_GenericTypeSpec();
            *genericTypeSpec = j_typeSpec.get<PuT_GenericTypeSpec>();
            put_typeSpecs.insert({genericTypeSpec->dwarfOffset, genericTypeSpec});

        } else {
            assert(false && "Unknown type spec type");
        }
    }

    // Ingest static variables
    for (auto j_var : j["dwarf_static_vars"]) {
        auto var = new PuT_StaticVar();
        *var = j_var.get<PuT_StaticVar>();
        put_staticVars.push_back(var);

        var->type = put_typeSpecs.at(var->typeSpecDwarfOffset);
    }

    // Ingest functions
    for (auto j_func : j["dwarf_functions"]) {
        auto func = new PuT_Function();
        *func = j_func.get<PuT_Function>();
        put_funcs.insert({func->baseAddress, func});

        // Link each automatic variable to its type
        for (auto &autoVar : func->autoVars) {
            autoVar->type = put_typeSpecs.at(autoVar->typeSpecDwarfOffset);
        }

        for (auto it : func->staticWrites) {
            auto staticWrite = it.second;
            // Find the pointer to the PuT_Variable that the static write writes to and link it to the static write
            if (staticWrite->staticWriteToAutoVar) {
                std::for_each(func->autoVars.begin(), func->autoVars.end(), [staticWrite](PuT_AutoVar *var) {
                    if (staticWrite->dstVarDwarfOffset == var->dwarfOffset) {
                        staticWrite->dstVar = var;
                    }
                });
                assert(staticWrite->dstVar);

            } else {
                std::for_each(put_staticVars.begin(), put_staticVars.end(), [staticWrite](PuT_StaticVar *var) {
                    if (staticWrite->dstVarDwarfOffset == var->dwarfOffset) {
                        staticWrite->dstVar = var;
                    }
                });
                assert(staticWrite->dstVar);
            }

            // Ingest static write sites into their own map for easier lookup
            staticWriteSites.insert({staticWrite->addr, func});
        }

        // Ingest bounds narrowing instructions into their own map for easier lookup
        for (auto &[_, bni] : func->boundsNarrowingInsts) {
            boundsNarrowingInsts.insert({bni->addr, bni});
        }
    }

    // Ingest pointer creation sites
    for (auto &[key, val] : j.at("pointerCreationSites").items()) {
        auto addr = std::stoull(key, nullptr, 16);
        auto reg = val;
        pointerCreationSites.insert(std::pair<uint64_t, std::string>(addr, reg));
    }

    // Ingest segments
    for (auto j_seg : j["segments"]) {
        for (auto j_sec : j_seg["sections"]) {
            auto sec = new PuT_Section();
            *sec = j_sec.get<PuT_Section>();
            put_sections.insert({sec->baseAddress, sec});
        }
    }

    // Ingest external library call addresses
    for (auto &[funName, addr] : j.at("libFunCallAddrs").items()) {
        libFunCallAddrs.insert(std::pair<uint64_t, std::string>(addr, funName));
    }

    // Ingest innocuous writes
    for (auto addr : j.at("innocuous_writes")) {
        innocuousWrites.insert((uint64_t)addr);
    }

    // Add pointer to the typeSpec to all entities containing a reference to a typeSpec
    // Prevents having to do a lookup with dwarfOffset every time
    for (auto &[typeSpecDwarfOffset, typeSpec] : put_typeSpecs) {
        // for struct member types
        if (typeSpec->cat == ts_struct) {
            auto structTypeSpec = static_cast<PuT_StructTypeSpec *>(typeSpec);
            for (auto &[memberDwarfOffset, member] : structTypeSpec->members) {
                member->type = put_typeSpecs.at(member->typeSpecDwarfOffset);
            }
            // for array element types
        } else if (typeSpec->cat == ts_array) {
            auto arrayTypeSpec = static_cast<PuT_ArrayTypeSpec *>(typeSpec);
            arrayTypeSpec->elemType = put_typeSpecs.at(arrayTypeSpec->elemTypeSpecDwarfOffset);
        }
    }
}

void MemoryTracker::onCall(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                           const ModuleDescriptorConstPtr &dest, uint64_t callerPc, uint64_t calleePc,
                           const FunctionMonitor::ReturnSignalPtr &returnSignal) {
    if (!m_procDetector->isTracked(state)) {
        return;
    }
    DECLARE_PLUGINSTATE(MemoryTrackerState, state);

    if (!plgState->setupDone && getMainFuncAddr() == calleePc) {
        plgState->setupDone = true;
    }

    if (!plgState->setupDone) {
        return;
    }

    auto callStack = &plgState->callStack;

    bool monitoredCaller = !callStack->empty() && callStack->peek()->func != nullptr;

    // onCall is invoked right after CALL, before MOV RBP, RSP
    // +8 because the SP has been moved implicitly by the CALL
    // This value is the new RBP + 16
    uint64_t old_frame_top = state->regs()->getSp() + 8;

    if (!callStack->empty()) {
        StackFrame *prev_sframe = callStack->peek();
        if (monitoredCaller && prev_sframe->top && prev_sframe->top != old_frame_top) {
            getWarningsStream(state) << "Top of stack frame of function " << prev_sframe->func->name << " moved from "
                                     << hexval(prev_sframe->top) << " to " << hexval(old_frame_top)
                                     << " since last function call\n ";
        }
        prev_sframe->top = old_frame_top;
        assert(prev_sframe->top <= prev_sframe->bottom);
    }

    StackFrame new_sframe;
    new_sframe.bottom = old_frame_top - 1;
    new_sframe.top = 0;  // We don't know this yet
    new_sframe.func = getFuncIfKnownHead(calleePc);
    new_sframe.callerAddr = callerPc;
    callStack->push(new_sframe);

    if (monitoredCaller) {
        if (new_sframe.func != nullptr) {
            getDebugStream(state) << "call to " << new_sframe.func->name << "\n";
        } else if (auto funName = getFunNameIfKnownLibFunCallAddr(calleePc)) {
            getDebugStream(state) << "call to library function " << *funName << "\n";
        } else {
            getDebugStream(state) << "call to unknown function at " << hexval(calleePc) << "\n";
        }
    }

    returnSignal->connect(sigc::bind(sigc::mem_fun(*this, &MemoryTracker::onRet), monitoredCaller, new_sframe.bottom));
}

void MemoryTracker::onRet(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                          const ModuleDescriptorConstPtr &dest, uint64_t returnSite, bool monitoredCaller,
                          uint64_t frameTopAddr) {
    // TODO: The stack frame monitoring as currently implemented probably breaks when we have tail calls
    DECLARE_PLUGINSTATE(MemoryTrackerState, state);
    auto sframe = plgState->callStack.pop();
    assert(sframe.bottom == frameTopAddr);

    if (!monitoredCaller) {
        return;
    }

    getDebugStream(state) << "returning at " << hexval(returnSite) << "\n";
}

std::optional<PuT_Function *> MemoryTracker::isStaticWriteSite(uint64_t addr) {
    // We could also go through the current function's collection of static writes to check
    // But that would require using DECLARE_PLUGIN, might be more overhead than just going through all
    auto it = staticWriteSites.find(addr);
    if (it == staticWriteSites.end()) {
        return std::nullopt;
    }
    // return std::optional(it->second);
    return it->second;
}

std::optional<PuT_BoundsNarrowingInst *> MemoryTracker::isBoundsNarrowingInst(uint64_t addr) {
    auto it = boundsNarrowingInsts.find(addr);
    if (it == boundsNarrowingInsts.end()) {
        return std::nullopt;
    }
    return it->second;
}

PuT_GenericTypeSpec *MemoryTracker::getTypeSpec(uint64_t dwarfOffset) {
    auto it = put_typeSpecs.find(dwarfOffset);
    if (it == put_typeSpecs.end()) {
        return nullptr;
    }
    return it->second;
}

PuT_Section *MemoryTracker::getStaticSectionByAddr(uint64_t addr) {
    auto candidateSec = getFloorElem(put_sections, addr);
    if (!candidateSec) {
        return nullptr;
    }
    if ((*candidateSec)->baseAddress + (*candidateSec)->size < addr) {
        return nullptr;
    }
    return *candidateSec;
}

MemRegion MemoryTracker::getAddrMemRegion(uint64_t addr) {
    // Check the static regions
    auto candidateSec = getFloorElem(put_sections, addr);
    if (candidateSec && (*candidateSec)->baseAddress + (*candidateSec)->size >= addr) {
        if ((*candidateSec)->name == ".data") {
            return mr_data;
        } else if ((*candidateSec)->name == ".bss") {
            return mr_bss;
        } else if ((*candidateSec)->name == ".text") {
            return mr_text;
        } else {
            return mr_static_other;
        }
    }
    return mr_unknown;
}

MemRegion MemoryTracker::getAddrMemRegion(S2EExecutionState *state, uint64_t addr) {
    MemRegion static_res = getAddrMemRegion(addr);
    if (static_res != mr_unknown) {
        return static_res;
    } else if (state->regs()->getSp() - 0xffff < addr && addr < 0x7fffffffffff) {
        return mr_stack;
    } else {
        return mr_unknown;
    }
    // TODO: Maybe improve to also identify in mr_heap, mr_dynlib
}

uint64_t MemoryTracker::getMainFuncAddr() {
    static uint64_t mainFuncAddr = 0;
    if (!mainFuncAddr) {
        for (auto func : put_funcs) {
            if (func.second->name == "main") {
                mainFuncAddr = func.second->baseAddress;
                break;
            }
        }
        assert(mainFuncAddr && "failed to find main function");
    }

    return mainFuncAddr;
}

PuT_Function *MemoryTracker::getCurrentFunc(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(MemoryTrackerState, state);
    return plgState->callStack.empty() ? nullptr : plgState->callStack.peek()->func;
}

CallStack MemoryTracker::getCallStack(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(MemoryTrackerState, state);
    return plgState->callStack;
}

/*
 * Populates the passed bounds record with bounds information for ptrAddr.
 * Recursively dives into composite objects, attempting to find the most logical pointee object.
 * Intended to only be called from findPointeeBounds()
 * If the variable that the pointer points to is fragmented, we cannot reliably find the narrowest object pointed to, so
 * we simply take the variable itself as pointee.
 *
 * @param baseAddr The base address of the object we're currently treating
 * @param type The type of the object we're currently treating
 * @param boundsNarrowingIndices Bounds narrowing information describing the indices of members/fields that should be
 * @param sanCheck Whether or not to perform basic sanity check if pointer actually points to object
 * accessed. First element is highest-level index. Empty vector if no bounds narrowing information is available.
 */
bool MemoryTracker::findPointeeBoundsRec(S2EExecutionState *state, uint64_t ptrAddr, uint64_t baseAddr,
                                         PuT_GenericTypeSpec *type, std::vector<unsigned> boundsNarrowingIndices,
                                         bool sanCheck, BoundsRecord *boundsRecord, PuT_Var *var) {
    if (sanCheck && !(baseAddr <= ptrAddr && ptrAddr <= baseAddr + type->size)) {
        // ptrAddr is outside of the object
        return false;
    }

    if (var != nullptr && var->fragmented) {
        boundsRecord->lower = baseAddr;
        boundsRecord->upper = baseAddr + var->n_fragmentBytes - 1;
        boundsRecord->typeSpec = type;
        boundsRecord->varIsFragmented = true;

        getWarningsStream(state) << "Fragmented object prevented determining exact pointee at "
                                 << hexval(state->regs()->getPc()) << "\n";
        N_POINTEE_SEARCH_INHIBITED_FRAGMENTED_OBJ++;
        return true;
    }

    switch (type->cat) {
        case ts_generic: {
            if (boundsNarrowingIndices.size()) {
                getWarningsStream(state) << "Got bounds narrowing indices but pointee is generic type\n";
            }
            boundsRecord->lower = baseAddr;
            boundsRecord->upper = baseAddr + type->size - 1;
            boundsRecord->typeSpec = type;
            boundsRecord->varIsFragmented = false;
            getDebugStream(state) << "Identified pointee of " << hexval(ptrAddr) << " as variable " << var->name
                                  << " with DWARF offset " << var->dwarfOffset << "\n";
            return true;
        }

        case ts_struct: {
            auto structType = static_cast<PuT_StructTypeSpec *>(type);

            // find the member to whose space ptrAddr points
            auto candidateMemberPair = getFloorElemPair(structType->members, ptrAddr - baseAddr);
            assert(candidateMemberPair);
            auto candidateMemberOffset = candidateMemberPair->first;
            auto candidateMember = candidateMemberPair->second;

            if (boundsNarrowingIndices.size()) {
                // there exists bounds narrowing information, we act according to it, ignoring the actual pointee
                auto it_m = structType->members.begin();
                std::advance(it_m, boundsNarrowingIndices.front());

                auto fieldType = it_m->second->type;
                uint64_t newBaseAddr = baseAddr + it_m->first;
                boundsNarrowingIndices.erase(boundsNarrowingIndices.begin());  // remove index of this level
                if (it_m->first != candidateMemberOffset) {
                    getWarningsStream(state) << "Bounds narrowing index specifies field at offset " << it_m->first
                                             << " but pointer points to field at offset " << candidateMemberOffset
                                             << ". Narrowing according to index and disabling further sanity checks.\n";
                    sanCheck = false;
                }
                return findPointeeBoundsRec(state, ptrAddr, newBaseAddr, fieldType, boundsNarrowingIndices, sanCheck,
                                            boundsRecord, var);
            } else if (baseAddr == ptrAddr) {
                // pointer points to the very beginning of the struct. We do not recurse further but assume the entire
                // struct is the pointee
                boundsRecord->lower = baseAddr;
                boundsRecord->upper = baseAddr + type->size - 1;
                boundsRecord->typeSpec = type;
                boundsRecord->varIsFragmented = false;
                getDebugStream(state) << "Identified pointee of " << hexval(ptrAddr) << " as variable " << var->name
                                      << " with DWARF offset " << var->dwarfOffset << "\n";
                return true;

            } else {
                // No bounds narrowing information and pointer points to somewhere within the struct. Recurse further
                // into the struct to find the pointee field.
                if (baseAddr + candidateMemberOffset + candidateMember->type->size <= ptrAddr) {
                    // addr points to unused space inside struct, probably padding
                    return false;  // TODO: Ensure that this is really what we want to do
                }
                auto newBaseAddr = baseAddr + candidateMemberOffset;
                return findPointeeBoundsRec(state, ptrAddr, newBaseAddr, candidateMember->type, boundsNarrowingIndices,
                                            sanCheck, boundsRecord, var);
            }
        }

        case ts_array: {
            // TODO: This all was built without considering that multi-dimensional arrays are a thing, it probably
            // breaks if one is encountered
            auto arrayType = static_cast<PuT_ArrayTypeSpec *>(type);
            auto elemType = arrayType->elemType;

            // TODO: assumes size=stride, do this properly when we have the stride in the dwarf
            auto pointeeElemIndex = (ptrAddr - baseAddr) / elemType->size;

            if (boundsNarrowingIndices.size()) {
                uint64_t bn_idx = boundsNarrowingIndices.front();
                boundsNarrowingIndices.erase(boundsNarrowingIndices.begin());  // remove index of this level

                if (pointeeElemIndex != bn_idx) {
                    getWarningsStream(state) << "Bounds narrowing index specifies element at index " << bn_idx
                                             << " but pointer points to element at index " << pointeeElemIndex
                                             << ". Narrowing according to index and disabling further sanity checks.\n";
                    sanCheck = false;
                }

                // TODO: assumes size=stride, do this properly when we have the stride in the dwarf
                auto newBaseAddr = baseAddr + elemType->size * bn_idx;

                return findPointeeBoundsRec(state, ptrAddr, newBaseAddr, elemType, boundsNarrowingIndices, sanCheck,
                                            boundsRecord, var);

            } else if (baseAddr == ptrAddr) {
                // addr points to the base of the array
                boundsRecord->lower = baseAddr;
                boundsRecord->upper = baseAddr + type->size - 1;
                boundsRecord->typeSpec = type;
                boundsRecord->varIsFragmented = false;
                getDebugStream(state) << "Identified pointee of " << hexval(ptrAddr) << " as variable " << var->name
                                      << " with DWARF offset " << var->dwarfOffset << "\n";
                return true;

            } else {
                // TODO: assumes size=stride, do this properly when we have the stride in the dwarf
                auto newBaseAddr = baseAddr + elemType->size * pointeeElemIndex;

                // TODO: When stride is implemented, also add check whether we're in padding?
                return findPointeeBoundsRec(state, ptrAddr, newBaseAddr, elemType, boundsNarrowingIndices, sanCheck,
                                            boundsRecord, var);
            }
        }

        default:
            assert(false && "Type does not have valid kind!");
    }
}

/*
 *
 */
bool MemoryTracker::findPointeeBounds(S2EExecutionState *state, uint64_t addr,
                                      std::vector<unsigned> boundsNarrowingIndices, BoundsRecord *boundsRecord) {
    switch (getAddrMemRegion(state, addr)) {
        case mr_bss:
        case mr_data: {
            if (auto candidateVar = getStaticVarAtAddr(state, addr)) {
                return findPointeeBoundsRec(state, addr, (*candidateVar)->addr, (*candidateVar)->type,
                                            boundsNarrowingIndices, false, boundsRecord, *candidateVar);
            }
            return false;
        }
        case mr_text:
        case mr_static_other: {
            g_s2e->getDebugStream(state) << "Assigning zero-bounds for pointer " << hexval(addr)
                                         << " to static section\n";
            boundsRecord->lower = 0;
            boundsRecord->upper = 0;
            boundsRecord->typeSpec = nullptr;
            return true;  // TODO: Could handle this differently if the pointer points to a section that is writable
        }

        case mr_stack: {
            auto currFunc = getCurrentFunc(state);
            if (currFunc == nullptr) {
                return false;
            }
            // Check that addr is within stack frame of current function
            // Can't work with PuTs compiled with frame pointer omission this way
            assert(currFunc->baseReg == "RBP");
            long addr_rel = addr - state->regs()->getBp();

            // auto candidateVar = getFloorElem(currFunc->autoVars, addr_rel);
            auto candidateVar = getAutoVarAtOffset(state, currFunc->autoVars, addr_rel);
            if (!candidateVar) {
                return false;
            }
            uint64_t varBaseAddr_abs = (*candidateVar)->relAddr + state->regs()->getBp();
            return findPointeeBoundsRec(state, addr, varBaseAddr_abs, (*candidateVar)->type, boundsNarrowingIndices,
                                        true, boundsRecord, *candidateVar);
        }

        default:
            return false;
    }
}

// If the address is that of the head of a function that we monitor, return a pointer to the corresponding function
// struct
PuT_Function *MemoryTracker::getFuncIfKnownHead(uint64_t addr) {
    auto it = put_funcs.find(addr);
    if (it == put_funcs.end()) {
        return nullptr;
    }
    return it->second;
}

std::optional<std::string> MemoryTracker::getFunNameIfKnownLibFunCallAddr(uint64_t addr) {
    auto it = libFunCallAddrs.find(addr);
    if (it == libFunCallAddrs.end()) {
        return std::nullopt;
    }
    return std::optional(it->second);
}

std::optional<PuT_StaticVar *> MemoryTracker::getStaticVarAtAddr(S2EExecutionState *state, uint64_t addr) {
    std::vector<PuT_StaticVar *> candidates;
    uint64_t pc = state->regs()->getPc();

    // Could also do tolerant selection here, like for auto vars
    for (auto var : put_staticVars) {
        if (var->start_pc <= pc && pc < var->end_pc) {
            uint64_t size = var->fragmented ? var->n_fragmentBytes : var->type->size;
            assert(size != (uint64_t)-1);
            if (var->addr <= addr && addr < var->addr + size) {
                candidates.push_back(var);
            }
        }
    }

    if (candidates.empty()) {
        getWarningsStream(state) << "Found no static variables at " << hexval(addr) << " at PC=" << hexval(pc) << "\n";
        N_POINTEE_NOT_DETERMINED_NO_OBJECT++;
        return std::nullopt;
    } else if (candidates.size() == 1) {
        return candidates[0];
    } else {
        getWarningsStream(state) << "Found multiple static variables at " << hexval(addr) << " at PC=" << hexval(pc)
                                 << "\n";
        N_MULTIPLE_OBJECTS_AT_LOCATION_AND_TIME++;
        return std::nullopt;
    }
}

std::optional<PuT_AutoVar *> MemoryTracker::getAutoVarAtOffset(S2EExecutionState *state,
                                                               std::vector<PuT_AutoVar *> &autoVars, long offset) {
    std::vector<PuT_AutoVar *> perfectCandidates;
    PuT_AutoVar *approxCandidate = nullptr;
    uint64_t pc = state->regs()->getPc();

    for (auto var : autoVars) {
        int size = var->fragmented ? var->n_fragmentBytes : var->type->size;
        assert(size != -1);
        if (var->relAddr <= offset && offset < var->relAddr + size) {
            if (var->start_pc <= pc && pc < var->end_pc) {
                perfectCandidates.push_back(var);
            } else if (var->start_pc - 0x100 <= pc && pc < var->end_pc) {
                if (approxCandidate == nullptr || approxCandidate->start_pc < var->start_pc) {
                    approxCandidate = var;
                }
            }
        }
    }

    if (perfectCandidates.empty()) {
        if (approxCandidate == nullptr) {
            N_POINTEE_NOT_DETERMINED_NO_OBJECT++;
            getWarningsStream(state) << "Found no automatic variables at RBP" << offset << " at PC=" << hexval(pc)
                                     << "\n";
            return std::nullopt;
        } else {
            getDebugStream(state) << "Chose approximate match for variable at RBP" << offset << " at PC=" << hexval(pc)
                                  << "\n";
            return approxCandidate;
        }

    } else if (perfectCandidates.size() == 1) {
        return perfectCandidates[0];
    } else {
        getWarningsStream(state) << "Found multiple automatic variables at RBP" << offset << " at PC=" << hexval(pc)
                                 << "\n";
        N_MULTIPLE_OBJECTS_AT_LOCATION_AND_TIME++;
        return std::nullopt;
    }
}

}  // namespace plugins
}  // namespace s2e