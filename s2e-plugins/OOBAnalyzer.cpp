#include "OOBAnalyzer.h"

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(OOBAnalyzer, "Aggregates and analyzes discovered OOB write vulnerabilities", "", );

void OOBAnalyzer::initialize() {
    m_memTracker = s2e()->getPlugin<MemoryTracker>();
    assert(m_memTracker);
}

nlohmann::ordered_json OOBAnalyzer::jsonifyComposite(ival_abs intersection, ival_abs obj_ival,
                                                     PuT_GenericTypeSpec *typeSpec) {
    nlohmann::ordered_json j;

    if (b_ival::is_empty(intersection)) {
        return j;
    }

    if (typeSpec->cat == ts_struct) {
        auto structType = static_cast<PuT_StructTypeSpec *>(typeSpec);
        nlohmann::ordered_json members_j = json::array();
        for (auto &[offset, member] : structType->members) {
            auto member_ival =
                new_ival_abs(obj_ival.lower() + offset, obj_ival.lower() + offset + member->type->size - 1);

            auto member_intersection = intersection & member_ival;
            if (!b_ival::is_empty(member_intersection)) {
                nlohmann::ordered_json member_j;
                member_j["name"] = member->name;
                member_j.update(jsonifyComposite(member_intersection, member_ival, member->type));

                members_j.emplace_back(member_j);
            }
        }
        if (members_j.size()) {
            j["affected_members"] = members_j;
        }
    } else if (typeSpec->cat == ts_array) {
        auto arrayType = static_cast<PuT_ArrayTypeSpec *>(typeSpec);
        j["size"] = typeSpec->size;
        j["n_elems"] = arrayType->n_elems;
        j["first_overwritten_byte"] = intersection.lower() - obj_ival.lower();
        j["last_overwritten_byte"] = intersection.upper() - obj_ival.lower();

    } else {
        j["size"] = typeSpec->size;
        j["first_overwritten_byte"] = intersection.lower() - obj_ival.lower();
        j["last_overwritten_byte"] = intersection.upper() - obj_ival.lower();
    }

    return j;
}

nlohmann::ordered_json *OOBAnalyzer::generateJson() {
    auto j = new nlohmann::ordered_json();

    for (auto &[key, oobRecord] : oobWrites) {
        nlohmann::ordered_json recordJ;

        recordJ["function"] = oobRecord->func == nullptr ? "<untracked>" : oobRecord->func->name;
        recordJ["instruction"] = hexval(oobRecord->vulnSiteAddr).str();
        recordJ["pruned_call_stack"] = oobRecord->prunedCallStack;
        getInfoStream() << "Call stack for OOB write at " << hexval(oobRecord->vulnSiteAddr) << ":\n"
                        << oobRecord->callStack.str();

        for (ival_set_unsigned::iterator ow_ival = oobRecord->intervals.begin(); ow_ival != oobRecord->intervals.end();
             ow_ival++) {
            nlohmann::ordered_json rangeJ;
            rangeJ["overwrite_lower"] = hexval(ow_ival->lower()).str();
            rangeJ["overwrite_upper"] = hexval(ow_ival->upper() + 1).str();

            // Check if interval is on stack, leaving generous 2048 byte tolerance to account for red zone
            if (oobRecord->rsp - 2048 < ow_ival->lower()) {
                // TODO: We only consider objects within the stack frame here but stack-passed arguments might be
                // located outside of it
                // Iterate over all stack frames to determine affected objects
                for (auto frame_it = oobRecord->callStack.iterator_top();
                     frame_it != oobRecord->callStack.iterator_bottom(); ++frame_it) {
                    auto frame_ival = new_ival_abs(frame_it->top, frame_it->bottom);

                    auto rbp = frame_ival.upper() - 15;

                    if (!b_ival::intersects(frame_ival, *ow_ival)) {
                        // none of the overwritten addresses is in this stack frame
                        continue;
                    }
                    nlohmann::ordered_json stackFrameJ;
                    stackFrameJ["function"] = frame_it->func == nullptr ? "<untracked>" : frame_it->func->name;
                    stackFrameJ["stack_frame_bottom"] = hexval(frame_it->bottom).str();
                    stackFrameJ["stack_frame_top"] = hexval(frame_it->top).str();
                    if (frame_it->func == nullptr) {
                        continue;
                    }

                    auto frame_ow_ival_abs =
                        frame_ival & *ow_ival;  // absolute interval of affected addresses within frame
                    auto frame_ow_ival_rel =
                        new_ival_rel(frame_ow_ival_abs.lower() - rbp, frame_ow_ival_abs.upper() - rbp);
                    stackFrameJ["overwrite_lower_rel"] = frame_it->func->baseReg +
                                                         (frame_ow_ival_rel.lower() > 0 ? "+" : "") +
                                                         std::to_string(frame_ow_ival_rel.lower());
                    stackFrameJ["overwrite_upper_rel"] = frame_it->func->baseReg +
                                                         (frame_ow_ival_rel.upper() > 0 ? "+" : "") +
                                                         std::to_string(frame_ow_ival_rel.upper());

                    // Find out which objects are affected

                    struct StackFrameObject {
                        std::string name;
                        std::string addr;
                        ival_abs ival;
                        std::optional<PuT_AutoVar *> autoVar;
                    };

                    std::map<uint64_t, StackFrameObject> stackFrameObjects;
                    auto frame_unclaimed_space = new ival_set_unsigned();
                    frame_unclaimed_space->insert(frame_ival);

                    for (auto autoVar : frame_it->func->autoVars) {
                        // TODO: Could also consider the lifetime of the variables here but that gives very sparse
                        // results if (autoVar->start_pc <= oobRecord->vulnSiteAddr && oobRecord->vulnSiteAddr <
                        // autoVar->end_pc) {
                        uint64_t varSize = autoVar->fragmented ? autoVar->n_fragmentBytes : autoVar->type->size;
                        auto autoVar_ival = new_ival_abs(rbp + autoVar->relAddr, rbp + autoVar->relAddr + varSize - 1);

                        frame_unclaimed_space->subtract(autoVar_ival);
                        std::string addrStr =
                            "RBP" + std::string((autoVar->relAddr < 0 ? "" : "+")) + std::to_string(autoVar->relAddr);
                        stackFrameObjects.insert(
                            {autoVar_ival.lower(), StackFrameObject({autoVar->name, addrStr, autoVar_ival, autoVar})});
                        //}
                    }

                    // According to the System V ABI, the saved RBP/RIP are part of the called function's stack
                    // frame. We adhere to that.
                    auto savedRbp_ival = new_ival_abs(rbp, rbp + 7);
                    auto savedRip_ival = new_ival_abs(rbp + 8, rbp + 15);
                    stackFrameObjects.insert(
                        {savedRbp_ival.lower(), StackFrameObject({"<saved RBP>", "RBP", savedRbp_ival, std::nullopt})});
                    stackFrameObjects.insert({savedRip_ival.lower(),
                                              StackFrameObject({"<saved RIP>", "RBP+8", savedRip_ival, std::nullopt})});
                    frame_unclaimed_space->subtract(savedRbp_ival);
                    frame_unclaimed_space->subtract(savedRip_ival);

                    for (auto ival : *frame_unclaimed_space) {
                        auto actualIval = new_ival_abs(ival.lower() + 1, ival.upper() - 1);
                        long relAddrStart = actualIval.lower() - rbp;
                        std::string addrStr =
                            "RBP" + std::string((relAddrStart < 0 ? "" : "+")) + std::to_string(relAddrStart);
                        stackFrameObjects.insert({actualIval.lower(), StackFrameObject({"<unknown/padding>", addrStr,
                                                                                        actualIval, std::nullopt})});
                    }

                    nlohmann::ordered_json affectedObjectsJ;
                    for (auto &[absBegin, obj] : stackFrameObjects) {
                        auto intersection = obj.ival & *ow_ival;
                        if (!b_ival::is_empty(intersection)) {
                            nlohmann::ordered_json objJ;
                            objJ["name"] = obj.name;
                            objJ["startAddr"] = obj.addr;

                            if (obj.autoVar) {
                                objJ.update(jsonifyComposite(intersection, obj.ival, (*obj.autoVar)->type));
                            } else {
                                objJ["size"] = obj.ival.upper() - obj.ival.lower() + 1;
                                objJ["first_overwritten_byte"] = intersection.lower() - obj.ival.lower();
                                objJ["last_overwritten_byte"] = intersection.upper() - obj.ival.lower();
                            }

                            affectedObjectsJ.emplace_back(objJ);
                        }
                    }
                    stackFrameJ["affected_objects"] = affectedObjectsJ;

                    rangeJ["affected_stack_frames"].emplace_back(stackFrameJ);
                }
            } else {
                nlohmann::ordered_json globalVarsJ;

                struct StaticObject {
                    std::string name;
                    std::string addr;
                    ival_abs ival;
                    std::optional<PuT_StaticVar *> staticVar;
                };

                std::map<uint64_t, StaticObject> staticObjects;
                auto unclaimed_space = new ival_set_unsigned();
                unclaimed_space->insert(*ow_ival);

                // Find out which objects are affected
                for (auto staticVar : m_memTracker->put_staticVars) {
                    // if (staticVar->start_pc <= oobRecord->vulnSiteAddr && oobRecord->vulnSiteAddr <
                    // staticVar->end_pc) {
                    uint64_t varSize = staticVar->fragmented ? staticVar->n_fragmentBytes : staticVar->type->size;
                    auto staticVar_ival = new_ival_abs(staticVar->addr, staticVar->addr + varSize - 1);

                    unclaimed_space->subtract(staticVar_ival);
                    staticObjects.insert(
                        {staticVar_ival.lower(),
                         StaticObject({staticVar->name, hexval(staticVar->addr).str(), staticVar_ival, staticVar})});
                    //}
                }

                for (auto ival : *unclaimed_space) {
                    auto actualIval = new_ival_abs(ival.lower() + 1, ival.upper() - 1);
                    staticObjects.insert(
                        {actualIval.lower(), StaticObject({"<unknown/padding>", hexval(actualIval.lower()).str(),
                                                           actualIval, std::nullopt})});
                }

                nlohmann::ordered_json affectedObjectsJ;
                for (auto &[absBegin, obj] : staticObjects) {
                    auto intersection = obj.ival & *ow_ival;
                    if (!b_ival::is_empty(intersection)) {
                        nlohmann::ordered_json objJ;
                        objJ["name"] = obj.name;
                        objJ["startAddr"] = obj.addr;

                        if (obj.staticVar) {
                            objJ.update(jsonifyComposite(intersection, obj.ival, (*obj.staticVar)->type));
                        } else {
                            objJ["size"] = obj.ival.upper() - obj.ival.lower() + 1;
                            objJ["first_overwritten_byte"] = intersection.lower() - obj.ival.lower();
                            objJ["last_overwritten_byte"] = intersection.upper() - obj.ival.lower();
                        }

                        affectedObjectsJ.emplace_back(objJ);
                    }
                }
                rangeJ["affected_static_vars"].emplace_back(affectedObjectsJ);
            }
            recordJ["affected_ranges"].emplace_back(rangeJ);
        }
        j->emplace_back(recordJ);
    }

    return j;
}

void OOBAnalyzer::handleOOBWrite(S2EExecutionState *state, uint64_t addr, unsigned int accessSize,
                                 uint64_t vulnSiteAddr, const BoundsRecord &br) {
    // If we wanted to explore multiple states concurrently, we would need to protect this function with a mutex

    OOBRecord *oobRecord;

    // TODO: Create setting-depending logic here that prunes off any frames from the call stack not belonging to a
    // monitored function

    CallStack callStack = m_memTracker->getCallStack(state);
    bool prunedCallStack = false;

    while (callStack.peek()->func == nullptr) {
        vulnSiteAddr = callStack.peek()->callerAddr;
        callStack.pop();
        prunedCallStack = true;
    }

    // Determine the lookup key of the OOB write
    uint64_t key = vulnSiteAddr ^ callStack.getHash();

    // See if this OOB write already exists, otherwise create a new one
    auto it = oobWrites.find(key);
    if (it == oobWrites.end()) {
        oobRecord = new OOBRecord();
        oobRecord->key = key;
        oobRecord->callStack = callStack;
        oobRecord->func = callStack.peek()->func;
        oobRecord->vulnSiteAddr = vulnSiteAddr;
        oobRecord->rsp = state->regs()->getSp();
        oobRecord->rbp = state->regs()->getBp();
        oobRecord->prunedCallStack = prunedCallStack;
        oobWrites.insert({key, oobRecord});
    } else {
        oobRecord = it->second;
    }

    uint64_t accessLower = addr;                   // lowest absolute address of the access
    uint64_t accessUpper = addr + accessSize - 1;  // highest absolute address of the access
    uint64_t overwriteLower = (br.lower <= accessLower && accessLower <= br.upper) ? br.upper + 1 : accessLower;
    uint64_t overwriteUpper = (br.lower <= accessUpper && accessUpper <= br.upper) ? br.lower - 1 : accessUpper;

    oobRecord->intervals.insert(ival_set_unsigned::interval_type::closed(overwriteLower, overwriteUpper));
}

}  // namespace plugins
}  // namespace s2e