#include "OOBCollector.h"

#include <unistd.h>

#include <fstream>
#include <set>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Operator.h"

#define RAW(s) dbgs() << s << "\n";
#define INFO(s) dbgs() << "\033[34m" << s << "\033[0m\n";
#define WARN(s) dbgs() << "\033[31m" << s << "\033[0m\n";

#define DEBUG_TYPE "oob-collector"

STATISTIC(N_STATIC_WRITES_NO_DEBUG, "Number of static writes without debug information");
STATISTIC(N_BNIS_NO_DEBUG, "Number of bounds narrowing instructions without debug information");

STATISTIC(N_DYNAMIC_BNIS, "Number of dynamic bounds narrowing instructions discovered");
STATISTIC(N_BNIS_MULTIPLE_GEP_AT_SAME_IR_INST,
          "Number of instructions that have more than one bounds narrowing instruction in them");
STATISTIC(N_BNIS_BOUNDS_SHIFTING, "Number of bounds shifting instructions");

void to_json(json &j, const PuT_IRMemModInst &putMemModInst) {
    j["instStr"] = putMemModInst.instStr;
    j["hasDebugInfo"] = putMemModInst.hasDebugInfo;
    j["srcLine"] = (putMemModInst.hasDebugInfo) ? putMemModInst.srcLine : -1;
    j["srcColumn"] = (putMemModInst.hasDebugInfo) ? putMemModInst.srcColumn : -1;
    j["srcFileName"] = (putMemModInst.hasDebugInfo) ? putMemModInst.srcFileName : "";
    j["isStaticWrite"] = putMemModInst.isStaticWrite;
    j["staticWriteToLocalVar"] = (putMemModInst.isStaticWrite) ? putMemModInst.staticWriteToLocalVar : false;
    j["staticWriteToAutoVar"] = (putMemModInst.isStaticWrite) ? putMemModInst.staticWriteToAutoVar : false;
    j["staticWriteDstInternalName"] = putMemModInst.staticWriteDstInternalName;
    j["staticWriteDstActualName"] = putMemModInst.staticWriteDstActualName;
    j["boundsNarrowingIndices"] = putMemModInst.boundsNarrowingIndices;
}

void to_json(json &j, const PuT_IRBoundsNarrowingInst &putBoundsNarrowingInst) {
    j["instStr"] = putBoundsNarrowingInst.instStr;
    j["hasDebugInfo"] = putBoundsNarrowingInst.hasDebugInfo;
    j["srcLine"] = (putBoundsNarrowingInst.hasDebugInfo) ? putBoundsNarrowingInst.srcLine : -1;
    j["srcColumn"] = (putBoundsNarrowingInst.hasDebugInfo) ? putBoundsNarrowingInst.srcColumn : -1;
    j["srcFileName"] = (putBoundsNarrowingInst.hasDebugInfo) ? putBoundsNarrowingInst.srcFileName : "";
    j["hasAltDebugInfo"] = putBoundsNarrowingInst.hasAltDebugInfo;
    j["altSrcLine"] = (putBoundsNarrowingInst.hasAltDebugInfo) ? putBoundsNarrowingInst.altSrcLine : -1;
    j["altSrcColumn"] = (putBoundsNarrowingInst.hasAltDebugInfo) ? putBoundsNarrowingInst.altSrcColumn : -1;
    j["altSrcFileName"] = (putBoundsNarrowingInst.hasAltDebugInfo) ? putBoundsNarrowingInst.altSrcFileName : "";
    j["narrowingFieldIndices"] = putBoundsNarrowingInst.narrowingFieldIndices;
    j["typeMnemonic"] = putBoundsNarrowingInst.typeMnemonic;
}

void to_json(json &j, const PuT_IRFunction &putFunction) {
    j["name"] = putFunction.name;
    j["uniqueName"] = putFunction.uniqueName;
    j["srcFileName"] = putFunction.srcFileName;
    j["memModInsts"] = putFunction.memModInsts;
    j["boundsNarrowingInsts"] = putFunction.boundsNarrowingInsts;
}

#define ADJUST_LINE_DBG_INFO 1
#define BNI_ADD_ALT_DBG_INFO 1

#ifdef ADJUST_LINE_DBG_INFO
#define DBG_LINE_MAX 65535
#define DBG_COLUMN_MAX 65535

std::map<std::string, std::string> syntheticDebugInfoLUT;

static void checkLineNumberDebugInfo(Instruction *I, bool forceModification = false) {
    static std::map<std::string, std::set<std::pair<unsigned, unsigned>>> seenLocs;
    static std::map<std::string, std::pair<unsigned, unsigned>> synthDbgLocCtr;

    static std::set<Instruction *> synthesizedDebugLocInsts;

    if (synthesizedDebugLocInsts.count(I)) {
        // We already added synthetic debug info to this instruction, don't do it again
        return;
    }

    auto dbgLoc = I->getDebugLoc();
    auto funcDbg = dyn_cast_or_null<DISubprogram>(I->getFunction()->getMetadata("dbg"));
    std::string filename = std::string(funcDbg->getFilename());

    unsigned lineOrig = 0;
    unsigned columnOrig = 0;
    if (dbgLoc) {
        assert(filename == std::string(dbgLoc->getFilename()));
        lineOrig = dbgLoc->getLine();
        columnOrig = dbgLoc->getColumn();

        if (!forceModification) {
            if (seenLocs[filename].count({lineOrig, columnOrig}) == 0) {
                seenLocs[filename].insert({lineOrig, columnOrig});
                return;
            }
        }
    }

    if (!synthDbgLocCtr.count(filename)) {
        synthDbgLocCtr[filename] = {DBG_LINE_MAX, DBG_COLUMN_MAX};
    }

    unsigned line = synthDbgLocCtr[filename].first;
    unsigned column = synthDbgLocCtr[filename].second;

    std::string origDbgInfoStr = filename + ":" + std::to_string(lineOrig) + ":" + std::to_string(columnOrig);
    std::string newDbgInfoStr = filename + ":" + std::to_string(line) + ":" + std::to_string(column);
    syntheticDebugInfoLUT.insert({newDbgInfoStr, origDbgInfoStr});

    // WARN("setting debug loc: " << line << " " << column << "\n");

    I->setDebugLoc(DILocation::get(I->getContext(), line, column, funcDbg));
    seenLocs[filename].insert({line, column});
    synthesizedDebugLocInsts.insert(I);

    synthDbgLocCtr[filename].first--;
    if (synthDbgLocCtr[filename].first == 0) {
        synthDbgLocCtr[filename].second--;
        synthDbgLocCtr[filename].first = DBG_COLUMN_MAX;
        assert(synthDbgLocCtr[filename].second > 0);
    }
}
#endif

// Checks if the given type contains a structure somewhere in its memory space
static bool containsStructRec(Type *t) {
    if (isa<StructType>(t)) {
        return true;
    } else if (ArrayType *AT = dyn_cast<ArrayType>(t)) {
        return containsStructRec(AT->getElementType());
    } else {
        // Any other type cannot contain a struct - also no pointer type
        return false;
    }
}

// Inspect the GEP instruction for whether it is a bounds narrowing instruction, i.e., it takes a pointer to a composite
// memory object and returns a pointer to one of its child-objects. If so, return true and populate
// boundsNarrowingIndices with the indices of the element to which the bounds are narrowed at each step
//
static bool inspectBoundsNarrowingInstRec(GEPOperator *GEP, Type *idx_pos_type, unsigned idx_pos,
                                          std::vector<int> *boundsNarrowingIndices) {
    if (idx_pos == GEP->getNumIndices()) {
        // We handled all indices, nothing left to do
        return false;
    }

    Value *idx = GEP->getOperand(1 + idx_pos);  // getOperand(0) is always the pointer, hence +1

    if (idx_pos_type->isPointerTy()) {
        // It should never happen that a GEP dereferences a pointer besides the very first one, as that would require
        // accessing memory, right?
        assert(idx_pos == 0);

        if (!inspectBoundsNarrowingInstRec(GEP, idx_pos_type->getContainedType(0), idx_pos + 1,
                                           boundsNarrowingIndices)) {
            return false;
        }

        if (!isa<ConstantInt>(idx)) {
            N_DYNAMIC_BNIS++;
            throw std::runtime_error("Dynamic bounds narrowing detected");
        }
        // TODO: Could build in detection for structPtr++ operations here to eliminate FPs when arrays can be composite
        // objects. If the value below is not 0, there is an offset to the pointer being calculated
        if (dyn_cast<ConstantInt>(idx)->getSExtValue() != 0) {
            N_BNIS_BOUNDS_SHIFTING++;
            throw std::runtime_error("Bounds shifting instruction detected");
        }

        return true;

    } else if (StructType *ST = dyn_cast<StructType>(idx_pos_type)) {
        // If GEP indexes a struct, we know for sure it's a bounds narrowing instruction, no matter what happens further
        // down
        assert(isa<ConstantInt>(idx));
        auto idx_int = dyn_cast<ConstantInt>(idx)->getSExtValue();
        boundsNarrowingIndices->push_back(idx_int);
        inspectBoundsNarrowingInstRec(GEP, ST->getElementType(idx_int), idx_pos + 1, boundsNarrowingIndices);
        return true;

    } else if (ArrayType *AT = dyn_cast<ArrayType>(idx_pos_type)) {
        auto idxConst = dyn_cast<ConstantInt>(idx);
        if (idxConst) {
            // need to add the field here already to have it in the right position
            boundsNarrowingIndices->push_back(idxConst->getSExtValue());
        }

        // Check if there is a struct in the array that justifies not treating it as a continuous chunk of memory
        if (inspectBoundsNarrowingInstRec(GEP, AT->getElementType(), idx_pos + 1, boundsNarrowingIndices) ||
            (idx_pos + 1 == GEP->getNumIndices() && containsStructRec(idx_pos_type))) {
            if (idxConst) {
                return true;
            } else {
                // There is a struct somewhere in it but the index into the array is not constant
                // We cannot handle dynamic bounds narrowing, requires run time information
                // WARN("Discovered dynamic bounds narrowing site: " << *U);
                // INFO(boundsNarrowingIndices->size());
                N_DYNAMIC_BNIS++;
                throw std::runtime_error("Dynamic bounds narrowing detected");
            }
        }

        if (idxConst) {
            // remove the field we added earlier
            boundsNarrowingIndices->pop_back();
        }
        return false;
    } else {
        return false;
    }
}

static Optional<std::vector<int>> getBoundsNarrowingIndices(GEPOperator *GEPO) {
    std::vector<int> boundsNarrowingIndices;
    if (inspectBoundsNarrowingInstRec(GEPO, GEPO->getOperand(0)->getType(), 0, &boundsNarrowingIndices)) {
        return boundsNarrowingIndices;
    }
    return None;
}

/**
 *
 */
static void findMemModDst(PuT_IRMemModInst *putMMI) {
    Value *currVal = putMMI->immDst;

    while (true) {
        if (GEPOperator *GEPO = dyn_cast<GEPOperator>(currVal)) {  // Includes both GEPO and GEPI
            currVal = cast<Value>(GEPO->getPointerOperand());
            // WARN("gepo" << putMMI->boundsNarrowingIndices.size());

            try {
                if (auto boundsNarrowingIndices_o = getBoundsNarrowingIndices(GEPO)) {
                    // We're traversing the chain upwards, hence we add the indices at the beginning of the existing
                    // vector
                    putMMI->boundsNarrowingIndices.insert(putMMI->boundsNarrowingIndices.begin(),
                                                          boundsNarrowingIndices_o->begin(),
                                                          boundsNarrowingIndices_o->end());
                }
            } catch (std::runtime_error &e) {
                // need to wipe the bounds narrowing instructions so far, which correspond to the narrowest narrowing.
                // The ones to come do wider narrowing.
                putMMI->boundsNarrowingIndices.clear();
                (void)e;
            }

        } else if (AllocaInst *AI = dyn_cast<AllocaInst>(currVal)) {
            // We arrived at an automatic variable allocated on the stack

            putMMI->isStaticWrite = true;
            putMMI->staticWriteDst = AI;
            putMMI->staticWriteToAutoVar = true;
            putMMI->staticWriteDstInternalName = std::string(AI->getName());
            putMMI->staticWriteToLocalVar = true;
            break;

        } else if (GlobalVariable *GV = dyn_cast<GlobalVariable>(currVal)) {
            // We arrived at a global variable

            putMMI->isStaticWrite = true;
            putMMI->staticWriteDst = GV;
            putMMI->staticWriteToAutoVar = false;
            putMMI->staticWriteDstInternalName = std::string(GV->getName());
            if (auto DIGVE = dyn_cast_or_null<DIGlobalVariableExpression>(GV->getMetadata("dbg"))) {
                putMMI->staticWriteDstActualName = std::string(DIGVE->getVariable()->getName());
                putMMI->staticWriteToLocalVar = DIGVE->getVariable()->isLocalToUnit();
            }
            // INFO(putMMI->instStr);
            // INFO(putMMI->boundsNarrowingIndices.size());
            // assert(putMMI->staticWriteDstInternalName != "dyn_ltree");
            break;

        } else if (dyn_cast<LoadInst>(currVal)) {
            // We arrived at a load instruction, hence the destination of the store is a pointer obtained from memory
            putMMI->isStaticWrite = false;
            break;

        } else if (BitCastOperator *BCO = dyn_cast<BitCastOperator>(currVal)) {
            currVal = cast<Value>(BCO->getOperand(0));

        } else if (CastInst *CI = dyn_cast<CastInst>(currVal)) {
            currVal = cast<Value>(CI->getOperand(0));

        } else if (dyn_cast<PHINode>(currVal)) {
            putMMI->isStaticWrite = false;
            // TODO: Should trace further upwards here and check whether the options are the same object
            break;

        } else if (dyn_cast<CallInst>(currVal)) {
            // A store to the return value of a function is always dynamic
            putMMI->isStaticWrite = false;
            break;

        } else if (Argument *A = dyn_cast<Argument>(currVal)) {
            if (A->hasByValAttr()) {
                // aggregate type argument that is passed on the stack (at the top of the caller's frame)
                putMMI->isStaticWrite = true;
            } else {
                putMMI->isStaticWrite = false;
            }
            break;

        } else if (dyn_cast<SelectInst>(currVal)) {
            putMMI->isStaticWrite = false;
            // TODO: Should trace further upwards here and check whether the options are the same object
            break;
        }

        else {
            WARN("\n\nFailed to proceed at instruction ");
            currVal->dump();
            WARN("originating from instruction " << putMMI->instStr << "\n\n\n");

            assert(false);
        }
    }
}

static Optional<PuT_IRMemModInst> checkIfStaticWrite(Instruction *MMI) {
    PuT_IRMemModInst putMemModInst = {};
    putMemModInst.inst = MMI;
    std::string instStr;
    llvm::raw_string_ostream(instStr) << *MMI;
    putMemModInst.instStr = instStr;
    // INFO("Looking at memory-modifying instruction " << instStr);

    if (StoreInst *SI = dyn_cast<StoreInst>(MMI)) {
        putMemModInst.immDst = cast<Value>(SI->getPointerOperand());
    } else if (MemIntrinsic *MI = dyn_cast<MemIntrinsic>(MMI)) {
        putMemModInst.immDst = cast<Value>(MI->getOperand(0));
    } else {
        assert(false && "not implemented");
    }

    findMemModDst(&putMemModInst);

    if (!putMemModInst.isStaticWrite) {
        return None;
    }

#ifdef ADJUST_LINE_DBG_INFO
    // TODO: Maybe it's smarter to do this for all instructions to ensure there are no lineinfo duplicates?
    checkLineNumberDebugInfo(MMI, true);
#endif

    putMemModInst.hasDebugInfo = false;
    if (auto debugInfo = MMI->getMetadata("dbg")) {
        auto memModDILoc = dyn_cast<DILocation>(debugInfo);

        putMemModInst.srcFileName = std::string(memModDILoc->getFile()->getFilename());
        putMemModInst.srcLine = memModDILoc->getLine();
        putMemModInst.srcColumn = memModDILoc->getColumn();

        putMemModInst.hasDebugInfo = true;
    } else {
        N_STATIC_WRITES_NO_DEBUG++;
        return None;
    }

    return putMemModInst;
}

/*
 *
 */
static bool isBoundsNarrowingInstUseInterestingRec(Use *U, std::vector<Use *> &hist) {
    User *user = U->getUser();
    unsigned operandNo = U->getOperandNo();

    if (isa<LoadInst>(user)) {
        return false;
    } else if (isa<CallInst>(user)) {
        return true;
    } else if (auto SI = dyn_cast<StoreInst>(user)) {
        if (operandNo == 1) {
            PuT_IRMemModInst dummyMMI = {};
            dummyMMI.inst = SI;
            dummyMMI.immDst = cast<Value>(SI->getPointerOperand());
            findMemModDst(&dummyMMI);
            if (dummyMMI.isStaticWrite) {
                return false;  // Use is a destination operand of a static write, not interesting
            }
        }
        return true;  // can be used either as destination or data to be stored, both are interesting
    } else if (isa<GetElementPtrInst>(user)) {
        // if it's used as an index, the GEP is, if any, a dynamic BNI and we don't care
        if (operandNo != 0) {
            return false;
        }
    } else if (isa<ICmpInst>(user)) {
        return false;
    } else if (isa<ReturnInst>(user)) {
        return true;
    } else if (isa<BranchInst>(user)) {
        return false;
    } else if (isa<SelectInst>(user)) {
        if (operandNo == 0) {  // it's the condition on which is selected
            return false;
        }
    } else if (isa<CastInst>(user)) {
    } else if (isa<BinaryOperator>(user)) {
        // TODO: Could do more filtering here, e.g. to filter out cases where a int representing a pointer is subtracted
        // from another int representing a pointer, creating an offset that isn't a valid pointer anymore
    } else if (isa<PHINode>(user)) {
    }

    else {
        WARN(*(U->get()));
        WARN(*user);
        assert(false && "not implemented");
    }

    hist.emplace_back(U);

    bool res = false;
    for (auto &use : user->uses()) {
        // Only recurse if the user is not in the history (prevent infinite recursion)
        if (std::find(hist.begin(), hist.end(), &use) == hist.end()) {
            res |= isBoundsNarrowingInstUseInterestingRec(&use, hist);
        }
    }

    hist.pop_back();
    return res;
}

static bool isBoundsNarrowingInstUseInterestingRec(Use *U) {
    std::vector<Use *> hist;
    return isBoundsNarrowingInstUseInterestingRec(U, hist);
}

/*
 * To be called from collectGEPOperators()
 * firstUse is the use constituting the edge between the Instruction and the first operator in the chain
 */
static void collectGEPOperatorsRec(User *U, Use *firstUse, std::vector<std::pair<GEPOperator *, Use *>> &gepoUsePairs) {
    if (isa<GEPOperator>(U) && !isa<GetElementPtrInst>(U)) {  // GetElementPtrInst is also a GEPOperator, sort out
        GEPOperator *GEPO = static_cast<GEPOperator *>(U);
        gepoUsePairs.emplace_back(GEPO, firstUse);
    }

    for (auto &use : U->operands()) {
        User *operand = dyn_cast<User>(use.get());

        // Instructions also cast to Operand, hence we must filter
        if (operand && !isa<Instruction>(operand) && isa<Operator>(operand)) {
            collectGEPOperatorsRec(operand, firstUse, gepoUsePairs);
        }
    }
}

/*
 * For the given instruction, find all GEPOperators it recursively uses and append them paired with the Use between the
 * given instruction and the first operator use. This first oeprator use might not be the GEPOperator yet.
 */
static void collectGEPOperators(Instruction *I, std::vector<std::pair<GEPOperator *, Use *>> &gepoUsePairs) {
    for (auto &use : I->operands()) {
        User *operand = dyn_cast<User>(use.get());

        // Instructions also cast to Operand, hence we must filter
        if (operand && !isa<Instruction>(operand) && isa<Operator>(operand)) {
            collectGEPOperatorsRec(operand, &use, gepoUsePairs);
        }
    }
}

/*
 * Given a GEP instruction or operator, creates and returns a mnemonic string for the type that is narrowed by the GEP.
 * Example: somestruct[2][67] becomes <2><67>somestruct
 */
// TODO: It would be nicer to get the struct names from the debug info
static std::string getGepSubjectTypeMnemonic(GEPOperator *GEP) {
    std::stringstream name;

    auto subjectType = GEP->getSourceElementType();
    while (subjectType->isArrayTy()) {
        auto arrayType = dyn_cast<ArrayType>(subjectType);
        // Array types never have names, hence we have to improvise the names
        name << "<" << arrayType->getNumElements() << ">";
        subjectType = arrayType->getElementType();
    }

    assert(subjectType->isStructTy());

    // Append the name of the struct to the end of the mnemonic
    auto structType = dyn_cast<StructType>(subjectType);
    if (!structType->hasName()) {
        WARN("Struct " << *structType << " does not have a name, cannot create mnemonic");
        return "";
    }
    name << std::string(structType->getName()).substr(std::string("struct.").length());
    return name.str();
}

/*
 * If the instruction is a bounds narrowing instruction, analyze it and return the corresponding container struct
 * We check both for GEP Instructions and GEP Operators
 */
static bool getPutBoundsNarrowingInst(Instruction *I, PuT_IRBoundsNarrowingInst &bni) {
    int n_geps = 0;
    std::vector<PuT_IRBoundsNarrowingInst> bnis;

    // Find all the GEPOs that this instruction depends on, add them to the collection if they seem interesting
    std::vector<std::pair<GEPOperator *, Use *>> gepoUsePairs;
    collectGEPOperators(I, gepoUsePairs);
    for (auto gepoUsePair : gepoUsePairs) {
        n_geps++;
        try {
            if (auto boundsNarrowingIndices_o = getBoundsNarrowingIndices(gepoUsePair.first)) {
                if (isBoundsNarrowingInstUseInterestingRec(gepoUsePair.second)) {
                    assert(boundsNarrowingIndices_o->size());

                    PuT_IRBoundsNarrowingInst putBoundsNarrowingInst = {};
                    putBoundsNarrowingInst.narrowingFieldIndices = *boundsNarrowingIndices_o;
                    putBoundsNarrowingInst.typeMnemonic = getGepSubjectTypeMnemonic(gepoUsePair.first);
                    bnis.emplace_back(putBoundsNarrowingInst);
                }
            }
        } catch (std::runtime_error &e) {
            // dynamic bounds narrowing instruction, not supported
            (void)e;
        }
    }

    // Check if the instruction itself is a GEPO (actually, a GEPI)
    if (auto GEPO = dyn_cast<GEPOperator>(I)) {
        n_geps++;
        try {
            if (auto boundsNarrowingIndices_o = getBoundsNarrowingIndices(GEPO)) {
                bool isInteresting = false;
                for (auto &use : GEPO->uses()) {
                    isInteresting |= isBoundsNarrowingInstUseInterestingRec(&use);
                }
                if (isInteresting) {
                    assert(boundsNarrowingIndices_o->size());

                    PuT_IRBoundsNarrowingInst putBoundsNarrowingInst = {};
                    putBoundsNarrowingInst.narrowingFieldIndices = *boundsNarrowingIndices_o;
                    putBoundsNarrowingInst.typeMnemonic = getGepSubjectTypeMnemonic(GEPO);
                    bnis.emplace_back(putBoundsNarrowingInst);
                }
            }
        } catch (std::runtime_error &e) {
            // dynamic bounds narrowing instruction, not supported
            (void)e;
        }
    }

    if (bnis.size() == 0) {
        return false;
    } else if (n_geps > 1) {
        N_BNIS_MULTIPLE_GEP_AT_SAME_IR_INST += bnis.size();
        return false;
    }
    assert(bnis.size() == 1);

#ifdef ADJUST_LINE_DBG_INFO
    checkLineNumberDebugInfo(I, true);
#endif

    if (auto debugInfo = I->getMetadata("dbg")) {
        auto memModDILoc = dyn_cast<DILocation>(debugInfo);
        bni = bnis[0];

        bni.srcFileName = std::string(memModDILoc->getFile()->getFilename());
        bni.srcLine = memModDILoc->getLine();
        bni.srcColumn = memModDILoc->getColumn();
        bni.hasDebugInfo = true;

#ifdef BNI_ADD_ALT_DBG_INFO
        // TODO: Could also trace further than just the immediate use and add multiple alternative locations
        if (isa<GEPOperator>(I) && I->hasOneUser()) {
            if (auto userInst = dyn_cast<Instruction>(*I->users().begin())) {
                checkLineNumberDebugInfo(userInst, true);
                auto dILoc = dyn_cast<DILocation>(userInst->getMetadata("dbg"));
                bni.altSrcFileName = std::string(dILoc->getFile()->getFilename());
                bni.altSrcLine = dILoc->getLine();
                bni.altSrcColumn = dILoc->getColumn();
                bni.hasAltDebugInfo = true;
                return true;
            }
        }
#endif
        bni.hasAltDebugInfo = false;
        return true;
    } else {
        N_BNIS_NO_DEBUG++;
        return false;
    }
}

static bool runOOBCollectorOnModule(Module &M) {
    std::vector<PuT_IRFunction> putFunctions;

    WARN("Running OOBCollector...");

    EnableStatistics(false);

    for (Function &F : M) {
        if (F.isIntrinsic() || F.isDeclaration()) {
            continue;
        }

        std::string funName = std::string(F.getName());
        // LLVM_DEBUG(dbgs() << "Entering function " + funName + "\n");

        PuT_IRFunction putFunction;

        putFunction.uniqueName = funName;
        // DIScope *dbgFunctionScope;

        if (auto DIS = dyn_cast_or_null<DISubprogram>(F.getMetadata("dbg"))) {
            putFunction.name = std::string(DIS->getName());
            putFunction.srcFileName = std::string(DIS->getFilename());
            // dbgFunctionScope = DIS->getScope();
        } else {
            WARN(F);
            assert(false && "Function has no debug information, can't get name and file name");
        }

        // maps Values to their original variable names, extracted from llvm.dbg.declare intrinsics
        std::map<std::string, std::string> valsToAutoVarNames;

        // GEPOperators we collect
        std::vector<GEPOperator *> gepos;

        for (Instruction &I : instructions(F)) {
            // Check for bounds-narrowing instructions
            PuT_IRBoundsNarrowingInst bni;
            if (getPutBoundsNarrowingInst(&I, bni)) {
                putFunction.boundsNarrowingInsts.emplace_back(bni);
            }

            if (isa<StoreInst>(&I) || isa<MemIntrinsic>(&I)) {
                // MemIntrinsic covers llvm.memcpy, llvm.memcpy.inline, llvm.memmove, llvm.memset
                if (auto mmi = checkIfStaticWrite(&I)) {
                    putFunction.memModInsts.push_back(*mmi);
                }
            } else if (dyn_cast<AtomicCmpXchgInst>(&I) || dyn_cast<AtomicRMWInst>(&I)) {
                assert(false && "AtomicCmpXchgInst and AtomicRMWInst are not supported!");
            } else if (DbgDeclareInst *DDI = dyn_cast<DbgDeclareInst>(&I)) {
                valsToAutoVarNames.insert(
                    {std::string(DDI->getAddress()->getName()), std::string(DDI->getVariable()->getName())});
            } else if (CallInst *CI = dyn_cast<CallInst>(&I)) {
                if (CI->isTailCall()) {
                    assert(false && "Tail calls are not supported!");
                }
            }
            // TODO: Could build in checks for other memory-modifying instructions we don't support:
            // llvm.memcpy.inline.* llvm.matrix.column.major.store.* llvm.vp.store llvm.masked.store.*
            // llvm.masked.scatter.* llvm.vp.scatter llvm.masked.compressstore llvm.memmove.element.unordered.atomic
            // llvm.memset.unordered.atomic, atomicrmw, cmpxchg
        }

        // Automatic variables do not have debug information attached to their alloca() calls, hence we need to pull
        // their names from the debug.declare calls for which we colelcted the debug info earlier
        for (auto memModInstIt = putFunction.memModInsts.begin(); memModInstIt != putFunction.memModInsts.end();
             ++memModInstIt) {
            if (!memModInstIt->isStaticWrite || memModInstIt->staticWriteDstActualName != "") {
                continue;
            }
            auto nameIt = valsToAutoVarNames.find(std::string(memModInstIt->staticWriteDst->getName()));
            if (nameIt != valsToAutoVarNames.end()) {
                memModInstIt->staticWriteDstActualName = nameIt->second;
            }
        }

        putFunctions.push_back(putFunction);
    }

    json j;
    j["putFunctions"] = putFunctions;
    j["syntheticDbgInfo"] = syntheticDebugInfoLUT;

    std::string moduleID = M.getSourceFileName();
    moduleID = moduleID.substr(moduleID.find_last_of("/") + 1);

    auto cwd = std::string(get_current_dir_name());
    auto resFilePath = cwd + "/pass-res-" + moduleID + ".json";

    std::ofstream resFile(resFilePath);
    resFile << j.dump(2) << std::endl;
    resFile.close();
    INFO("Wrote OOBCollector results to " + resFilePath);

    std::string statsNew;
    llvm::raw_string_ostream statsNewStream(statsNew);
    PrintStatisticsJSON(statsNewStream);
    statsNewStream.flush();

    auto j_statsNew = json::parse(statsNew);

    std::string statsFilePath = cwd + "/pass-stats.json";

    std::ifstream statsFileIn;
    statsFileIn.open(statsFilePath);
    if (statsFileIn.is_open()) {
        json j_statsOld = json::parse(statsFileIn);

        for (auto el : j_statsOld.items()) {
            if (!j_statsNew.contains(el.key())) {
                j_statsNew[el.key()] = 0;
            }
            j_statsNew[el.key()] = j_statsNew[el.key()].get<int>() + el.value().get<int>();
        }
    }
    statsFileIn.close();

    std::ofstream statsOut(statsFilePath);
    statsOut << j_statsNew.dump(2) << std::endl;
    statsOut.close();

    INFO(j_statsNew.dump(2));

#ifdef ADJUST_LINE_DBG_INFO
    return true;
#else
    return false;
#endif
}

// --------------------------------------------------------------------------------------
// Boilerplate code

#ifdef ADJUST_LINE_DBG_INFO
bool isAnalysis = false;
#else
bool isAnalysis = true;
#endif

#ifdef OLD_PASSMANAGER

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

struct LegacyOOBCollectorPass : public ModulePass {
    static char ID;
    LegacyOOBCollectorPass() : ModulePass(ID) {}

    bool runOnModule(Module &M) override { return runOOBCollectorOnModule(M); }
};

char LegacyOOBCollectorPass::ID = 0;

static RegisterPass<LegacyOOBCollectorPass> X("oobcollector", "OOBCollector Pass", false /* Only looks at CFG */,
                                              isAnalysis);

// Register the pass to run after all optimizations when the optimization level is != -O0
static RegisterStandardPasses Y(PassManagerBuilder::EP_OptimizerLast,
                                [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
                                    PM.add(new LegacyOOBCollectorPass());
                                });

// Register the pass to run when the optimization level is == -O0
static RegisterStandardPasses Z(PassManagerBuilder::EP_EnabledOnOptLevel0,
                                [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
                                    PM.add(new LegacyOOBCollectorPass());
                                });

#else

PreservedAnalyses OOBCollectorPass::run(Module &M, ModuleAnalysisManager &AM) {
    runOOBCollectorOnModule(M);

    return PreservedAnalyses::all();
}

llvm::PassPluginLibraryInfo llvm::getOOBCollectorPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "OOBCollector", LLVM_VERSION_STRING, [](PassBuilder &PB) {
                PB.registerPipelineParsingCallback(
                    [](StringRef Name, ModulePassManager &FPM, ArrayRef<PassBuilder::PipelineElement>) {
                        if (Name == "oob-collector") {
                            FPM.addPass(OOBCollectorPass());
                            return true;
                        }
                        return false;
                    });
            }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return getOOBCollectorPluginInfo();
}

#endif