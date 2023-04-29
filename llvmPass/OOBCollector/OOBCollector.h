#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_OOBCOLLECTOR_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_OOBCOLLECTOR_H

#include <nlohmann/json.hpp>

#include "llvm/IR/Module.h"

#define OLD_PASSMANAGER

#ifndef OLD_PASSMANAGER
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#endif

using json = nlohmann::json;
using namespace llvm;

struct PuT_IRMemModInst {
    Instruction *inst;
    Value *immDst;  // immediate destination, as present in the instruction's string representation
    std::string instStr;
    bool hasDebugInfo;
    int srcLine;
    int srcColumn;
    std::string srcFileName;
    bool isStaticWrite;
    bool staticWriteToLocalVar;
    bool staticWriteToAutoVar;
    Value *staticWriteDst;
    std::string staticWriteDstInternalName = "";
    std::string staticWriteDstActualName = "";
    std::vector<int> boundsNarrowingIndices = std::vector<int>();
};

struct PuT_IRBoundsNarrowingInst {
    std::string instStr;
    bool hasDebugInfo;
    int srcLine;
    int srcColumn;
    std::string srcFileName;
    bool hasAltDebugInfo;
    int altSrcLine;
    int altSrcColumn;
    std::string altSrcFileName;
    std::vector<int> narrowingFieldIndices;
    std::string typeMnemonic;
};

struct PuT_IRFunction {
    std::string name;
    std::string uniqueName;
    std::string srcFileName;
    std::vector<PuT_IRMemModInst> memModInsts;
    std::vector<PuT_IRBoundsNarrowingInst> boundsNarrowingInsts;
};

void to_json(json &j, const PuT_IRMemModInst &putMemModInst);
void to_json(json &j, const PuT_IRBoundsNarrowingInst &putBoundsNarrowingInst);
void to_json(json &j, const PuT_IRFunction &putFunction);

namespace llvm {

#ifndef OLD_PASSMANAGER

class OOBCollectorPass : public PassInfoMixin<OOBCollectorPass> {
   public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
    // static bool isRequired() { return true; }
};

llvm::PassPluginLibraryInfo getOOBCollectorPluginInfo();
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo();

#endif

}  // end namespace llvm

#endif  // LLVM_TRANSFORMS_INSTRUMENTATION_DOOBWDETECTION_H
