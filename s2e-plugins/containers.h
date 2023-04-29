#ifndef S2E_PLUGINS_OOBCONTAINERS_H
#define S2E_PLUGINS_OOBCONTAINERS_H

#include <s2e/Utils.h>

#include <boost/container_hash/hash.hpp>
#include <nlohmann/json.hpp>

#include "util.h"

using json = nlohmann::json;

namespace s2e {
namespace plugins {

enum PuT_TypeSpecCat { ts_generic, ts_struct, ts_array };

struct PuT_GenericTypeSpec {
    PuT_TypeSpecCat cat;
    std::string name;
    uint64_t dwarfOffset;
    size_t size;
    std::string mnemonic;  // Only relevant for array and struct
};
void from_json(const json &j, PuT_GenericTypeSpec &ts);

struct PuT_StructMember {
    std::string name;
    uint64_t typeSpecDwarfOffset;
    PuT_GenericTypeSpec *type;
};

struct PuT_StructTypeSpec : PuT_GenericTypeSpec {
    std::map<size_t, PuT_StructMember *> members;  // key is offset from struct base
};
void from_json(const json &j, PuT_StructTypeSpec &ts);

struct PuT_ArrayTypeSpec : PuT_GenericTypeSpec {
    size_t n_elems;
    uint64_t elemTypeSpecDwarfOffset;
    PuT_GenericTypeSpec *elemType;  // TODO: Add field for stride?
};
void from_json(const json &j, PuT_ArrayTypeSpec &ts);

struct PuT_Var {
    std::string name;
    uint64_t dwarfOffset;
    uint64_t typeSpecDwarfOffset;
    PuT_GenericTypeSpec *type;
    bool fragmented;
    int n_fragmentBytes;
    bool local;
    bool inlined;
    std::string inlined_fun_name;
    uint64_t start_pc;
    uint64_t end_pc;

    // We need this to make it polymorphic and allow dynamic casts
    virtual ~PuT_Var() {}
};

struct PuT_AutoVar : PuT_Var {
    long relAddr;
};
void from_json(const json &j, PuT_AutoVar &var);

struct PuT_StaticVar : PuT_Var {
    uint64_t addr;
    virtual ~PuT_StaticVar() {}
};
void from_json(const json &j, PuT_StaticVar &var);

struct PuT_StaticWrite {
    uint64_t addr;
    bool staticWriteToAutoVar;
    uint64_t dstVarDwarfOffset;
    PuT_Var *dstVar;
    // std::vector<PuT_Var *> dstVars;
    union {
        long rel;      // if staticWriteToAutoVar
        uint64_t abs;  // else
    } lowerBound;
    union {
        long rel;      // if staticWriteToAutoVar
        uint64_t abs;  // else
    } upperBound;
};
void from_json(const json &j, PuT_StaticWrite &w);

struct PuT_BoundsNarrowingInst {
    uint64_t addr;
    std::string resReg;
    std::vector<unsigned> narrowingFieldIndices;
    std::string typeMnemonic;
};
void from_json(const json &j, PuT_BoundsNarrowingInst &bni);

struct PuT_Function {
    std::string name;
    uint64_t dwarfOffset;
    uint64_t baseAddress;
    std::string baseReg;
    // std::map<long, PuT_AutoVar *> autoVars;
    //  This being a vector really isn't great, should be a map to make lookup faster. But we need a multi-index map
    //  (spatial and temporal), too complex for now.
    std::vector<PuT_AutoVar *> autoVars;
    std::map<uint64_t, PuT_StaticWrite *> staticWrites;
    std::map<uint64_t, PuT_BoundsNarrowingInst *> boundsNarrowingInsts;
};
void from_json(const json &j, PuT_Function &func);

struct BoundsRecord {
    uint64_t lower;  // inclusive
    uint64_t upper;  // inclusive
    PuT_GenericTypeSpec *typeSpec;
    bool varIsFragmented;  // whether the type is fragmented (prevents bounds narrowing)
};

struct PuT_Section {
    std::string name;
    uint64_t baseAddress;
    uint64_t size;
    bool isWritable;
    bool isExecutable;
};
void from_json(const json &j, PuT_Section &sec);

struct StackFrame {
    uint64_t bottom;  // highest address (inclusive)
    uint64_t top;     // lowest address (inclusive)
    PuT_Function *func;
    uint64_t callerAddr;  // address of the CALL to func

    size_t hash() {
        std::size_t seed = 0;
        boost::hash_combine(seed, bottom);
        boost::hash_combine(seed, top);
        boost::hash_combine(seed, func);
        boost::hash_combine(seed, callerAddr);
        return seed;
    }

    std::string str() {
        std::stringstream ss;
        std::string funName = (func == nullptr) ? "<untracked>" : func->name;
        ss << "[" << hexval(bottom) << "," << hexval(top) << "] for " << funName << " from " << hexval(callerAddr)
           << "\n";
        return ss.str();
    }
};

class CallStack {
   private:
    size_t hash;
    bool hashOk = false;
    llvm::SmallVector<StackFrame, 32> stackFrames;

   public:
    void push(StackFrame sf) {
        hashOk = false;
        stackFrames.push_back(sf);
    }

    StackFrame pop() {
        hashOk = false;
        return stackFrames.pop_back_val();
    }

    size_t getHash() {
        if (!hashOk) {
            hash = 0;
            for (auto sf : stackFrames) {
                boost::hash_combine(hash, sf.hash());
            }
            hashOk = true;
        }
        return hash;
    }

    bool empty() { return stackFrames.empty(); }

    StackFrame *peek() {
        assert(!empty() && "tried peeking into empty call stack");
        return &stackFrames.back();
    }

    auto iterator_top() { return stackFrames.rbegin(); }

    auto iterator_bottom() { return stackFrames.rend(); }

    std::string str() {
        std::stringstream ss;
        for (StackFrame sf : stackFrames) {
            ss << sf.str();
        }
        return ss.str();
    }
};

struct OOBRecord {
    uint64_t key;
    uint64_t vulnSiteAddr;
    PuT_Function *func;
    ival_set_unsigned intervals;
    CallStack callStack;
    uint64_t rsp;
    uint64_t rbp;
    bool prunedCallStack;  // Whether or not the call stack was pruned back to the last monitored function
};

}  // namespace plugins
}  // namespace s2e

#endif