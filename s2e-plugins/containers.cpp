#include "containers.h"

namespace s2e {
namespace plugins {

void from_json(const json &j, PuT_GenericTypeSpec &ts) {
    ts.cat = ts_generic;
    j.at("name").get_to(ts.name);
    j.at("dwarfOffset").get_to(ts.dwarfOffset);
    j.at("size").get_to(ts.size);
    j.at("mnemonic").get_to(ts.mnemonic);
}

void from_json(const json &j, PuT_StructTypeSpec &ts) {
    ts.cat = ts_struct;
    j.at("name").get_to(ts.name);
    j.at("dwarfOffset").get_to(ts.dwarfOffset);
    j.at("size").get_to(ts.size);
    j.at("mnemonic").get_to(ts.mnemonic);

    for (auto j_member : j["members"]) {
        auto member = new PuT_StructMember();
        j_member.at("name").get_to(member->name);
        j_member.at("typeSpec").get_to(member->typeSpecDwarfOffset);
        ts.members.insert({j_member["offset"], member});
    }
}

void from_json(const json &j, PuT_ArrayTypeSpec &ts) {
    ts.cat = ts_array;
    j.at("name").get_to(ts.name);
    j.at("dwarfOffset").get_to(ts.dwarfOffset);
    j.at("size").get_to(ts.size);
    j.at("n_elems").get_to(ts.n_elems);
    j.at("elemTypeSpec").get_to(ts.elemTypeSpecDwarfOffset);
    j.at("mnemonic").get_to(ts.mnemonic);
}

void from_json(const json &j, PuT_AutoVar &var) {
    j.at("name").get_to(var.name);
    j.at("dwarfOffset").get_to(var.dwarfOffset);
    j.at("address").get_to(var.relAddr);
    j.at("typeSpec").get_to(var.typeSpecDwarfOffset);
    j.at("fragmented").get_to(var.fragmented);
    j.at("n_fragment_bytes").get_to(var.n_fragmentBytes);
    j.at("local").get_to(var.local);
    j.at("inlined").get_to(var.inlined);
    j.at("inlined_fun_name").get_to(var.inlined_fun_name);
    j.at("start_addr").get_to(var.start_pc);
    j.at("end_addr").get_to(var.end_pc);
}

void from_json(const json &j, PuT_StaticVar &var) {
    j.at("name").get_to(var.name);
    j.at("dwarfOffset").get_to(var.dwarfOffset);
    j.at("address").get_to(var.addr);
    j.at("typeSpec").get_to(var.typeSpecDwarfOffset);
    j.at("fragmented").get_to(var.fragmented);
    j.at("n_fragment_bytes").get_to(var.n_fragmentBytes);
    j.at("local").get_to(var.local);
    j.at("inlined").get_to(var.inlined);
    j.at("inlined_fun_name").get_to(var.inlined_fun_name);
    j.at("start_addr").get_to(var.start_pc);
    j.at("end_addr").get_to(var.end_pc);
}

void from_json(const json &j, PuT_StaticWrite &w) {
    j.at("addr").get_to(w.addr);
    j.at("staticWriteToAutoVar").get_to(w.staticWriteToAutoVar);
    j.at("dstVarDwarfOffset").get_to(w.dstVarDwarfOffset);

    if (w.staticWriteToAutoVar) {
        j.at("lowerBound").get_to(w.lowerBound.rel);
        j.at("upperBound").get_to(w.upperBound.rel);
    } else {
        j.at("lowerBound").get_to(w.lowerBound.abs);
        j.at("upperBound").get_to(w.upperBound.abs);
    }
}

void from_json(const json &j, PuT_Function &func) {
    j.at("name").get_to(func.name);
    j.at("dwarfOffset").get_to(func.dwarfOffset);
    j.at("baseAddress").get_to(func.baseAddress);
    j.at("baseReg").get_to(func.baseReg);

    for (auto var : j["autoVars"]) {
        auto var_parsed = new PuT_AutoVar();
        *var_parsed = var.get<PuT_AutoVar>();
        func.autoVars.push_back(var_parsed);
    }

    for (auto w : j["staticWrites"]) {
        auto staticWrite_parsed = new PuT_StaticWrite();
        *staticWrite_parsed = w.get<PuT_StaticWrite>();
        func.staticWrites.insert({staticWrite_parsed->addr, staticWrite_parsed});
    }

    for (auto bni : j["boundsNarrowingInsts"]) {
        auto bni_parsed = new PuT_BoundsNarrowingInst();
        *bni_parsed = bni.get<PuT_BoundsNarrowingInst>();
        func.boundsNarrowingInsts.insert({bni_parsed->addr, bni_parsed});
    }
}

void from_json(const json &j, PuT_Section &sec) {
    j.at("name").get_to(sec.name);
    j.at("baseAddress").get_to(sec.baseAddress);
    j.at("size").get_to(sec.size);
    j.at("isWritable").get_to(sec.isWritable);
    j.at("isExecutable").get_to(sec.isExecutable);
}

void from_json(const json &j, PuT_BoundsNarrowingInst &bni) {
    j.at("addr").get_to(bni.addr);
    j.at("resReg").get_to(bni.resReg);
    j.at("narrowingFieldIndices").get_to(bni.narrowingFieldIndices);
    j.at("typeMnemonic").get_to(bni.typeMnemonic);
}

}  // namespace plugins
}  // namespace s2e