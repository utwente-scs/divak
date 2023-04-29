from dataclasses import dataclass, field
from typing import Dict, List, Tuple
from collections import namedtuple

from elftools.dwarf.compileunit import CompileUnit

from capstone import CsInsn

from utils import *

SrcLoc = namedtuple("SourceCodeLoc", ["file", "line", "column"])
SrcLoc.__eq__ = lambda x, y: x.line == y.line and x.column == y.column and check_filenames_match(x.file, y.file)


@dataclass
class PuT_IrWrite:
    instStr: str = None
    hasDebugInfo: bool = None
    srcLine: int = None
    srcColumn: int = None
    srcFile: str = None
    isStaticWrite: bool = None
    staticWriteToAutoVar: bool = None
    staticWriteDstInternalName: str = None
    staticWriteDstActualName: str = None
    boundsNarrowingIndices: List = field(default_factory=list)

    def from_json(j):
        putIrWrite = PuT_IrWrite()
        putIrWrite.instStr = j["instStr"]
        putIrWrite.hasDebugInfo = j["hasDebugInfo"]
        putIrWrite.srcLine = j["srcLine"]
        putIrWrite.srcColumn = j["srcColumn"]
        putIrWrite.srcFile = j["srcFileName"]
        putIrWrite.isStaticWrite = j["isStaticWrite"]
        putIrWrite.staticWriteToLocalVar = j["staticWriteToLocalVar"]
        putIrWrite.staticWriteToAutoVar = j["staticWriteToAutoVar"]
        putIrWrite.staticWriteDstInternalName = j["staticWriteDstInternalName"]
        putIrWrite.staticWriteDstActualName = j["staticWriteDstActualName"]
        putIrWrite.boundsNarrowingIndices = j["boundsNarrowingIndices"]

        return putIrWrite


@dataclass
class PuT_BoundsNarrowingInst:
    irInstStr: str = None
    hasDebugInfo: bool = None
    srcLine: int = None
    srcColumn: int = None
    srcFile: str = None
    hasAltDebugInfo: bool = None
    altSrcLine: int = None
    altSrcColumn: int = None
    altSrcFile: str = None
    narrowingFieldIndices: List = field(default_factory=list)
    addr: int = None
    asmInst: Inst = None
    resReg: str = None  # register to which the bounds-narrowing instruction writes
    typeMnemonic: str = None

    def from_json(j):
        putBoundsNarrowingInst = PuT_BoundsNarrowingInst()
        putBoundsNarrowingInst.irInstStr = j["instStr"]
        putBoundsNarrowingInst.hasDebugInfo = j["hasDebugInfo"]
        putBoundsNarrowingInst.srcLine = j["srcLine"]
        putBoundsNarrowingInst.srcColumn = j["srcColumn"]
        putBoundsNarrowingInst.srcFile = j["srcFileName"]
        putBoundsNarrowingInst.hasAltDebugInfo = j["hasAltDebugInfo"]
        putBoundsNarrowingInst.altSrcLine = j["altSrcLine"]
        putBoundsNarrowingInst.altSrcColumn = j["altSrcColumn"]
        putBoundsNarrowingInst.altSrcFile = j["altSrcFileName"]
        putBoundsNarrowingInst.narrowingFieldIndices = j["narrowingFieldIndices"]
        putBoundsNarrowingInst.typeMnemonic = j["typeMnemonic"]

        return putBoundsNarrowingInst

    def to_json(self):
        return {
            "addr": self.addr,
            "addrHex": hex(self.addr),
            "narrowingFieldIndices": self.narrowingFieldIndices,
            "resReg": self.resReg,
            "typeMnemonic": self.typeMnemonic,
        }


@dataclass
class PuT_AsmWrite:
    addr: int = None
    inst: CsInsn = None
    srcLoc: SrcLoc = None
    isDependent: bool = None
    irWrite: PuT_IrWrite = None
    dstVarDwarfOffset: int = None  # DWARF offset of the variable to which it writes
    lowerBound: int = None
    upperBound: int = None

    def to_json(self):
        return {
            "addr": self.addr,
            "isStaticWrite": self.irWrite.isStaticWrite,
            "staticWriteToAutoVar": self.irWrite.staticWriteToAutoVar,
            "dstVarDwarfOffset": self.dstVarDwarfOffset,
            "lowerBound": self.lowerBound,
            "upperBound": self.upperBound,
        }


@dataclass
class PuT_AbstractTypeSpec:
    dwarfOffset: int = None
    name: str = None
    size: int = None
    mnemonic: str = None  # Only need this for struct and array types, for generic ones it will always be ""

    def __init__(self):
        raise NotImplementedError("Class is abstract")

    def to_json(self):
        raise NotImplementedError("Class is abstract")


@dataclass
class PuT_Function:
    dwarfOffset: int = None
    cu: CompileUnit = None
    name: str = None
    uniqueName: str = None  # Unique across all compile units
    srcFileName: str = None
    baseAddress: int = None  # address of first instruction
    lastAddress: int = None  # address of last instruction
    autoVars: List = field(default_factory=list)
    baseReg: str = None
    irWrites: List = field(default_factory=list)
    asmWrites: List = field(default_factory=list)
    boundsNarrowingInsts: List = field(default_factory=list)
    asmInsts: Dict = field(default_factory=dict)
    addrToLine: Dict = field(default_factory=dict)

    def to_json(self):
        return {
            "type": "function",
            "dwarfOffset": self.dwarfOffset,
            "name": self.name if self.name else "",
            "baseAddress": self.baseAddress,
            "baseAddressHex": hex(self.baseAddress),
            "baseReg": self.baseReg,
            "autoVars": [var.to_json() for var in self.autoVars],
            # only add asm Writes that are independent and fully matched to a memory object
            "staticWrites": [w.to_json() for w in self.asmWrites if not w.isDependent and w.dstVarDwarfOffset != None],
            "boundsNarrowingInsts": [
                bni.to_json() for bni in self.boundsNarrowingInsts if bni.addr
            ],  # TODO: need to handle BNIs to non-registers properly
        }

    """
    def from_json(j):
        putFunc = PuT_Function()
        putFunc.name = j["name"]
        putFunc.irWrites = j["storeInsts"]
        putFunc.boundsNarrowingInsts = j["boundsNarrowingInsts"]

        return putFunc
    """


VAR_LIFETIME_END_MAX = 0xFFFFFFFFFFFFFFFF


@dataclass
class PuT_Variable:
    dwarfOffset: int = None
    # name: str = None
    # A variable can have more than one name if we merge multiple into one because they're stored at the same location by the compiler
    names: List[str] = field(default_factory=list)
    fragmented: bool = None  # Whether or not this is a fragment of the variable
    automatic: bool = None
    local: bool = None
    inlined: bool = None  # Whether this is a local variable of an inlined function
    inlined_fun_name: str = None  # The name of the inlined function
    formalParameter: bool = None  # Whether this varaible is a formal parameter (i.e., a function argument)
    address: int = None
    n_fragment_bytes: int = None  # Number of bytes this fragment occupies
    typeSpec: PuT_AbstractTypeSpec = None
    start_addr: int = None
    end_addr: int = None

    def to_json(self):
        assert not (self.automatic and not self.local)
        if len(self.names) == 0:
            name = ""
        elif len(self.names) == 1:
            name = self.names[0]
        else:
            name = "merged<" + ",".join(self.names) + ">"

        return {
            "type": "variable",
            "dwarfOffset": self.dwarfOffset,
            "name": name,
            "fragmented": self.fragmented,
            "automatic": self.automatic,
            "local": self.local,
            "inlined": self.inlined,
            "inlined_fun_name": self.inlined_fun_name if self.inlined_fun_name else "",
            "address": self.address,
            "n_fragment_bytes": self.n_fragment_bytes,
            "typeSpec": self.typeSpec.dwarfOffset,
            "start_addr": self.start_addr,
            "end_addr": self.end_addr if self.end_addr != VAR_LIFETIME_END_MAX else -1,
        }


@dataclass
class PuT_GenericTypeSpec(PuT_AbstractTypeSpec):
    """
    Container for any variable that we consider a single chunk of memory in S2E
    """

    def to_json(self):
        return {
            "type": "generic",
            "dwarfOffset": self.dwarfOffset,
            "name": self.name if self.name else "",
            "size": self.size if self.size else 0,
            "mnemonic": "",
        }


@dataclass
class PuT_StructMember:
    name: str = None
    offset: int = None
    typeSpec: object = None

    def to_json(self):
        res = {
            "name": self.name if self.name else "",
            "offset": self.offset,
            "typeSpec": self.typeSpec.dwarfOffset,
        }
        if __debug__:
            res["typeFull"] = self.typeSpec.to_json()
        return res


@dataclass
class PuT_StructTypeSpec(PuT_AbstractTypeSpec):
    members: List[PuT_StructMember] = field(default_factory=list)

    def to_json(self):
        return {
            "type": "struct",
            "dwarfOffset": self.dwarfOffset,
            "name": self.name if self.name else "",
            "size": self.size if self.size else 0,
            "members": [m.to_json() for m in self.members],
            "mnemonic": self.mnemonic,
        }


@dataclass
class PuT_ArrayTypeSpec(PuT_AbstractTypeSpec):
    n_elems: int = None
    elemType: PuT_AbstractTypeSpec = None

    def to_json(self):
        res = {
            "type": "array",
            "dwarfOffset": self.dwarfOffset,
            "name": self.name if self.name else "",
            "size": self.size if self.size else 0,
            "n_elems": self.n_elems,
            "elemTypeSpec": self.elemType.dwarfOffset,
            "mnemonic": self.mnemonic,
        }
        if __debug__:
            res["elemTypeSpecFull"] = self.elemType.to_json()
        return res
