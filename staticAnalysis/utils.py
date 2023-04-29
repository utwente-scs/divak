from dataclasses import dataclass
from email.headerregistry import Address
import string
from capstone import *
from capstone.x86_const import *

import os, re

from enum import Enum

import logging

cmov_instrs = {
    X86_INS_CMOVA,
    X86_INS_CMOVAE,
    X86_INS_CMOVB,
    X86_INS_CMOVBE,
    X86_INS_FCMOVBE,
    X86_INS_FCMOVB,
    X86_INS_CMOVE,
    X86_INS_FCMOVE,
    X86_INS_CMOVG,
    X86_INS_CMOVGE,
    X86_INS_CMOVL,
    X86_INS_CMOVLE,
    X86_INS_FCMOVNBE,
    X86_INS_FCMOVNB,
    X86_INS_CMOVNE,
    X86_INS_FCMOVNE,
    X86_INS_CMOVNO,
    X86_INS_CMOVNP,
    X86_INS_FCMOVNU,
    X86_INS_CMOVNS,
    X86_INS_CMOVO,
    X86_INS_CMOVP,
    X86_INS_FCMOVU,
    X86_INS_CMOVS,
}

mov_instrs = {
    X86_INS_MOVAPD,
    X86_INS_MOVAPS,
    X86_INS_VMOVAPD,
    X86_INS_VMOVAPS,
    X86_INS_KMOVB,
    X86_INS_KMOVD,
    X86_INS_KMOVQ,
    X86_INS_KMOVW,
    X86_INS_MASKMOVDQU,
    X86_INS_MASKMOVQ,
    X86_INS_MOVD,
    X86_INS_MOVDQ2Q,
    X86_INS_MOVNTQ,
    X86_INS_MOVQ2DQ,
    X86_INS_MOVQ,
    X86_INS_PMOVMSKB,
    X86_INS_MOV,
    X86_INS_MOVABS,
    X86_INS_MOVBE,
    X86_INS_MOVDDUP,
    X86_INS_MOVDQA,
    X86_INS_MOVDQU,
    X86_INS_MOVHLPS,
    X86_INS_MOVHPD,
    X86_INS_MOVHPS,
    X86_INS_MOVLHPS,
    X86_INS_MOVLPD,
    X86_INS_MOVLPS,
    X86_INS_MOVMSKPD,
    X86_INS_MOVMSKPS,
    X86_INS_MOVNTDQA,
    X86_INS_MOVNTDQ,
    X86_INS_MOVNTI,
    X86_INS_MOVNTPD,
    X86_INS_MOVNTPS,
    X86_INS_MOVNTSD,
    X86_INS_MOVNTSS,
    X86_INS_MOVSB,
    X86_INS_MOVSD,
    X86_INS_MOVSHDUP,
    X86_INS_MOVSLDUP,
    X86_INS_MOVSQ,
    X86_INS_MOVSS,
    X86_INS_MOVSW,
    X86_INS_MOVSX,
    X86_INS_MOVSXD,
    X86_INS_MOVUPD,
    X86_INS_MOVUPS,
    X86_INS_MOVZX,
    X86_INS_PMOVSXBD,
    X86_INS_PMOVSXBQ,
    X86_INS_PMOVSXBW,
    X86_INS_PMOVSXDQ,
    X86_INS_PMOVSXWD,
    X86_INS_PMOVSXWQ,
    X86_INS_PMOVZXBD,
    X86_INS_PMOVZXBQ,
    X86_INS_PMOVZXBW,
    X86_INS_PMOVZXDQ,
    X86_INS_PMOVZXWD,
    X86_INS_PMOVZXWQ,
    X86_INS_VMASKMOVDQU,
    X86_INS_VMASKMOVPD,
    X86_INS_VMASKMOVPS,
    X86_INS_VMOVQ,
    X86_INS_VMOVDDUP,
    X86_INS_VMOVD,
    X86_INS_VMOVDQA32,
    X86_INS_VMOVDQA64,
    X86_INS_VMOVDQA,
    X86_INS_VMOVDQU16,
    X86_INS_VMOVDQU32,
    X86_INS_VMOVDQU64,
    X86_INS_VMOVDQU8,
    X86_INS_VMOVDQU,
    X86_INS_VMOVHLPS,
    X86_INS_VMOVHPD,
    X86_INS_VMOVHPS,
    X86_INS_VMOVLHPS,
    X86_INS_VMOVLPD,
    X86_INS_VMOVLPS,
    X86_INS_VMOVMSKPD,
    X86_INS_VMOVMSKPS,
    X86_INS_VMOVNTDQA,
    X86_INS_VMOVNTDQ,
    X86_INS_VMOVNTPD,
    X86_INS_VMOVNTPS,
    X86_INS_VMOVSD,
    X86_INS_VMOVSHDUP,
    X86_INS_VMOVSLDUP,
    X86_INS_VMOVSS,
    X86_INS_VMOVUPD,
    X86_INS_VMOVUPS,
    X86_INS_VPMASKMOVD,
    X86_INS_VPMASKMOVQ,
    X86_INS_VPMOVDB,
    X86_INS_VPMOVDW,
    X86_INS_VPMOVM2B,
    X86_INS_VPMOVM2D,
    X86_INS_VPMOVM2Q,
    X86_INS_VPMOVM2W,
    X86_INS_VPMOVMSKB,
    X86_INS_VPMOVQB,
    X86_INS_VPMOVQD,
    X86_INS_VPMOVQW,
    X86_INS_VPMOVSDB,
    X86_INS_VPMOVSDW,
    X86_INS_VPMOVSQB,
    X86_INS_VPMOVSQD,
    X86_INS_VPMOVSQW,
    X86_INS_VPMOVSXBD,
    X86_INS_VPMOVSXBQ,
    X86_INS_VPMOVSXBW,
    X86_INS_VPMOVSXDQ,
    X86_INS_VPMOVSXWD,
    X86_INS_VPMOVSXWQ,
    X86_INS_VPMOVUSDB,
    X86_INS_VPMOVUSDW,
    X86_INS_VPMOVUSQB,
    X86_INS_VPMOVUSQD,
    X86_INS_VPMOVUSQW,
    X86_INS_VPMOVZXBD,
    X86_INS_VPMOVZXBQ,
    X86_INS_VPMOVZXBW,
    X86_INS_VPMOVZXDQ,
    X86_INS_VPMOVZXWD,
    X86_INS_VPMOVZXWQ,
}

# Instrution that modify memory implicitly (i.e. without having an operand that specifies a memory location)
# and are always innocuous in this.
implicit_innoc_write_insts = {
    X86_INS_PUSH,
    X86_INS_PUSHAW,
    X86_INS_PUSHAL,
    X86_INS_PUSHF,
    X86_INS_PUSHFD,
    X86_INS_PUSHFQ,
    X86_INS_CALL,
}

# Instrution that modify memory exlicitly (i.e. by having an operand that specifies a memory location)
# and are always innocuous in this.
explicit_innoc_write_insts = {
    X86_INS_ADD,
    X86_INS_SUB,
    X86_INS_AND,
    X86_INS_OR,
    X86_INS_XOR,
    X86_INS_INC,
    X86_INS_DEC,
}

word_regs = {
    X86_REG_AX,
    X86_REG_BX,
    X86_REG_CX,
    X86_REG_DX,
    X86_REG_SI,
    X86_REG_DI,
    X86_REG_BP,
    X86_REG_SP,
    X86_REG_R8W,
    X86_REG_R9W,
    X86_REG_R10W,
    X86_REG_R11W,
    X86_REG_R12W,
    X86_REG_R13W,
    X86_REG_R14W,
    X86_REG_R15W,
}

byte_regs = {
    X86_REG_AL,
    X86_REG_BL,
    X86_REG_CL,
    X86_REG_DL,
    X86_REG_SIL,
    X86_REG_DIL,
    X86_REG_BPL,
    X86_REG_SPL,
    X86_REG_R8B,
    X86_REG_R9B,
    X86_REG_R10B,
    X86_REG_R11B,
    X86_REG_R12B,
    X86_REG_R13B,
    X86_REG_R14B,
    X86_REG_R15B,
    X86_REG_AH,
    X86_REG_BH,
    X86_REG_CH,
    X86_REG_DH,
}


VERY_LIKELY = 4
LIKELY = 3
POSSIBLE = 2
UNLIKELY = 1
IMPOSSIBLE = 0

# reg_lut = {v: k[8:] for k, v in locals().items() if k.startswith("X86_REG_")}


amd64_gprs = {
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rbp",
    "rsi",
    "rdi",
    "rsp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r14",
    "r15",
    "eax",
    "ebx",
    "ecx",
    "edx",
    "ebp",
    "esi",
    "edi",
    "esp",
    "r8d",
    "r9d",
    "r10d",
    "r11d",
    "r12d",
    "r13d",
    "r14d",
    "r14d",
    "r15d",
}


def find_unique_match(elem, coll, cond):
    """
    elem: the element to be matched to an element of the collection
    coll: the collection
    cond: the lambda function to be used for matching
    """
    matches = [coll_elem for coll_elem in coll if cond(elem, coll_elem)]
    if len(matches) == 0:
        raise RuntimeError("Failed to find a match for")
    elif len(matches) == 1:
        return matches[0]
    else:
        raise RuntimeError("Found more than one match")


def check_filenames_match(str1, str2):
    """
    Given two strings containing relative or absolute paths, check if these possibly point to the same file.
    """
    j_comps = os.path.normpath(str1).split(os.path.sep)
    p_comps = os.path.normpath(str2).split(os.path.sep)
    min_len = min(len(j_comps), len(p_comps))
    return j_comps[-min_len:] == p_comps[-min_len:]


no_bni_regs = word_regs.union(byte_regs).union({X86_REG_EFLAGS})


def remove_impossible_bnis(coll):
    control_flow_groups = {X86_GRP_JUMP, X86_GRP_CALL, X86_GRP_RET, X86_GRP_BRANCH_RELATIVE}
    try:
        for inst in list(coll):
            assert isinstance(inst, Inst)
            if not set(inst.groups).isdisjoint(control_flow_groups):
                coll.remove(inst)
            elif not inst.operands:
                # Instruction has no operands
                coll.remove(inst)
            elif inst.dst_reg and inst.src_imm != None and inst.src_imm < 0xFFFFF:
                # MOV reg, (imm that is not an address)
                coll.remove(inst)
            # elif inst.operands[0].type == X86_OP_REG and all(reg in no_bni_regs for reg in inst.regs_access()[1]):
            elif inst.operands[0].type == X86_OP_REG and not any(inst.reg_name(reg) in amd64_gprs for reg in inst.regs_access()[1]):
                # The instruction writes to a register but does not modify any 32-bit or 64-bit GPRS, can't be a BNI
                coll.remove(inst)
    except:
        print(inst.regs_access())
        assert False


class AddressingMode(Enum):
    AM_D = 1  # Displacement
    AM_B = 2  # Base
    AM_B_I = 3  # Base + Index
    AM_B_D = 4  # Base + Displacement
    AM_B_I_D = 5  # Base + Index + Displacement
    AM_B_I_S = 6  # Base + (Index * Scale)
    AM_I_S_D = 7  # (Index * Scale) + Displacement
    AM_B_I_S_D = 8  # Base + (Index * Scale) + Displacement
    AM_RIP_D = 9  # RIP + Displacement


@dataclass
class MemoryOperand:
    addressing_mode: AddressingMode = None
    base: string = None
    displacement: int = None
    index: string = None
    scale: int = None


class StatsCollector:
    def __init__(self):
        self.n_static_writes_skipped_fragmented_var = 0
        self.n_static_writes_skipped_no_object_match = 0
        self.n_static_writes_skipped_multiple_object_matches = 0
        self.n_static_writes_skipped_no_original_name = 0
        self.n_independent_writes_successfully_matched = 0
        self.n_independent_writes_skipped_multiple_ir_candidates = 0
        self.n_independent_writes_skipped_no_ir_candidates = 0

        self.n_vlas_detected = 0
        self.n_pcs_skipped_memory_dst = 0
        self.n_pcs_skipped_conditional_mov = 0
        self.n_overlapping_objects = 0
        self.uncharted_stack_frame_mean = 0
        self.uncharted_stack_frame_median = 0
        self.uncharted_stack_frame_stdev = 0

        self.n_bnis_unmatched_no_candidates = 0
        self.n_bnis_unmatched_multiple_candidates = 0
        self.n_pcs_discovered = 0
        self.n_bnis_successfully_matched = 0
        self.n_bnis_matched_alternative_loc = 0
        self.n_bnis_skipped_many_ir_one_asm = 0
        self.n_internal_bnis = 0

        self.n_external_lib_functions_discovered = 0

    def print(self):
        for stat_name, value in self.__dict__.items():
            logging.info(f"{stat_name}: {value}")

    def to_json(self):
        return self.__dict__


class Inst(CsInsn):
    _src_str = None
    _dst_str = None
    _dst_reg = None
    _src_reg = None
    _src_imm = None

    def __init__(self, baseCsInsn):
        self.__class__ = type(baseCsInsn.__class__.__name__, (self.__class__, baseCsInsn.__class__), {})
        self.__dict__ = baseCsInsn.__dict__

    def is_mov(self):
        return self.id in mov_instrs

    def is_cmov(self):
        return self.id in cmov_instrs

    def is_add(self):
        return self.id == X86_INS_ADD

    def is_lea(self):
        return self.id == X86_INS_LEA

    def is_push(self):
        return self.id in [X86_INS_PUSH, X86_INS_PUSHAW, X86_INS_PUSHAL, X86_INS_PUSHF, X86_INS_PUSHFD, X86_INS_PUSHFQ]

    def is_call(self):
        return self.id in [X86_INS_CALL]

    def is_possible_add_bni(self):
        if not self.is_add():
            return False
        if self.reg_name(self.operands[0].reg) not in amd64_gprs:
            return False
        if self.operands[1].type != X86_OP_IMM:
            return False
        return True

    def is_possible_mov_bni(self):
        if not self.is_mov():
            return False

        if self.operands[0].type == X86_OP_REG and self.operands[1].type == X86_OP_IMM and self.operands[1].imm < 0x400000:
            # MOV from an IMM to a register, but the IMM is not a valid address
            return False

        if self.operands[0].type == X86_OP_REG and self.reg_name(self.operands[0].reg) not in amd64_gprs:
            # MOV to a register but the register cannot hold a pointer
            return False

        return True

    def is_possible_lea_bni(self):
        if not self.is_lea():
            return False
        if self.reg_name(self.operands[0].reg) not in amd64_gprs:
            return False
        return True

    def is_innoc_write_inst(self):
        if self.id in implicit_innoc_write_insts:
            return True
        if self.id in explicit_innoc_write_insts:
            for op in self.operands:
                if op.type == X86_OP_MEM and op.access & CS_AC_WRITE:
                    # Operand accesses memory and the acvess type has the write bit set
                    return True
        return False

    def to_string(self):
        return f"{hex(self.address)} {self.mnemonic} {self.op_str}"

    def dst_addr_op(self):
        if self.operands[0].type != X86_OP_MEM:
            return RuntimeError("Tried to get the addressing operand of a non-memory operand")

        int_re = "(0x[0-9a-fA-F]+|[0-9]+)"

        assert self.op_str.split()[0] in ["byte", "word", "dword", "qword", "xmmword"]
        assert self.op_str.split()[1] == "ptr"

        dst_str = self.op_str.partition("[")[2].partition("]")[0]
        components = dst_str.split()

        if len(components) == 1:
            if re.match(int_re, components[0]):
                return MemoryOperand(addressing_mode=AddressingMode.AM_D, displacement=int(components[0], 0))
            elif components[0] in amd64_gprs:
                return MemoryOperand(addressing_mode=AddressingMode.AM_B, base=components[0])

        elif len(components) == 3:
            if not components[1] in ["+", "-"]:
                raise RuntimeError(f"Couldn't find the addressing mode of {dst_str}")
            if components[0] in amd64_gprs:
                if components[2] in amd64_gprs:
                    return MemoryOperand(addressing_mode=AddressingMode.AM_B_I, base=components[0], index=components[2])
                elif re.match(int_re, components[2]):
                    return MemoryOperand(addressing_mode=AddressingMode.AM_B_D, base=components[0], displacement=int(components[2], 0))
                elif "*" in components[2]:
                    idx_sc = components[2].split("*")
                    if len(idx_sc) == 2:
                        index = idx_sc[0]
                        scale = idx_sc[1]
                        if index in amd64_gprs and scale in ["1", "2", "4", "8"]:
                            return MemoryOperand(addressing_mode=AddressingMode.AM_B_I_S, base=components[0], index=index, scale=int(scale))

            elif components[0] == "rip" and re.match(int_re, components[2]):
                return MemoryOperand(addressing_mode=AddressingMode.AM_RIP_D, displacement=int(components[2], 0))
            elif "*" in components[0] and re.match(int_re, components[2]):
                idx_sc = components[0].split("*")
                if len(idx_sc) == 2:
                    index = idx_sc[0]
                    scale = idx_sc[1]
                    if index in amd64_gprs and scale in ["1", "2", "4", "8"]:
                        return MemoryOperand(
                            addressing_mode=AddressingMode.AM_I_S_D, index=index, scale=int(scale), displacement=int(components[2], 0)
                        )
        elif len(components) == 5:
            if not (components[1] in ["+", "-"] and components[3] in ["+", "-"]):
                raise RuntimeError(f"Couldn't find the addressing mode of {dst_str}")
            if components[0] in amd64_gprs and re.match(int_re, components[4]):
                if "*" in components[2]:
                    idx_sc = components[2].split("*")
                    if len(idx_sc) == 2:
                        index = idx_sc[0]
                        scale = idx_sc[1]
                        if index in amd64_gprs and scale in ["1", "2", "4", "8"]:
                            return MemoryOperand(
                                addressing_mode=AddressingMode.AM_B_I_S_D,
                                base=components[0],
                                index=index,
                                scale=int(scale),
                                displacement=int(components[4], 0),
                            )
                elif components[2] in amd64_gprs:
                    return MemoryOperand(
                        addressing_mode=AddressingMode.AM_B_I_D, base=components[0], index=components[2], displacement=int(components[4], 0)
                    )

        raise RuntimeError(f"Couldn't find the addressing mode of {dst_str}")

    @property
    def dst_str(self):
        if not self._dst_str:
            self._dst_str = self.op_str.partition("[")[2].partition("]")[0]  # Now we have the destination address, without brackets
        return self._dst_str

    @property
    def dst_reg(self):
        if not (self.is_mov() or self.is_cmov()):
            return None
        if not self._dst_reg:
            if not self.operands[0].type == X86_OP_REG:
                return None
            self._dst_reg = self.reg_name(self.operands[0].reg).upper()  # reg_lut[self.operands[0].reg]
        return self._dst_reg

    @property
    def src_reg(self):
        if not (self.is_mov() or self.is_cmov()):
            return None
        if not self._src_reg:
            if not self.operands[1].type == X86_OP_REG:
                return None
            self._src_reg = self.reg_name(self.operands[1].reg).upper()  # reg_lut[self.operands[1].reg]
        return self._src_reg

    @property
    def src_imm(self):
        if not (self.is_mov() or self.is_cmov()):
            return None
        if not self._src_imm:
            if not self.operands[1].type == X86_OP_IMM:
                return None
            self._src_imm = self.operands[1].imm
        return self._src_imm

    def is_mov_to_imm_addr(self):
        int_re = "(0x[0-9a-fA-F]+|[0-9]+)"
        return (self.is_mov() or self.is_cmov()) and re.match(int_re, self.dst_str)
