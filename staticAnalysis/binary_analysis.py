from containers import *

from itertools import chain

from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from elftools.elf.elffile import ELFFile

import bisect


class BinaryAnalyzer:
    def __init__(self, elffile: ELFFile, statsCollector: StatsCollector):
        self.stats = statsCollector
        self.elffile = elffile
        self.innoc_writes = []

    def findPtrCreationSites(self):
        # addrs_sorted = sorted(list(text_disasm))
        sites = dict()

        assert self.elf_segments

        # Disassemble the .text section
        elf_text_sec = self.elffile.get_section_by_name(".text")
        elf_text_base_addr = elf_text_sec["sh_addr"]
        cs_md = Cs(CS_ARCH_X86, CS_MODE_64)
        cs_md.detail = True  # To have detailed information on operands etc. available

        suspicious_insts = []

        for inst in cs_md.disasm(elf_text_sec.data(), elf_text_base_addr):
            # if X86_REG_RBP in inst.regs_access()[1] and f"{inst.mnemonic} {inst.op_str}" not in ["pop rbp", "mov rbp, rsp"]:
            #    suspicious_insts.append(f"{hex(inst.address)}: {inst.mnemonic} {inst.op_str}")

            if inst.id == X86_INS_LEA:
                # print(f"{hex(inst.address)}: {inst.id} {inst.mnemonic} {inst.op_str}")

                # next_inst_addr = addrs_sorted[bisect_left(addrs_sorted, addr) + 1]
                # sites[hex(next_inst_addr)] = reg_lut[inst.operands[0].reg]
                sites[hex(inst.address)] = inst.reg_name(inst.operands[0].reg).upper()  # reg_lut[inst.operands[0].reg]

            elif inst.id in mov_instrs:
                assert len(inst.operands) == 2
                dst = inst.operands[0]
                src = inst.operands[1]

                if src.type != X86_OP_IMM:
                    # Disregard MOVs without a hard-coded src
                    continue
                if not any(seg["baseAddress"] <= src.value.imm <= seg["baseAddress"] + seg["size"] for seg in self.elf_segments):
                    # Disregard MOVs with a src that isn't an address within a static section
                    continue

                if inst.id in cmov_instrs:
                    logging.warning(
                        f"Found pointer-creating CMOV-type instruction at {hex(inst.address)}. We don't currently support them, ignoring..."
                    )
                    self.stats.n_pcs_skipped_conditional_mov += 1
                    continue

                # print(f"{hex(inst.address)}: {inst.id} {inst.mnemonic} {inst.op_str}")

                if dst.type == X86_OP_REG:
                    # next_inst_addr = addrs_sorted[bisect_left(addrs_sorted, addr) + 1]
                    # sites[hex(next_inst_addr)] = reg_lut[inst.operands[0].reg]
                    sites[hex(inst.address)] = inst.reg_name(inst.operands[0].reg).upper()  # reg_lut[inst.operands[0].reg]
                    self.stats.n_pcs_discovered += 1
                elif dst.type == X86_OP_MEM:
                    logging.warning(f"Found pointer-creating instruction with memory dest at {hex(inst.address)}. Ignoring...")
                    self.stats.n_pcs_skipped_memory_dst += 1
                else:
                    raise RuntimeError()

        return sites

    def processSegments(self):
        if hasattr(self, "elf_segments"):
            return self.elf_segments

        self.elf_segments = []

        for segment in self.elffile.iter_segments():
            if segment.header["p_type"] != "PT_LOAD":
                continue

            isExecutable = bool(segment.header["p_flags"] & 1)
            isWritable = bool(segment.header["p_flags"] & 2)
            isReadable = bool(segment.header["p_flags"] & 4)

            d_seg = {
                "baseAddress": segment.header["p_paddr"],
                "baseAddressHex": hex(segment.header["p_paddr"]),
                "size": segment.header["p_memsz"],
                "isExecutable": isExecutable,
                "isWritable": isWritable,
                "isReadable": isReadable,
                "sections": [],
            }

            for section in self.elffile.iter_sections():
                if segment.section_in_segment(section):
                    isWritable = bool(section.header["sh_flags"] & 1)
                    allocable = bool(section.header["sh_flags"] & 2)
                    isExecutable = bool(section.header["sh_flags"] & 4)
                    assert allocable
                    d_sec = {
                        "name": section.name,
                        "baseAddress": section.header["sh_addr"],
                        "baseAddressHex": hex(section.header["sh_addr"]),
                        "size": section.header["sh_size"],
                        "isWritable": isWritable,
                        "isExecutable": isExecutable,
                    }
                    d_seg["sections"].append(d_sec)

            self.elf_segments.append(d_seg)

        return self.elf_segments

    def extract_lib_function_addrs(self):
        """
        Returns a dict with external library function names as keys and their corresponding address in the .plt, i.e. the address that is CALLed from .text, as values
        """
        rela_plt = self.elffile.get_section_by_name(".rela.plt")
        assert isinstance(rela_plt, RelocationSection)

        # First step: Find .rela.plt (function name string) to .got.plt mapping
        symbol_table = self.elffile.get_section(rela_plt["sh_link"])
        relocs = (
            dict()
        )  # to contain .got.plt addresses at which pointers to external functions are stored as keys, function names as values
        for reloc in rela_plt.iter_relocations():
            symbol_name = symbol_table.get_symbol(reloc["r_info_sym"]).name
            addr = reloc["r_offset"]
            # print(hex(addr) + " -> " + symbol_name)
            relocs[addr] = symbol_name

        # Second step: Find .plt to .got.plt mapping
        plt_sec = self.elffile.get_section_by_name(".plt")
        plt_base_addr = plt_sec["sh_addr"]
        cs_md = Cs(CS_ARCH_X86, CS_MODE_64)
        cs_md.detail = True  # To have detailed information on operands etc. available
        instrs_disasm = list(cs_md.disasm(plt_sec.data(), plt_base_addr))
        got_plt_to_plt_matches = dict()
        for inst, next_inst in zip(instrs_disasm, instrs_disasm[1:]):
            if inst.id != X86_INS_JMP:
                continue
            jmp_target = inst.operands[0]
            if jmp_target.type != X86_OP_MEM:
                continue
            # The destination pointer in .got.plt always seems to be accessed via RIP-relative addressing
            jmp_dst = next_inst.address + jmp_target.value.mem.disp

            got_plt_to_plt_matches[jmp_dst] = int(inst.address)

        # Third step: Find .plt to .rela.plt (function name string) mapping
        fun_name_to_plt_addr = dict()
        for got_plt_addr, fun_name in relocs.items():
            plt_addr = got_plt_to_plt_matches[got_plt_addr]
            fun_name_to_plt_addr[fun_name] = plt_addr
            self.stats.n_external_lib_functions_discovered += 1

        return fun_name_to_plt_addr

    def disass_functions(self):
        """
        Returns a dict with the names of functions defined in the symbol table as keys and a dict with (addr:instruction) as values
        """
        elf_text_sec = self.elffile.get_section_by_name(".text")
        elf_text_base_addr = elf_text_sec["sh_addr"]
        cs_md = Cs(CS_ARCH_X86, CS_MODE_64)
        cs_md.detail = True  # To have detailed information on operands etc. available

        # get all symbols from the symbol table
        symb_addrs = []
        for section in self.elffile.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if symbol["st_value"] != 0:
                    symb_addrs.append(symbol["st_value"])
        list.sort(symb_addrs)

        # get the disassembled instructions for each function from the symbol table
        disass_funcs = dict()

        insts = list(cs_md.disasm(elf_text_sec.data(), elf_text_base_addr))
        inst_addrs = [inst.address for inst in insts]
        symb_addrs.append(0xFFFFFFFFFFFFFFFF)  # To allow iterating by zipping in the next step

        for currFuncStart, nextFuncStart in zip(symb_addrs, symb_addrs[1:]):
            currFuncFirstInstIdx = bisect.bisect_left(inst_addrs, currFuncStart)
            nextFuncFirstInstIdx = bisect.bisect_left(inst_addrs, nextFuncStart)

            disass_funcs[currFuncStart] = [Inst(inst) for inst in insts[currFuncFirstInstIdx:nextFuncFirstInstIdx]]

        return disass_funcs

    def add_assembly_to_functions(self, put_funcs: list):
        disass_func_dict = self.disass_functions()

        for put_func in put_funcs:
            assert isinstance(put_func, PuT_Function)
            insts = disass_func_dict[put_func.baseAddress]
            put_func.asmInsts = {
                i.address: i for i in filter(lambda inst: put_func.baseAddress <= inst.address <= put_func.lastAddress, insts)
            }

    def points_to_static_sec(self, addr):
        assert self.elf_segments
        if not hasattr(self, "static_sec_ivals"):
            self.static_sec_ivals = set(
                chain(
                    *(range(sec["baseAddress"], sec["baseAddress"] + sec["size"]) for seg in self.elf_segments for sec in seg["sections"])
                )
            )

        return addr in self.static_sec_ivals

    def extract_asm_writes(self, putFuncs: list):
        """
        Extends putFuncs with the ASM writes performed in each function (in the form of a PuT_AsmWrite object)
        """

        # for funName, fun_disass in disass_funcs.items():
        for putFunc in putFuncs:
            # putFunc = next((x for x in putFuncs if x.name == funName), None)
            # if not putFunc:
            # Not all functions in the symbol table are in DWARF but we only care about those that are
            #    continue

            for _, inst in putFunc.asmInsts.items():
                if inst.is_innoc_write_inst():
                    self.innoc_writes.append(inst.address)
                    continue

                if inst.id not in mov_instrs:
                    continue
                dst = inst.operands[0]
                if dst.type != X86_OP_MEM:
                    continue

                asmWrite = PuT_AsmWrite()
                asmWrite.addr = inst.address
                asmWrite.inst = inst

                # TODO: Make variable?
                sfb_regs = ["rbp", "rsp"]

                dst_addr_op = inst.dst_addr_op()
                assert isinstance(dst_addr_op, MemoryOperand)

                assert not (dst_addr_op.index in sfb_regs and dst_addr_op.scale == 1)

                if dst_addr_op.addressing_mode in [AddressingMode.AM_D, AddressingMode.AM_RIP_D]:
                    self.innoc_writes.append(inst.address)
                    continue
                elif dst_addr_op.addressing_mode in [AddressingMode.AM_B, AddressingMode.AM_B_D] and dst_addr_op.base in sfb_regs:
                    self.innoc_writes.append(inst.address)
                    continue
                elif dst_addr_op.addressing_mode == AddressingMode.AM_B_I and dst_addr_op.base in sfb_regs or dst_addr_op.index in sfb_regs:
                    asmWrite.isDependent = False
                elif dst_addr_op.addressing_mode == AddressingMode.AM_B_D and self.points_to_static_sec(dst_addr_op.displacement):
                    asmWrite.isDependent = False
                elif dst_addr_op.addressing_mode == AddressingMode.AM_B_I_D and (
                    dst_addr_op.base in sfb_regs or dst_addr_op.index in sfb_regs or self.points_to_static_sec(dst_addr_op.displacement)
                ):
                    asmWrite.isDependent = False
                elif dst_addr_op.addressing_mode == AddressingMode.AM_B_I_S and dst_addr_op.base in sfb_regs:
                    asmWrite.isDependent = False
                elif dst_addr_op.addressing_mode == AddressingMode.AM_I_S_D and self.points_to_static_sec(dst_addr_op.displacement):
                    asmWrite.isDependent = False
                elif dst_addr_op.addressing_mode == AddressingMode.AM_B_I_S_D and (
                    dst_addr_op.base in sfb_regs or self.points_to_static_sec(dst_addr_op.displacement)
                ):
                    asmWrite.isDependent = False
                else:
                    asmWrite.isDependent = True

                asmWrite.srcLoc = putFunc.addrToLine[inst.address]

                # print(
                #    f"{'dependent: ' if asmWrite.isDependent else 'independent: '}{hex(asmWrite.inst.address)}: {asmWrite.inst.mnemonic} {asmWrite.inst.op_str}"
                # )

                putFunc.asmWrites.append(asmWrite)
