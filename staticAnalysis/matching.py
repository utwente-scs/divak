from elftools.elf.elffile import ELFFile

from containers import *
from dwarf_analysis import *
from utils import *


class Matcher:
    """
    Contains all the logic for matching things (memory objects, writes) from the IR to DWARF/ASM
    """

    elffile: ELFFile

    def __init__(self, elffile: ELFFile, dwarfAnalyzer: DwarfAnalyzer, statsCollector: StatsCollector):
        self.elffile = elffile
        self.dwarfAnalyzer = dwarfAnalyzer

        handler = logging.FileHandler("matching.log", mode="w")
        handler.setFormatter(logging.Formatter("%(levelname)s:%(message)s"))

        self.logger = logging.getLogger("matching_logger")
        self.logger.setLevel("DEBUG")
        self.logger.addHandler(handler)

        self.stats = statsCollector

    def match_writes(self):
        """
        For each PuT_Function in put_funcs, attempts to match its PuT_IrWrite(s) to its PuT_AsmWrites
        """

        for put_func in self.dwarfAnalyzer.put_funcs:
            assert isinstance(put_func, PuT_Function)
            if not len(put_func.asmWrites):
                continue

            logging.debug(f"----- {put_func.name} -----")
            n_static_writes = sum(map(lambda w: w.isStaticWrite, put_func.irWrites))
            n_independent_writes = sum(map(lambda w: not w.isDependent, put_func.asmWrites))
            logging.debug(f"{n_static_writes} static writes in IR, {n_independent_writes} independent writes in ASM")

            for asmWrite in put_func.asmWrites:
                if asmWrite.isDependent:
                    continue  # dependent writes are bounds-checked via the taint of their pointer
                if asmWrite.irWrite:
                    continue  # already matched

                match_irws_mixed = [irw for irw in put_func.irWrites if asmWrite.srcLoc == SrcLoc(irw.srcFile, irw.srcLine, irw.srcColumn)]

                match_irws = [irw for irw in match_irws_mixed if irw.isStaticWrite]

                # The elimination of dependent writes should never result in the elimination of all matches
                assert len(match_irws) != 0 or len(match_irws_mixed) == 0

                if len(match_irws) == 0:
                    self.logger.warning(f"No IR writes for {hex(asmWrite.inst.address)}: {asmWrite.inst.mnemonic} {asmWrite.inst.op_str}")
                    self.stats.n_independent_writes_skipped_no_ir_candidates += 1
                elif len(match_irws) == 1:
                    asmWrite.irWrite = match_irws[0]
                else:
                    self.logger.warning(
                        f"More than one ({len(match_irws)}) IR write at {asmWrite.srcLoc} for {hex(asmWrite.inst.address)}: {asmWrite.inst.mnemonic} {asmWrite.inst.op_str}"
                    )
                    self.stats.n_independent_writes_skipped_multiple_ir_candidates += 1

            n_matchedIndWrites = len([w for w in put_func.asmWrites if not w.isDependent and w.irWrite])
            n_unmatchedIndWrites = len([w for w in put_func.asmWrites if not w.isDependent]) - n_matchedIndWrites
            if n_unmatchedIndWrites:
                logging.warning(f"Found and matched {n_matchedIndWrites} independent writes, failed to match {n_unmatchedIndWrites}")
            elif n_matchedIndWrites:
                logging.info(f"Found and matched all {n_matchedIndWrites} independent writes")

    def match_mem_objects(self):
        for put_func in self.dwarfAnalyzer.put_funcs:
            assert isinstance(put_func, PuT_Function)
            if not len(put_func.asmWrites):
                continue

            succMatches = 0
            failedMatches = 0

            for asmWrite in put_func.asmWrites:
                assert isinstance(asmWrite, PuT_AsmWrite)
                if not asmWrite.irWrite:
                    # Couldn't match this write earlier, so we have no way to find the dst object
                    continue

                varName = (
                    asmWrite.irWrite.staticWriteDstActualName
                    if asmWrite.irWrite.staticWriteDstActualName
                    else asmWrite.irWrite.staticWriteDstInternalName
                )

                if not varName:
                    self.stats.n_static_writes_skipped_no_original_name += 1
                    failedMatches += 1
                    continue

                # The LLVM pass managed to extract the source code name of the destination variable

                vars = put_func.autoVars if asmWrite.irWrite.staticWriteToAutoVar else self.dwarfAnalyzer.dwarf_static_vars

                matches = [
                    var
                    for var in vars
                    if varName in var.names and (var.end_addr < var.start_addr or var.start_addr <= asmWrite.addr <= var.end_addr)
                ]

                if len(matches) == 0:
                    logging.error(
                        f"Identified destination of static write at {hex(asmWrite.addr)} as IR variable {varName} but can't find a corresponding variable in DWARF"
                    )
                    self.stats.n_static_writes_skipped_no_object_match += 1
                    failedMatches += 1
                    continue
                elif any(var.fragmented for var in matches):
                    self.stats.n_static_writes_skipped_fragmented_var += 1
                    continue
                elif len(matches) == 1:
                    dstVar = matches[0]
                else:
                    logging.error(
                        f"Identified destination of static write at {hex(asmWrite.addr)} as IR variable {varName} but there are more than one corresponding variable in DWARF"
                    )
                    self.stats.n_static_writes_skipped_multiple_object_matches += 1
                    failedMatches += 1
                    # TODO: Implement considering the scope of the variables!
                    continue

                assert isinstance(dstVar, PuT_Variable)

                # Ensure the variable is live
                assert dstVar.start_addr <= asmWrite.addr <= dstVar.end_addr

                if dstVar.fragmented:
                    logging.warning(f"Found a static write to the fragmented variable {varName}, skipping")
                    self.stats.n_static_writes_skipped_fragmented_var += 1
                    continue

                asmWrite.lowerBound = dstVar.address
                asmWrite.upperBound = dstVar.address + dstVar.typeSpec.size - 1

                # not modified with bounds narrowing, stays highest-level
                asmWrite.dstVarDwarfOffset = dstVar.dwarfOffset

                currType = dstVar.typeSpec

                # perform bounds narrowing according to the bounds narrowing indices
                for idx in asmWrite.irWrite.boundsNarrowingIndices:
                    if isinstance(currType, PuT_StructTypeSpec):
                        field = currType.members[idx]
                        currType = field.typeSpec
                        asmWrite.lowerBound += field.offset
                        asmWrite.upperBound = asmWrite.lowerBound + currType.size - 1
                    elif isinstance(currType, PuT_ArrayTypeSpec):
                        currType = currType.elemType
                        # TODO: this assumes size=stride. Modify to consider the actual stride
                        asmWrite.lowerBound += currType.size * idx
                        asmWrite.upperBound = asmWrite.lowerBound + currType.size - 1
                    else:
                        print(currType)
                        print(asmWrite.irWrite.staticWriteDstActualName)
                        print(f"{asmWrite.irWrite.srcFile}:{asmWrite.irWrite.srcLine}:{asmWrite.irWrite.srcColumn}")
                        assert False

                succMatches += 1
                self.stats.n_independent_writes_successfully_matched += 1

            if failedMatches:
                matchless_names = [
                    asmWrite.irWrite.staticWriteDstActualName
                    if asmWrite.irWrite.staticWriteDstActualName
                    else asmWrite.irWrite.staticWriteDstInternalName
                    for asmWrite in put_func.asmWrites
                    if asmWrite.irWrite and not asmWrite.dstVarDwarfOffset
                ]
                logging.warning(
                    f"Failed to match {failedMatches} out of {succMatches+failedMatches} destination objects of writes for function {put_func.name}: {matchless_names}"
                )
                for asmWrite in put_func.asmWrites:
                    if not asmWrite.irWrite or asmWrite.dstVarDwarfOffset:
                        continue
                    logging.warning(asmWrite.irWrite.instStr)
            elif succMatches:
                logging.info(f"Matched all {succMatches} destination objects of writes for function {put_func.name}")

    def pick_bni_from_many(self, candidates: list, put_func: PuT_Function):
        """
        Picks a BNI from multiple candidates if the following conditions are satisfied:
        1. The candidates are sequential instructions, none is missing
        2. All but the last instruction write to at most one GPR (which is the one in which the pointer is)
        3. Only the last instruction may write to memory
        Picks the last instrution in which the pointer is written to a register as the BNI
        """
        candidates.sort(key=lambda inst: inst.address)

        func_insts = list(put_func.asmInsts.values())

        first_candidate_idx = next((i for i, inst in enumerate(func_insts) if inst == candidates[0]), None)
        assert first_candidate_idx

        if candidates != func_insts[first_candidate_idx : first_candidate_idx + len(candidates)]:
            # the candidates are not sequential instructions
            # could improve this to handle that case
            return None

        written_gpr = None
        last_gpr_writing_candidate = None
        for candidate in candidates:
            written_gprs = [reg for reg in candidate.regs_access()[1] if candidate.reg_name(reg) in amd64_gprs]
            if len(written_gprs) > 1:
                return None
            if len(written_gprs) == 1:
                if written_gpr != None and written_gpr != written_gprs[0]:
                    # A previous candidate writes to a different GPR than this one
                    return None
                written_gpr = written_gprs[0]
                last_gpr_writing_candidate = candidate

            for op in candidate.operands:
                if op.type == X86_OP_MEM and op.access & CS_AC_WRITE:
                    if candidate != candidates[-1]:
                        # An instruction that isn't the last candidate writes to memory
                        return None

        return last_gpr_writing_candidate

    def match_bounds_narrowing_insts_exact_new(self, put_func: PuT_Function):
        for bni in put_func.boundsNarrowingInsts:
            assert isinstance(bni, PuT_BoundsNarrowingInst)
            match_insts = [
                put_func.asmInsts[k] for k, v in put_func.addrToLine.items() if v == SrcLoc(bni.srcFile, bni.srcLine, bni.srcColumn)
            ]
            alt_match_insts = [
                put_func.asmInsts[k]
                for k, v in put_func.addrToLine.items()
                if v == SrcLoc(bni.altSrcFile, bni.altSrcLine, bni.altSrcColumn)
            ]

            candidates = [
                inst for inst in match_insts if inst.is_possible_add_bni() or inst.is_possible_lea_bni() or inst.is_possible_mov_bni()
            ]
            alt_candidates = [
                inst for inst in alt_match_insts if inst.is_possible_add_bni() or inst.is_possible_lea_bni() or inst.is_possible_mov_bni()
            ]

            if len(candidates) > 0:
                matchedOnAltLoc = False
            elif len(alt_candidates) > 0:
                candidates = alt_candidates
                matchedOnAltLoc = True
            else:
                self.logger.warning(f"BNI {bni.srcFile}:{bni.srcLine}:{bni.srcColumn} has no possible matches in ASM")
                self.stats.n_bnis_unmatched_no_candidates += 1
                continue

            candidates.sort(key=lambda inst: inst.address)

            if len(candidates) == 1:
                if bni.addr:
                    # ASM instruction already has a match
                    self.stats.n_bnis_skipped_many_ir_one_asm += 1
                    continue
                if matchedOnAltLoc:
                    self.stats.n_bnis_matched_alternative_loc += 1
                bni.addr = candidates[0].address
                bni.asmInst = candidates[0]
                self.logger.debug(
                    f"found bounds narrowing instruction {hex(bni.asmInst.address)} {bni.asmInst.mnemonic} {bni.asmInst.op_str}"
                )

            elif len(candidates) > 1:
                if candidate := self.pick_bni_from_many(candidates, put_func):
                    if bni.addr:
                        # ASM instruction already has a match
                        self.stats.n_bnis_skipped_many_ir_one_asm += 1
                        continue
                    if matchedOnAltLoc:
                        self.stats.n_bnis_matched_alternative_loc += 1
                    bni.addr = candidate.address
                    bni.asmInst = candidate
                    self.logger.debug(
                        f"found bounds narrowing instruction from many {hex(bni.asmInst.address)} {bni.asmInst.mnemonic} {bni.asmInst.op_str}"
                    )
                else:
                    self.logger.warning(f"found multiple candidates for bounds narrowing instruction:")
                    for candidate in candidates:
                        self.logger.warning(f"\t\t {hex(candidate.address)}: {candidate.mnemonic} {candidate.op_str}")
                    self.logger.warning("")
                    self.stats.n_bnis_unmatched_multiple_candidates += 1
            else:
                assert False

    def match_bounds_narrowing_insts(self):
        logging.debug("")
        logging.debug(f"----- Matching Bounds Narrowing Instructions -----")
        for put_func in self.dwarfAnalyzer.put_funcs:
            assert isinstance(put_func, PuT_Function)
            if not put_func.boundsNarrowingInsts:
                continue
            logging.debug(f"----- {put_func.name} -----")

            self.match_bounds_narrowing_insts_exact_new(put_func)

            n_matched_bnis = len([bni for bni in put_func.boundsNarrowingInsts if bni.addr])
            unmatched_bni = [bni for bni in put_func.boundsNarrowingInsts if not bni.addr]

            if unmatched_bni:
                logging.warning(
                    f"Failed to match {len(unmatched_bni)} of {len(put_func.boundsNarrowingInsts)} bounds-narrowing instructions"
                )
                for bni in unmatched_bni:
                    logging.warning(f"{bni.srcFile} {bni.srcLine} {bni.srcColumn}")
            elif n_matched_bnis:
                logging.info(f"Successfully matched all {len(put_func.boundsNarrowingInsts)} bounds-narrowing instructions")

            # determine the locations the instructions write to
            for bni in put_func.boundsNarrowingInsts:
                assert isinstance(bni, PuT_BoundsNarrowingInst)

                if not bni.addr:
                    continue

                assert len(bni.asmInst.operands) == 2

                dst = bni.asmInst.operands[0]
                if bni.asmInst.operands[0].type == X86_OP_REG:
                    bni.resReg = bni.asmInst.reg_name(dst.reg).upper()
                else:
                    bni.resReg = ""
                    self.stats.n_internal_bnis += 1

                self.stats.n_bnis_successfully_matched += 1
