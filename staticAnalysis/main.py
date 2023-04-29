from __future__ import print_function

from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import set_global_machine_arch

from capstone import *
from capstone.x86_const import *

import portion as P

import json
import coloredlogs, logging
import argparse
import os
import time
import shutil
import statistics

from containers import *
from dwarf_analysis import *
from utils import *
from matching import *
from plotter import *
from binary_analysis import *


def parse_ir_analysis(json_dir: str, dwarfAnalyzer: DwarfAnalyzer):
    n_ir_analysis_files = 0
    for filename in os.listdir(json_dir):
        if not (filename.startswith("pass-res-") and filename.endswith(".json") and not filename == "pass-res-aug.json"):
            continue
        n_ir_analysis_files += 1
        logging.warning("handling file " + filename)

        with open(os.path.join(json_dir, filename)) as f:
            ir_analysis_json = json.load(f)

        for j_putFunc in ir_analysis_json["putFunctions"]:

            matches = [
                f
                for f in dwarfAnalyzer.put_funcs
                if j_putFunc["name"] == f.name and check_filenames_match(j_putFunc["srcFileName"], f.srcFileName)
            ]
            if len(matches) == 0:
                logging.info(f"Function {j_putFunc['name']} has been analyzed in IR but does not exist in DWARF. Skipping...")
            elif len(matches) > 1:
                raise RuntimeError(f"Function {j_putFunc['name']} of IR has more than one match in DWARF")
            else:
                func = matches[0]

            func.uniqueName = j_putFunc["uniqueName"]

            for j_irWrite in j_putFunc["memModInsts"]:
                irw_parsed = PuT_IrWrite.from_json(j_irWrite)
                # We don't have a way to match writes without debug info anyways, just discard them
                if irw_parsed.hasDebugInfo:
                    func.irWrites.append(irw_parsed)

            func.boundsNarrowingInsts = [PuT_BoundsNarrowingInst.from_json(j_bni) for j_bni in j_putFunc["boundsNarrowingInsts"]]

    if n_ir_analysis_files == 0:
        raise RuntimeError("There are no IR analysis result files in " + json_dir)


def do_sanity_checks(put_funcs: list, dwarfAnalyzer: DwarfAnalyzer, stats: StatsCollector):
    def getSpatialOverlap(a, b):
        return max(0, min(a[1], b[1]) + 1 - max(a[0], b[0]))

    def getTemporalOverlap(a, b):
        return max(0, min(a[1], b[1]) - max(a[0], b[0]))

    for func in put_funcs:
        intervals = []
        for autoVar in func.autoVars:
            if not any(autoVar.typeSpec.dwarfOffset == ts.dwarfOffset for ts in dwarfAnalyzer.dwarf_type_specs):
                logging.error(
                    f"automatic variable {str(autoVar.names)} of function {func.name} has no matching typeSpec with dwarfOffset {autoVar.typeSpec.dwarfOffset}"
                )
            lower = autoVar.address
            upper = autoVar.address + (autoVar.n_fragment_bytes if autoVar.fragmented else autoVar.typeSpec.size) - 1
            intervals.append((lower, upper, autoVar))

        intervals.sort(key=lambda e: (e[0], e[1]))
        for curr, next in zip(intervals, intervals[1:]):
            curr_var = curr[2]
            next_var = next[2]
            byte_overlap = getSpatialOverlap(curr, next)
            time_overlap = getTemporalOverlap((curr_var.start_addr, curr_var.end_addr), (next_var.start_addr, next_var.end_addr))
            if byte_overlap and time_overlap:
                logging.warning(
                    f"Automatic variables {str(curr_var.names)} and {str(next_var.names)} of function {func.name} overlap on {byte_overlap} bytes"
                )
                stats.n_overlapping_objects += 1

    for staticVar in dwarfAnalyzer.dwarf_static_vars:
        if not any(staticVar.typeSpec.dwarfOffset == ts.dwarfOffset for ts in dwarfAnalyzer.dwarf_type_specs):
            logging.error(
                f"static variable {str(staticVar.names)} has no matching typeSpec with dwarfOffset {staticVar.typeSpec.dwarfOffset}"
            )


def analyze_stack_frame(put_func: PuT_Function):
    assert isinstance(put_func, PuT_Function)
    res = {"n_pushed_regs": 0, "n_rsp_inc": 0}

    for addr, inst in put_func.asmInsts.items():
        assert isinstance(inst, Inst)
        if inst.id == X86_INS_SUB and inst.operands[0].reg == X86_REG_RSP:
            assert res["n_rsp_inc"] == 0
            res["n_rsp_inc"] = inst.operands[1].value.imm
        elif inst.id == X86_INS_PUSH:
            if inst.operands[0].reg == X86_REG_RBP:
                pass
            else:
                res["n_pushed_regs"] += 1
        elif inst.id == X86_INS_MOV and inst.operands[0].reg == X86_REG_RBP and inst.operands[1].reg == X86_REG_RSP:
            pass
        else:
            return res

    assert False


def find_uncharted_frame_ratios(put_funcs: list):
    uncharted_ratios = []

    for put_func in put_funcs:
        assert isinstance(put_func, PuT_Function)
        frame_dets = analyze_stack_frame(put_func)
        n_frame_bytes = frame_dets["n_pushed_regs"] * 8 + frame_dets["n_rsp_inc"]

        if frame_dets["n_rsp_inc"] == 0:
            continue

        # Saved RIP and RBP are also part of the stack frame but they're always there, hence we just ignore them.
        # We don't end at 0 because 0 = RBP, which is already occupied by the saved RBP
        frame_ival = P.closed(-n_frame_bytes, -1 - (frame_dets["n_pushed_regs"] * 8))

        for auto_var in put_func.autoVars:
            assert isinstance(auto_var, PuT_Variable)
            frame_ival = frame_ival - P.closed(auto_var.address, auto_var.address + auto_var.typeSpec.size - 1)

        unclaimed_bytes = 0

        for unclaimed_ival in frame_ival:
            if unclaimed_ival.empty:
                continue
            if unclaimed_ival.lower == -n_frame_bytes:
                # This is the topmost chunk of the stack frame, likely used for passing arguments
                continue
            lower = unclaimed_ival.lower if unclaimed_ival.left == P.Bound.CLOSED else unclaimed_ival.lower + 1
            upper = unclaimed_ival.upper if unclaimed_ival.right == P.Bound.CLOSED else unclaimed_ival.upper - 1
            n_bytes = upper - lower + 1
            if n_bytes >= 8:
                unclaimed_bytes += n_bytes
                #s = f"{put_func.name} has {n_bytes} bytes of unclaimed space at {unclaimed_ival}"
                #print(f"{s} {(100 - len(s)) * ' '} {'-' * n_bytes}")

        uncharted_ratios.append((unclaimed_bytes / frame_dets["n_rsp_inc"]) * 100)

    return uncharted_ratios


level_styles = {
    "debug": {"color": "green"},
    "info": {"color": "blue"},
    "warning": {"color": "yellow"},
    "error": {"color": "red"},
    "critical": {"bold": True, "color": "red"},
    "notice": {"color": "magenta"},
    "spam": {"color": "green", "faint": True},
    "success": {"bold": True, "color": "green"},
    "verbose": {"color": "blue"},
}
logging.basicConfig(filename="static_python.log", filemode="w", level=logging.DEBUG)
coloredlogs.install(fmt="%(levelname)s:%(message)s", level_styles=level_styles, level="DEBUG")
logging.getLogger("matplotlib").setLevel(logging.WARNING)


def augment_pass_results(json_dir, elf_filename, plot_stack_frames=False):

    with open(elf_filename, "rb") as f:
        elffile = ELFFile(f)

        assert elffile.has_dwarf_info()
        assert elffile.get_machine_arch() == "x64"
        set_global_machine_arch(elffile.get_machine_arch())

        stats = StatsCollector()

        dwarfAnalyzer = DwarfAnalyzer(elffile, stats)
        binaryAnalyzer = BinaryAnalyzer(elffile, stats)
        matcher = Matcher(elffile, dwarfAnalyzer, stats)

        elf_segments = binaryAnalyzer.processSegments()

        # Extract information from DWARF
        logging.info(f"\n\t----- Starting DWARF analysis -----")
        start = time.time()
        dwarfAnalyzer.run_dwarf_analysis()
        logging.info(f"done ({time.time() - start})")

        # Process results of IR analysis
        logging.info(f"\n\t----- Parsing IR Analysis -----")
        start = time.time()
        parse_ir_analysis(json_dir, dwarfAnalyzer)
        logging.info(f"done ({time.time() - start})")

        # Extract information from the ELF
        logging.info(f"\n\t----- Adding Assembly to Functions -----")
        start = time.time()
        binaryAnalyzer.add_assembly_to_functions(dwarfAnalyzer.put_funcs)
        logging.info(f"done ({time.time() - start})")

        logging.info(f"\n\t----- Adding Lineinfo to Functions -----")
        start = time.time()
        dwarfAnalyzer.add_lineinfo_to_funcs()
        logging.info(f"done ({time.time() - start})")

        logging.info(f"\n\t----- Extracting ASM Writes -----")
        start = time.time()
        binaryAnalyzer.extract_asm_writes(dwarfAnalyzer.put_funcs)
        logging.info(f"done ({time.time() - start})")

        logging.info(f"\n\t----- Matching Independent Writes -----")
        start = time.time()
        matcher.match_writes()
        logging.info(f"done ({time.time() - start})")

        logging.info(f"\n\t----- Matching Memory Objects -----")
        start = time.time()
        matcher.match_mem_objects()
        logging.info(f"done ({time.time() - start})")

        logging.info(f"\n\t----- Matching Bounds Narrowing Instructions-----")
        start = time.time()
        matcher.match_bounds_narrowing_insts()
        logging.info(f"done ({time.time() - start})")

        llvm_json = dict()
        llvm_json["libFunCallAddrs"] = binaryAnalyzer.extract_lib_function_addrs()
        llvm_json["segments"] = elf_segments
        llvm_json["pointerCreationSites"] = binaryAnalyzer.findPtrCreationSites()
        llvm_json["dwarf_type_specs"] = [typeSpec.to_json() for typeSpec in dwarfAnalyzer.dwarf_type_specs]
        llvm_json["dwarf_functions"] = [func.to_json() for func in dwarfAnalyzer.put_funcs]
        llvm_json["dwarf_static_vars"] = [var.to_json() for var in dwarfAnalyzer.dwarf_static_vars]
        llvm_json["innocuous_writes"] = binaryAnalyzer.innoc_writes

        if plot_stack_frames:
            plots_dir = json_dir + "/stack_frame_plots"
            shutil.rmtree(plots_dir, ignore_errors=True)
            os.mkdir(plots_dir)
            for func in dwarfAnalyzer.put_funcs:
                plot_stack_frame(func, plots_dir)

        noSizeTypeSpecs = [ts for ts in dwarfAnalyzer.dwarf_type_specs if not ts.size]
        if len(noSizeTypeSpecs):
            logging.warning(
                f"Failed to determine the size of {len(noSizeTypeSpecs)} types. Their offsets: {[hex(ts.dwarfOffset) for ts in noSizeTypeSpecs]}"
            )

        do_sanity_checks(dwarfAnalyzer.put_funcs, dwarfAnalyzer, stats)

        uncharted_ratios = find_uncharted_frame_ratios(dwarfAnalyzer.put_funcs)
        stats.uncharted_stack_frame_mean = statistics.mean(uncharted_ratios)
        stats.uncharted_stack_frame_median = statistics.median(uncharted_ratios)
        stats.uncharted_stack_frame_stdev = statistics.stdev(uncharted_ratios)

        # Write the augmented JSON back to file
        # dst_file_split = ir_analysis_filename.rsplit(".", 1)
        # dst_file = dst_file_split[0] + "-aug." + dst_file_split[1]
        dst_file = json_dir + "/pass-res-aug.json"
        with open(dst_file, "w") as f:
            json.dump(llvm_json, f, indent=4)

        n_unmatched_bnis = (
            stats.n_bnis_unmatched_multiple_candidates + stats.n_bnis_unmatched_no_candidates + stats.n_bnis_skipped_many_ir_one_asm
        )

        logging.info(f"Matched/unmatched bounds narrowing instructions: {stats.n_bnis_successfully_matched} / {n_unmatched_bnis}")
        # logging.info(f"Matched/unmatched independent writes: {matcher.n_ind_writes_matched} / {matcher.n_ind_writes_unmatched}")

        stats.print()
        stats_file = json_dir + "/python-stats.json"
        with open(stats_file, "w") as f:
            json.dump(stats.to_json(), f, indent=4)

        n_total_pcis = stats.n_pcs_discovered + stats.n_pcs_skipped_conditional_mov + stats.n_pcs_skipped_memory_dst
        logging.info(f"Ratio of PCIs with memory destination: {stats.n_pcs_skipped_memory_dst / n_total_pcis}")
        logging.info(f"Ratio of CMOV PCIs: {stats.n_pcs_skipped_conditional_mov / n_total_pcis}")

        n_stack_objects = sum(len(func.autoVars) for func in dwarfAnalyzer.put_funcs)
        logging.info(f"Ratio of overlapping stack objects: {stats.n_overlapping_objects / n_stack_objects}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Do the static analysis")
    parser.add_argument("--elf", type=str, required=True, help="path to the ELF file")
    parser.add_argument("--json_dir", type=str, required=True, help="path to the JSON files")
    parser.add_argument(
        "--plot_stack_frames", nargs="?", type=bool, required=False, const=False, help="hwether to plot the extracted stack frames"
    )

    args = parser.parse_args()
    augment_pass_results(args.json_dir, args.elf, args.plot_stack_frames)
