from elftools.dwarf.descriptions import describe_reg_name, describe_DWARF_expr
from elftools.dwarf.locationlists import LocationParser, LocationExpr, LocationEntry
from elftools.dwarf.dwarf_expr import DWARFExprParser, DWARFExprOp
from elftools.dwarf.die import DIE
from elftools.dwarf.constants import *
from elftools.elf.elffile import ELFFile


import logging
import os
import bisect

from containers import *


@dataclass
class TempVarLoc:
    locs: list = field(default_factory=list)  # Contains tuples (expr, n_bytes). n_bytes = -1 iff no fragmentation
    var_is_fragmented: bool = None
    start_addr: int = None
    end_addr: int = None


class DwarfAnalyzer:
    def __init__(self, elffile: ELFFile, statsCollector: StatsCollector):
        self.elffile = elffile
        self.stats = statsCollector
        self.dwarf_type_specs = []
        self.put_funcs = []
        self.dwarf_static_vars = []

    def add_lineinfo_to_funcs(self):
        lineinfo = dict()
        dwarfinfo = self.elffile.get_dwarf_info()
        assert self.put_funcs

        # Extract lineinfo for the entire program
        for cu in dwarfinfo.iter_CUs():
            line_prog = dwarfinfo.line_program_for_CU(cu)
            filename_cache = dict()

            for entry in line_prog.get_entries():
                if entry.state != None:
                    if entry.state.file not in filename_cache:
                        file_entry = dwarfinfo.line_program_for_CU(cu)["file_entry"][entry.state.file - 1]
                        dir_idx = file_entry["dir_index"]
                        dir_name = line_prog["include_directory"][dir_idx - 1].decode() if line_prog["include_directory"] else ""
                        file_name = file_entry.name.decode()
                        filename_cache[entry.state.file] = os.path.join(dir_name, file_name)

                    lineinfo[entry.state.address] = SrcLoc(filename_cache[entry.state.file], entry.state.line, entry.state.column)

        self.put_funcs.sort(key=lambda f: f.baseAddress)

        # Assign lineinfo for each instruction in each function
        # lineinfo_lst = [(addr, srcLoc) for addr, srcLoc in sorted(lineinfo.items())]
        # bisect in Python < 3.10 doesn't take a key, hence we have to maintain two lists
        lineinfo_addrs = [addr for addr, srcLoc in sorted(lineinfo.items())]
        lineinfo_locs = [srcLoc for addr, srcLoc in sorted(lineinfo.items())]
        # i = 0
        # curr_loc = lineinfo_lst[i]
        # next_loc = lineinfo_lst[i + 1]
        for put_func in self.put_funcs:
            assert isinstance(put_func, PuT_Function)
            for addr, inst in sorted(put_func.asmInsts.items()):
                # Find the lineinfo for the largest address that's smaller than addr
                i = bisect.bisect(lineinfo_addrs, addr) - 1
                if i < 0 or lineinfo_addrs[i] < put_func.baseAddress:
                    # Debug entry is either non-existent or for the previous function
                    put_func.addrToLine[addr] = SrcLoc("", -1, -1)
                    continue

                # if addr == next_loc[0]:
                #    i += 1
                #    curr_loc = lineinfo_lst[i]
                #    next_loc = lineinfo_lst[i + 1] if i + 1 != len(lineinfo_lst) else None

                put_func.addrToLine[addr] = lineinfo_locs[i]

    def eliminate_var_overlaps(self):
        """ """
        VarInterval = namedtuple("VarInterval", ["lower", "upper", "var"])

        for func in self.put_funcs:
            intervals = []
            for autoVar in func.autoVars:
                lower = autoVar.address
                upper = autoVar.address + (autoVar.n_fragment_bytes if autoVar.fragmented else autoVar.typeSpec.size) - 1
                intervals.append(VarInterval(lower, upper, autoVar))

            intervals.sort(key=lambda e: (e.lower, e.upper))

            i = 0
            while i + 1 < len(intervals):
                overlaps = [intervals[i]]
                # Find all variables that have the same spatial position
                while (
                    i + 1 < len(intervals) and overlaps[0].lower == intervals[i + 1].lower and overlaps[0].upper == intervals[i + 1].upper
                ):
                    overlaps.append(intervals[i + 1])
                    i += 1
                i += 1

                if len(overlaps) > 1:
                    lifetime_start = min(ov.var.start_addr for ov in overlaps)
                    lifetime_end = max(ov.var.end_addr for ov in overlaps)
                    overlaps[0].var.start_addr = lifetime_start
                    overlaps[0].var.end_addr = lifetime_end

                    for ov in overlaps[1:]:
                        # TODO: This causes us to loose some information (whether the function of the variable is inlined, the name of the inlined function...)
                        overlaps[0].var.names += ov.var.names
                        func.autoVars.remove(ov.var)
                    overlaps[0].var.names = list(set(overlaps[0].var.names))  # eliminate duplicates
        # assert False

    def run_dwarf_analysis(self):
        for CU in self.elffile.get_dwarf_info().iter_CUs():
            for DIE in CU.iter_DIEs():
                if DIE.tag == "DW_TAG_subprogram":
                    self.dismantle_func(DIE)
                elif DIE.tag in ["DW_TAG_variable", "DW_TAG_formal_parameter", "DW_TAG_constant"]:
                    self.dismantle_var(DIE)

        self.eliminate_var_overlaps()

    def get_DIE_from_ref_attr(self, baseDIE: DIE, attrName: str):
        """
        Given a DIE attribute that points to another DIE, return this other DIE.
        """
        attr = baseDIE.attributes[attrName]
        if attr.form == "DW_FORM_ref_addr":
            # Absolute address, from base of dwarf
            pointeeDIE = baseDIE.dwarfinfo.get_DIE_from_refaddr(attr.value)
        elif attr.form == "DW_FORM_ref4":
            # Relative address, from base of CU
            pointeeDIE = baseDIE.cu.get_DIE_from_refaddr(baseDIE.cu.cu_offset + attr.value)
        else:
            raise NotImplementedError()

        return pointeeDIE

    def split_pieces(self, exprs: list):
        """
        Given a list of DWARF expressions describing the location of a variable at a certain time, yield a list for each location description of a piece.
        """
        curr_piece = []

        for expr in exprs:
            assert isinstance(expr, DWARFExprOp)
            if expr.op_name == "DW_OP_piece":
                assert len(expr.args) == 1
                n_bytes = expr.args[0]
                if curr_piece:
                    yield curr_piece, n_bytes
                curr_piece.clear()
            else:
                curr_piece.append(expr)

        if curr_piece:
            yield curr_piece, -1

    def loc_expr_to_mem_loc(self, loc_expr: list, expr_parser: DWARFExprParser):
        """
        Takes a list of DwarfExprOp that describes the location of a variable at one point in its lifetime.
        """
        assert isinstance(loc_expr, list)
        loc_expr_lst = expr_parser.parse_expr(loc_expr)

        temp_var_loc = TempVarLoc()
        temp_var_loc.var_is_fragmented = any(e.op_name == "DW_OP_piece" for e in loc_expr_lst)

        for piece, n_bytes in self.split_pieces(loc_expr_lst):
            assert not any(e.op_name == "DW_OP_stack_value" for e in piece[:-1])
            if piece[-1].op_name == "DW_OP_stack_value":
                continue

            for expr in piece:
                assert isinstance(expr, DWARFExprOp)

                if expr.op_name.startswith("DW_OP_reg"):
                    continue  # value is located in register
                elif expr.op_name == "DW_OP_implicit_value":
                    continue  # Value is implicit, not in memory or register
                elif expr.op_name == "DW_OP_piece":
                    continue  # Type is split up into multiple parts, we handle it above already
                elif expr.op_name == "DW_OP_addr":
                    temp_var_loc.locs.append((expr, n_bytes))
                elif expr.op_name == "DW_OP_fbreg":
                    temp_var_loc.locs.append((expr, n_bytes))
                elif expr.op_name.startswith("DW_OP_breg"):
                    temp_var_loc.locs.append((expr, n_bytes))
                else:
                    print(expr)
                    assert False

        return temp_var_loc

    def apply_ancestor_die_lifetime_to_var(self, ancestorDIE: DIE, temp_var_locs: list):
        """
        Decrease the lifetime of temporary locations of a variable according to the lifetime dictated by an ancestor DIE.
        Such ancestor DIEs are typically inlined subprogram DIEs and lexical block DIEs
        """
        if "DW_AT_ranges" in ancestorDIE.attributes:
            range_entry_lst = ancestorDIE.dwarfinfo.range_lists().get_range_list_at_offset(ancestorDIE.attributes["DW_AT_ranges"].value)

            # This here is a bit dirty. We simply take the beginning of the first range and the end of the last range and
            # assume everything in between is the lifetime, even though there are most certainly gaps in there.
            base = ancestorDIE.cu.get_top_DIE().attributes["DW_AT_low_pc"].value
            lifetime_start = base + range_entry_lst[0].begin_offset
            lifetime_end = base + range_entry_lst[-1].end_offset
            # print(f"{hex(lifetime_start)} {hex(lifetime_end)}")
        else:
            lifetime_start = ancestorDIE.attributes["DW_AT_low_pc"].value
            lifetime_end = lifetime_start + ancestorDIE.attributes["DW_AT_high_pc"].value

        for temp_loc in temp_var_locs:
            assert isinstance(temp_loc, TempVarLoc)
            # print(f"{hex(temp_loc.end_addr)} {hex(lifetime_end)}")
            # TODO: Check if these assertions are actually reasonable and variables violating them might overlap
            # assert temp_loc.start_addr == 0 or temp_loc.start_addr >= lifetime_start
            # assert temp_loc.end_addr == -1 or temp_loc.end_addr <= lifetime_end
            temp_loc.start_addr = max(temp_loc.start_addr, lifetime_start)
            temp_loc.end_addr = min(temp_loc.end_addr, lifetime_end)

    def dismantle_var(self, varDIE: DIE):
        if "DW_AT_const_value" in varDIE.attributes:
            # compile-time constant, no representation in address space
            return
        if "DW_AT_location" not in varDIE.attributes:
            parent = varDIE.get_parent()
            if (
                parent.tag == "DW_TAG_subroutine_type"
                and "DW_AT_prototyped" in parent.attributes
                and parent.attributes["DW_AT_prototyped"].value
            ):
                return
            elif parent.tag == "DW_TAG_subprogram":
                if "DW_AT_inline" in parent.attributes and parent.attributes["DW_AT_inline"].value in [
                    DW_INL_inlined,
                    DW_INL_declared_inlined,
                ]:
                    return
                elif "DW_AT_declaration" in parent.attributes and parent.attributes["DW_AT_declaration"].value:
                    return

            # logging.warning(f"variable-like entity at offset {hex(varDIE.offset)} doesn't have a DW_AT_location")
            return

        # metaDIE is the DIE that contains metadata such as variable name, declared file etc. It's not the same as the variable DIE if the function is marked as inlined
        if "DW_AT_abstract_origin" in varDIE.attributes:
            metaDIE = self.get_DIE_from_ref_attr(varDIE, "DW_AT_abstract_origin")
        else:
            metaDIE = varDIE

        var_name = metaDIE.attributes["DW_AT_name"].value.decode("ascii") if "DW_AT_name" in metaDIE.attributes else None

        typeDIE = self.get_DIE_from_ref_attr(metaDIE, "DW_AT_type")
        try:
            typeSpec = self.dismantle_type(typeDIE)
        except NotImplementedError:
            logging.error(f"Failed to analyze type of variable {var_name}, skipping variable...")
            return

        # Parse the address
        loc_parser = LocationParser(varDIE.dwarfinfo.location_lists())
        expr_parser = DWARFExprParser(varDIE.dwarfinfo.structs)

        loc = loc_parser.parse_from_attribute(varDIE.attributes["DW_AT_location"], varDIE.cu["version"])

        temp_var_locs = []

        if isinstance(loc, LocationExpr):
            # it's a single location, the position of the variable doesn't change over its lifetime
            temp_var_loc = self.loc_expr_to_mem_loc(loc.loc_expr, expr_parser)
            temp_var_loc.start_addr = 0
            temp_var_loc.end_addr = VAR_LIFETIME_END_MAX
            temp_var_locs.append(temp_var_loc)

        elif isinstance(loc, list):
            # it's a location list, the variable changes location over its lifetime
            for loc_entry in loc:
                assert isinstance(loc_entry, LocationEntry)

                base = varDIE.cu.get_top_DIE().attributes["DW_AT_low_pc"].value

                temp_var_loc = self.loc_expr_to_mem_loc(loc_entry.loc_expr, expr_parser)
                temp_var_loc.start_addr = base + loc_entry.begin_offset
                temp_var_loc.end_addr = base + loc_entry.end_offset

                temp_var_locs.append(temp_var_loc)
        else:
            assert False

        temp_var_locs = [loc for loc in temp_var_locs if loc.locs]
        if not temp_var_locs:
            return  # The variable never exists in memory

        # Determine whether the variable is local, automatic or inlined
        is_automatic = None
        is_local = None
        is_inlined = False
        inlined_fun_name = None
        func = None
        currDIE = varDIE.get_parent()
        found_lifetime_limiting_die = False
        while currDIE:
            if currDIE.tag == "DW_TAG_compile_unit":
                is_automatic = False
                is_local = False
                break

            elif currDIE.tag == "DW_TAG_subprogram" and currDIE.get_parent().tag == "DW_TAG_compile_unit":
                is_local = True
                if len(currDIE.attributes):
                    func = find_unique_match(currDIE, self.put_funcs, lambda die, f: die.offset == f.dwarfOffset)
                else:  # function is basically optimized out
                    func = None
                # can't say anything about whether it's automatic or not at this point, depends on the location
                break

            elif currDIE.tag == "DW_TAG_subprogram":
                raise NotImplementedError("Variable is in nested subprogram")
            elif currDIE.tag == "DW_TAG_inlined_subroutine":
                assert not "DW_AT_frame_base" in currDIE.attributes
                if not is_inlined:  # we only care about the innermost inlined function
                    is_inlined = True

                    # Find the name of the inlined function that the variable logically belongs to
                    inlined_fun_name = (
                        currDIE.attributes["DW_AT_name"].value.decode("ascii") if "DW_AT_name" in currDIE.attributes else None
                    )
                    if "DW_AT_name" in currDIE.attributes:
                        inlined_fun_name = currDIE.attributes["DW_AT_name"].value.decode("ascii")
                    elif "DW_AT_abstract_origin" in currDIE.attributes:
                        funcMetaDIE = self.get_DIE_from_ref_attr(currDIE, "DW_AT_abstract_origin")
                        inlined_fun_name = (
                            funcMetaDIE.attributes["DW_AT_name"].value.decode("ascii") if "DW_AT_name" in funcMetaDIE.attributes else None
                        )
                    else:
                        inlined_fun_name = None
                if not found_lifetime_limiting_die:
                    found_lifetime_limiting_die = True
                    self.apply_ancestor_die_lifetime_to_var(currDIE, temp_var_locs)
            elif currDIE.tag == "DW_TAG_lexical_block":
                if not found_lifetime_limiting_die:
                    found_lifetime_limiting_die = True
                    self.apply_ancestor_die_lifetime_to_var(currDIE, temp_var_locs)

            currDIE = currDIE.get_parent()

        # Create the actual variable records to be passed on to S2E
        for temp_var_loc in temp_var_locs:
            assert isinstance(temp_var_loc, TempVarLoc)

            # Iterate over the locations in memory at which (fragments of) the variable are stored
            for mem_loc_info, n_bytes in temp_var_loc.locs:
                assert not (temp_var_loc.var_is_fragmented and n_bytes == -1)  # can't have a fragment for which we don't know the size
                var = PuT_Variable()
                var.dwarfOffset = varDIE.offset
                var.names = [var_name]

                var.typeSpec = typeSpec
                assert len(mem_loc_info.args) == 1
                var.address = mem_loc_info.args[0]
                var.fragmented = temp_var_loc.var_is_fragmented
                var.n_fragment_bytes = n_bytes
                var.inlined = is_inlined
                var.inlined_fun_name = inlined_fun_name if is_inlined else None
                var.formalParameter = varDIE.tag == "DW_TAG_formal_parameter"
                var.start_addr = temp_var_loc.start_addr
                var.end_addr = temp_var_loc.end_addr

                if mem_loc_info.op_name == "DW_OP_addr":
                    assert not is_automatic
                    var.automatic = False
                    var.local = is_local
                    self.dwarf_static_vars.append(var)
                elif mem_loc_info.op_name == "DW_OP_fbreg":
                    # variable is addressed relative to frame base
                    var.automatic = True
                    var.local = is_local
                    func.autoVars.append(var)
                elif mem_loc_info.op_name.startswith("DW_OP_breg"):
                    reg_num = int(mem_loc_info.op_name[len("DW_OP_breg") :])
                    reg_name = describe_reg_name(reg_num).upper()
                    assert reg_name == "RBP"
                    var.automatic = True
                    var.local = is_local
                    func.autoVars.append(var)
                else:
                    raise NotImplementedError()

    def dismantle_func(self, funcDIE: DIE):
        """
        Takes a DIE representing a function, dissects it and adds it to the collection put_funcs
        """

        # Sometimes there are function stubs of functions that were optimized out. They might still contain static variables but that's no problem
        if not len(funcDIE.attributes):
            return

        # The function is merely a declaration, doesn't have a definition, hence this DIE does not correspond to actual code in the binary
        if "DW_AT_declaration" in funcDIE.attributes and funcDIE.attributes["DW_AT_declaration"].value == True:
            return

        # These DIEs of inlined functions do not have corresponding code in the assembly
        if "DW_AT_inline" in funcDIE.attributes and funcDIE.attributes["DW_AT_inline"].value in [DW_INL_inlined, DW_INL_declared_inlined]:
            return

        # metaDIE is the DIE that contains metadata such as function name, declared file etc. It's not the same as the function DIE if the function is marked as inlined
        if "DW_AT_abstract_origin" in funcDIE.attributes:
            metaDIE = self.get_DIE_from_ref_attr(funcDIE, "DW_AT_abstract_origin")
        else:
            metaDIE = funcDIE

        func = PuT_Function()
        func.dwarfOffset = funcDIE.offset
        func.cu = funcDIE.cu
        func.name = metaDIE.attributes["DW_AT_name"].value.decode("ascii") if "DW_AT_name" in metaDIE.attributes else None

        # find the relative path of the file where the function is *declared*
        line_prog = metaDIE.dwarfinfo.line_program_for_CU(metaDIE.cu)
        file_idx = metaDIE.attributes["DW_AT_decl_file"].value
        file_name = line_prog["file_entry"][file_idx - 1].name.decode()
        dir_idx = line_prog["file_entry"][file_idx - 1].dir_index
        dir_name = line_prog["include_directory"][dir_idx - 1].decode() if line_prog["include_directory"] else ""
        func.srcFileName = os.path.join(dir_name, file_name)

        assert funcDIE.attributes["DW_AT_low_pc"].form == "DW_FORM_addr"
        func.baseAddress = funcDIE.attributes["DW_AT_low_pc"].value
        assert funcDIE.attributes["DW_AT_high_pc"].form.startswith("DW_FORM_data")  # ensure it's a constant
        func.lastAddress = func.baseAddress + funcDIE.attributes["DW_AT_high_pc"].value

        # Determine the base register of the function's automatic variable locations
        assert funcDIE.attributes["DW_AT_frame_base"].form == "DW_FORM_exprloc"
        rel_regnum = funcDIE.attributes["DW_AT_frame_base"].value[0] - 0x50  # 0x50 is some hardcoded register base thingy
        func.baseReg = describe_reg_name(rel_regnum).upper()

        self.put_funcs.append(func)

    def set_type_mnemonic(self, type: PuT_AbstractTypeSpec):
        assert isinstance(type, PuT_AbstractTypeSpec)
        type_orig = type
        mnemonic = ""
        while isinstance(type, PuT_ArrayTypeSpec):
            mnemonic += "<" + str(type.n_elems) + ">"
            type = type.elemType

        if isinstance(type, PuT_StructTypeSpec):
            mnemonic += type.name if type.name else ""
        else:
            mnemonic = ""

        type_orig.mnemonic = mnemonic

    def dismantle_type(self, typeDIE: DIE):
        if typeDIE.tag in ["DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_restrict_type", "DW_TAG_volatile_type"]:
            innerTypeDIE = self.get_DIE_from_ref_attr(typeDIE, "DW_AT_type")
            return self.dismantle_type(innerTypeDIE)
        elif typeDIE.tag == "DW_TAG_structure_type":
            return self.dismantle_struct(typeDIE)
        elif typeDIE.tag == "DW_TAG_array_type":
            return self.dismantle_array(typeDIE)
        else:
            return self.dismantle_generic_type(typeDIE)

    def dismantle_generic_type(self, typeDIE: DIE):
        if genType := next((t for t in self.dwarf_type_specs if t.dwarfOffset == typeDIE.offset), None):
            return genType

        genType = PuT_GenericTypeSpec()
        genType.dwarfOffset = typeDIE.offset
        genType.name = typeDIE.attributes["DW_AT_name"].value.decode("ascii") if "DW_AT_name" in typeDIE.attributes else None

        # TODO: Could properly set names for pointer and volatile
        if typeDIE.tag == "DW_TAG_pointer_type":
            genType.size = typeDIE.cu.header["address_size"]
        elif typeDIE.tag == "DW_TAG_volatile_type":
            genType.size = self.dismantle_type(self.get_DIE_from_ref_attr(typeDIE, "DW_AT_type")).size
        else:
            genType.size = typeDIE.attributes["DW_AT_byte_size"].value if "DW_AT_byte_size" in typeDIE.attributes else None

        self.dwarf_type_specs.append(genType)

        return genType

    def dismantle_struct(self, structDIE: DIE):
        if struct := next((t for t in self.dwarf_type_specs if t.dwarfOffset == structDIE.offset), None):
            return struct

        struct = PuT_StructTypeSpec()
        struct.dwarfOffset = structDIE.offset
        struct.name = structDIE.attributes["DW_AT_name"].value.decode("ascii") if "DW_AT_name" in structDIE.attributes else None
        struct.size = structDIE.attributes["DW_AT_byte_size"].value

        for memberDIE in structDIE.iter_children():
            if memberDIE.tag != "DW_TAG_member":
                continue
            member = PuT_StructMember()
            member.name = memberDIE.attributes["DW_AT_name"].value.decode("ascii") if "DW_AT_name" in memberDIE.attributes else None
            member.offset = memberDIE.attributes["DW_AT_data_member_location"].value

            memberTypeDIE = self.get_DIE_from_ref_attr(memberDIE, "DW_AT_type")
            member.typeSpec = self.dismantle_type(memberTypeDIE)

            struct.members.append(member)

        self.set_type_mnemonic(struct)

        self.dwarf_type_specs.append(struct)

        return struct

    def dismantle_array(self, arrayDIE: DIE):
        """
        Takes an array type DIE, returns a ArrayTypeSpec describing the array if it (recursively) contains a struct
        or array or a GenericTypeSpec otherwise.
        """
        if arrayTypeSpec := next((t for t in self.dwarf_type_specs if t.dwarfOffset == arrayDIE.offset), None):
            return arrayTypeSpec

        # The things below are allowed in DWARF4 but we're too lazy to handle them for now
        assert "DW_AT_byte_stride" not in arrayDIE.attributes and "DW_AT_bit_stride" not in arrayDIE.attributes
        assert "DW_AT_bit_size" not in arrayDIE.attributes

        # There is usually a null-child at the end, filter it out
        real_children = [child for child in arrayDIE.iter_children() if not child.is_null()]

        # Iterate over the subranges bottom-up to handle multidimensional arrays. Multidimensional arrays contain other arrays as elements
        elemTypeDIE = self.get_DIE_from_ref_attr(arrayDIE, "DW_AT_type")
        childTypeSpec = self.dismantle_type(elemTypeDIE)
        originalChildTypeSpec = childTypeSpec
        for subrngDIE in reversed(real_children):
            assert subrngDIE.tag == "DW_TAG_subrange_type"
            subarrayTypeSpec = PuT_ArrayTypeSpec()
            subarrayTypeSpec.name = None
            subarrayTypeSpec.dwarfOffset = subrngDIE.offset
            subarrayTypeSpec.elemType = childTypeSpec

            if subrngDIE.attributes["DW_AT_count"].form.startswith("DW_FORM_ref"):
                logging.error(f"Array type at DWARF offset {arrayDIE.offset} appears to be VLA, skipping...")
                self.stats.n_vlas_detected += 1
                raise NotImplementedError("Number of elements in array isn't a fixed integer, strong indicator for VLA!")

            subarrayTypeSpec.n_elems = subrngDIE.attributes["DW_AT_count"].value

            # Calculate the size of the array. Doesn't work like this if there is a stride specified
            subarrayTypeSpec.size = subarrayTypeSpec.elemType.size * subarrayTypeSpec.n_elems

            # The things below are allowed in DWARF4 but we're too lazy to handle them for now
            assert "DW_AT_byte_size" not in subrngDIE.attributes and "DW_AT_bit_size" not in subrngDIE.attributes
            assert "DW_AT_lower_bound" not in subrngDIE.attributes and "DW_AT_upper_bound" not in subrngDIE.attributes

            if not subrngDIE == real_children[0]:
                # Do this unless it's the topmost array in the multidimensional array
                childTypeSpec = subarrayTypeSpec
                self.set_type_mnemonic(subarrayTypeSpec)
                self.dwarf_type_specs.append(subarrayTypeSpec)

        # We use the last subrange as the container for the entire multidimensional array
        arrayTypeSpec = subarrayTypeSpec
        arrayTypeSpec.name = arrayDIE.attributes["DW_AT_name"].value.decode("ascii") if "DW_AT_name" in arrayDIE.attributes else None
        arrayTypeSpec.dwarfOffset = arrayDIE.offset

        # If the size of the array is explicitly given, use it. Otherwise use the calculated size
        if "DW_AT_byte_size" in arrayDIE.attributes:
            arrayTypeSpec.size = arrayDIE.attributes["DW_AT_byte_size"].value

        # If the array only contains generic types, we don't care about the array's contents and just represent it by a generic type
        if isinstance(originalChildTypeSpec, PuT_GenericTypeSpec):
            genTypeSpec = PuT_GenericTypeSpec()
            genTypeSpec.name = arrayTypeSpec.name
            genTypeSpec.dwarfOffset = arrayTypeSpec.dwarfOffset
            genTypeSpec.size = arrayTypeSpec.size
            arrayTypeSpec = genTypeSpec

        self.set_type_mnemonic(arrayTypeSpec)

        self.dwarf_type_specs.append(arrayTypeSpec)

        return arrayTypeSpec
