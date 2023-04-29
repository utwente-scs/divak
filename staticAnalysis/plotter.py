import matplotlib.pyplot as plt
import matplotlib.patches as patches
from containers import *
import numpy as np

import os


def plot_stack_frame(func: PuT_Function, dst_dir: str):

    if not func.autoVars:
        return

    pc_func_start = func.baseAddress
    pc_func_end = func.lastAddress
    frame_width = abs(min([var.address for var in func.autoVars]))

    fig, ax = plt.subplots()

    var_names = list(set(str(var.names) for var in func.autoVars))
    colors = plt.get_cmap("viridis")(np.linspace(0, 1, len(var_names)))
    colors_dict = {name: color for name, color in zip(var_names, colors)}

    seen_vars = set()

    for var in sorted(func.autoVars, key=lambda v: (v.address, v.start_addr)):
        assert isinstance(var, PuT_Variable)

        # Create a Rectangle patch
        upper_left = (var.address, max(var.start_addr, pc_func_start))  # (x,y)
        width = var.typeSpec.size if not var.fragmented else var.n_fragment_bytes
        height = var.end_addr - var.start_addr if var.start_addr else pc_func_end - pc_func_start

        if var.dwarfOffset in seen_vars:
            rect = patches.Rectangle(
                upper_left, width, height, linewidth=1, edgecolor="r", facecolor=colors_dict[str(var.names)], alpha=0.3
            )
        else:
            label = str(var.names) + (" (f)" if var.fragmented else f"({var.typeSpec.size})")
            rect = patches.Rectangle(
                upper_left, width, height, linewidth=1, edgecolor="r", facecolor=colors_dict[str(var.names)], alpha=0.3, label=label
            )

        # Add the patch to the Axes
        ax.add_patch(rect)

        seen_vars.add(var.dwarfOffset)

    ax.set_ylim(pc_func_start - 1, pc_func_end + 1)
    ax.set_xlim(-frame_width - 1, 1)
    ax.set_title(func.name)
    ax.legend()

    # plt.show()
    img_path = "/"
    ctr = 0
    while os.path.exists(img_path):
        img_path = dst_dir + "/" + func.name + ("" if ctr == 0 else ("-" + str(ctr))) + ".png"
        ctr += 1

    plt.savefig(img_path)
    plt.close()
