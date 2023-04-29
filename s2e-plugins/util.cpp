#include "util.h"

#include <s2e/cpu.h>

using namespace klee;

namespace s2e {
namespace plugins {

/*
 * Convert the name of a KLEE symbolic value to the name that is used as a key in the pointer store
 */
std::string getPtrStoreKeyFromName(std::string rawName, std::string prefix) {
    size_t prefixStart = rawName.find(prefix);
    auto firstSepPos = prefixStart + prefix.length() + rawName.substr(prefixStart + prefix.length()).find("_");
    auto secondSepPos = firstSepPos + 1 + rawName.substr(firstSepPos + 1).find("_");

    return rawName.substr(prefixStart, secondSepPos - prefixStart + 1);
}

/*
 * Assumption: A pointer-creating instruction will always create a QWORD or DWORD pointer, hence we only need to take
 * care of the 64-bit and 32-bit registers. In x64, 8-bit or 16-bit operations on 64-bit registers don't cause the upper
 * bits to be zeroed (contrary to 32-bit ops on 64-bit regs), hence using these operations for pointer creation would be
 * very inconvenient and we assume the compiler never does this.
 *
 */
uint regStrToIdx(std::string regName) {
    if (regName == "RAX" || regName == "EAX")
        return R_EAX;
    if (regName == "RCX" || regName == "ECX")
        return R_ECX;
    if (regName == "RDX" || regName == "EDX")
        return R_EDX;
    if (regName == "RBX" || regName == "EBX")
        return R_EBX;
    if (regName == "RSP" || regName == "ESP")
        return R_ESP;
    if (regName == "RBP" || regName == "EBP")
        return R_EBP;
    if (regName == "RSI" || regName == "ESI")
        return R_ESI;
    if (regName == "RDI" || regName == "EDI")
        return R_EDI;
    if (regName == "R8" || regName == "R8D")
        return 8;
    if (regName == "R9" || regName == "R9D")
        return 9;
    if (regName == "R10" || regName == "R10D")
        return 10;
    if (regName == "R11" || regName == "R11D")
        return 11;
    if (regName == "R12" || regName == "R12D")
        return 12;
    if (regName == "R13" || regName == "R13D")
        return 13;
    if (regName == "R14" || regName == "R14D")
        return 14;
    if (regName == "R15" || regName == "R15D")
        return 15;
    throw std::invalid_argument("Received unknown register " + regName + "\n");
}

}  // namespace plugins
}  // namespace s2e