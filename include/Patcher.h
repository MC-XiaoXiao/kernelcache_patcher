#pragma once

#include <KernelMacho.h>
#include <Resolver.h>

// Returns the number of unresolved external relocations. SIZE_MAX indicates
// an internal disassembler/assembler initialization failure.
size_t patch_kext_to_kernel(KernelMacho& y_kernel, KernelMacho& i_kernel, const LinkResolver* resolver = nullptr);
uint32_t patch_ios_kernel(KernelMacho& kernel, const char* patch_path);
