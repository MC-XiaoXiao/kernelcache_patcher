#pragma once

#include <KernelMacho.h>

void patch_kext_to_kernel(KernelMacho& y_kernel, KernelMacho& i_kernel);
uint32_t patch_ios_kernel(KernelMacho& kernel, const char* patch_path);