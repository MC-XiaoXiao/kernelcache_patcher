
#include <set>
#include <unordered_set>
#include <cinttypes>
#include <limits>

#include <capstone/capstone.h>
#include <keystone/keystone.h>
#include <tinyxml2.h>

#include <Patcher.h>
#include <Plist.h>

static bool resolve_kernel_reference(uint64_t source_address, KernelMacho& source_kernel,
    KernelMacho& target_kernel, const LinkResolver* resolver, uint64_t& target_address)
{
    if (resolver && resolver->resolve(source_address, target_address))
        return true;

    Symbol* source_symbol = source_kernel.find_symbol_by_addr(source_address);
    if (!source_symbol || !source_symbol->symbol_name)
        return false;
    Symbol* target_symbol = target_kernel.find_symbol_by_name(source_symbol->symbol_name);
    if (!target_symbol || !target_symbol->symbol_addr)
        return false;
    target_address = target_symbol->symbol_addr;
    return true;
}

static bool rebase_dependency_reference(Kext* kext, uint64_t source_address,
    uint64_t new_prelink_text_base, uint64_t new_prelink_text_exec_base,
    uint64_t new_prelink_data_base, uint64_t new_prelink_data_const_base,
    uint64_t& target_address)
{
    if (!kext)
        return false;
    for (Kext* dependency : kext->depends) {
        if (!dependency || dependency->is_from_file || !dependency->exec_macho)
            continue;
        struct SegmentBase { const char* name; uint64_t base; uint64_t offset; } segments[] = {
            { "__TEXT", new_prelink_text_base, dependency->text_off },
            { "__TEXT_EXEC", new_prelink_text_exec_base, dependency->text_exec_off },
            { "__DATA", new_prelink_data_base, dependency->data_off },
            { "__DATA_CONST", new_prelink_data_const_base, dependency->data_const_off },
        };
        for (const SegmentBase& entry : segments) {
            auto* segment = static_cast<segment_command_64_t*>(dependency->exec_macho->find_segment(entry.name));
            if (dependency->exec_macho->addr_in_segment(segment, source_address)) {
                target_address = source_address - segment->vmaddr + entry.base + entry.offset;
                return true;
            }
        }
    }
    return false;
}

// 得到单条指令的立即数
static uint64_t getSingleIMM(csh handle, const cs_insn* insn)
{
    int acount = cs_op_count(handle, insn, ARM64_OP_IMM);
    if (acount) {
        if (acount > 1)
            printf("getSingleIMM Immediate number more than one\n");
        for (int i = 1; i < acount + 1; ++i) {
            int index = cs_op_index(handle, insn, ARM64_OP_IMM, i);
            if (index >= 0)
                return insn->detail->arm64.operands[index].imm;
        }
    }
    return 0;
}

static void copy_segment_from_kext(Kext* kext, KernelMacho& i_kernel, const char* kext_segname, const char* kernel_segname, void* buf, uint64_t& off, uint64_t align)
{
    uint64_t copy_des = 0;
    uint64_t copy_src = 0;
    uint64_t copy_size = 0;

    segment_command_64_t* i_seg = (segment_command_64_t*)(i_kernel.find_segment(kernel_segname));

    segment_command_64_t* text_exec_seg = (segment_command_64_t*)(kext->exec_macho->find_segment(kext_segname));
    if (text_exec_seg) {
        if (kext->is_from_file) {
            copy_src = (uint64_t)kext->exec_macho->file_buf + text_exec_seg->fileoff;
        } else {
            copy_src = text_exec_seg->vmaddr;
            copy_src -= i_seg->vmaddr;
            copy_src += (uint64_t)i_kernel.file_buf + i_seg->fileoff;
        }

        copy_des = (uint64_t)buf + off;
        copy_size = text_exec_seg->filesize;
        // printf("Copy 0x%016llx -> 0x%016llx(0x%08x)\n", copy_src, off, copy_size);
        memset((void*)copy_des, 0, copy_size);
        memcpy((char*)copy_des, (char*)copy_src, copy_size);
        copy_size = ALIGN_UP(text_exec_seg->vmsize, align);
        off += copy_size;
    }
}

static void patch_seg_fileoff(segment_command_64_t* seg, uint64_t fileoff, uint64_t size)
{
    section_64_t* sect = (section_64_t*)((uint64_t)seg + sizeof(segment_command_64_t));
    for (uint32_t i = 0; i < seg->nsects; i++) {
        sect->offset = sect->offset - seg->fileoff + fileoff;
        sect = (section_64_t*)(sect + 1);
    }

    seg->fileoff = fileoff;
    seg->filesize = size;
}

static void patch_seg_vmbase(segment_command_64_t* seg, uint64_t vmaddr, uint64_t size)
{
    uint64_t old_vmbase = seg->vmaddr;
    seg->vmaddr = vmaddr;
    seg->vmsize = size;

    section_64_t* sect = (section_64_t*)((uint64_t)seg + sizeof(segment_command_64_t));
    for (uint32_t i = 0; i < seg->nsects; i++) {
        sect->addr = vmaddr + sect->addr - old_vmbase;
        sect = (section_64_t*)(sect + 1);
    }
}

static void patch_seg_base(segment_command_64_t* seg, uint64_t fileoff, uint64_t vmaddr, uint64_t size)
{
    patch_seg_vmbase(seg, vmaddr, size);
    seg->fileoff = fileoff;
    seg->filesize = size;

    section_64_t* sect = (section_64_t*)((uint64_t)seg + sizeof(segment_command_64_t));
    sect->offset = fileoff;
    sect->size = size;
}

static bool find_offs(
    csh handle,
    const cs_insn* insn,
    size_t start,
    size_t end,
    uint32_t reg,
    std::set<int>& indexs,
    std::unordered_set<int>& jumps, // 记录已跳转的位置
    uint32_t& off,
    bool find_first_off = false)
{
    std::unordered_set<int> used_addr;
    bool find_this_off = false;
    uint32_t first_off = std::numeric_limits<uint32_t>::max();
    uint32_t this_off = std::numeric_limits<uint32_t>::max();
    uint32_t this_write_reg;
    uint32_t this_read_reg;

#if DEBUG
    printf("start: 0x%zx(0x%" PRIx64 "), reg %s, off: 0x%x\n", start, insn[start].address, cs_reg_name(handle, reg), off);
#endif

    if (find_first_off)
        first_off = off;

    for (size_t off_index = start + 1; off_index < end; off_index++) {
        this_write_reg = 0;
        this_read_reg = 0;
        find_this_off = false;
        this_off = std::numeric_limits<uint32_t>::max();
        if (jumps.find(off_index) != jumps.end() || indexs.find(off_index) != indexs.end()) {
#if DEBUG
            printf("Over at 0x%" PRIx64 "\n", insn[off_index].address);
#endif
            break;
        }

        // 每条语句只检测一次
        jumps.insert(off_index);

        if (cs_insn_group(handle, &insn[off_index], CS_GRP_JUMP)) {
            if (strstr(insn[off_index].mnemonic, "bl")) {
                if (cs_op_count(handle, &insn[off_index], ARM64_OP_IMM) > 0) {
                    uint64_t bl_next = getSingleIMM(handle, &insn[off_index]);
                    if (used_addr.count(bl_next) == 0) {
                        used_addr.insert(insn[off_index].address);
                        // find_offs(handle, insn, off_index, end, reg, indexs);
                    }
                }
                // off_index++;
                continue;
            } else if (!strcmp(insn[off_index].mnemonic, "ret")) {
                break;
            } else if (!strcmp(insn[off_index].mnemonic, "br")) {
                // break;
} else if (strstr(insn[off_index].mnemonic, "tb")) {
                continue;
            } else if (strstr(insn[off_index].mnemonic, "b")) {
                // printf("0x%llx, %s\n", insn[off_index].address, insn[off_index].mnemonic);
                uint64_t b_next = getSingleIMM(handle, &insn[off_index]);
                if (b_next) {
                    int64_t new_offset = static_cast<int64_t>(b_next) - static_cast<int64_t>(insn[off_index].address);
                    new_offset /= 4;
                    // printf("BNext: 0x%llx, count %d\n", b_next, new_offset);
                    if (new_offset >= 0) {
                        size_t new_start = off_index + static_cast<size_t>(new_offset);
                        if (new_start > 0 && new_start < end) {
                            // if (jumps.find(new_start) == jumps.end()) {
                            // jumps.insert(new_start);
                            //     jumps.insert(off_index);
                            find_first_off = find_offs(handle, insn, new_start - 1, end, reg, indexs, jumps, off, find_first_off);
                            if (find_first_off) {
                                first_off = off;
                            }
                        }
                    }
                }
            } else {
                // printf("%s, 0x%llx\n", insn[off_index].mnemonic, insn[off_index].address);
            }

            continue;
        } else if (!strcmp(insn[off_index].mnemonic, "adrp")) {
            int reg_index = cs_op_index(handle, &insn[off_index], ARM64_OP_REG, 1);
            if (reg == insn[off_index].detail->arm64.operands[reg_index].reg) {
                // printf("Over\n");
                uint64_t this_base = getSingleIMM(handle, &insn[off_index]);
                uint64_t need_base = getSingleIMM(handle, insn);
                if (this_base == need_base) {
#if DEBUG
                    printf("%d\n", __LINE__);
#endif
                    continue;
                }

                break;
            }
        } else if (!strcmp(insn[off_index].mnemonic, "mov")) {
            int read_reg_index = cs_op_index(handle, &insn[off_index], ARM64_OP_REG, 2);
            int write_reg_index = cs_op_index(handle, &insn[off_index], ARM64_OP_REG, 1);
            int read_tmp, write_tmp;
            read_tmp = insn[off_index].detail->arm64.operands[read_reg_index].reg;
            write_tmp = insn[off_index].detail->arm64.operands[write_reg_index].reg;
            
            if (static_cast<uint32_t>(read_tmp) == reg && find_first_off) {
#if DEBUG
                printf("0x%" PRIx64 ": mov: %s, %s\n", insn[off_index].address, cs_reg_name(handle, write_tmp), cs_reg_name(handle, read_tmp));
#endif
                this_write_reg = reg;
                reg = write_tmp;
            } else {
                this_write_reg = insn[off_index].detail->arm64.operands[write_reg_index].reg;
                // printf("0x%llx, Write reg: %s\n", insn[off_index].address, cs_reg_name(handle, this_write_reg));
            }
            
        } else if (!strcmp(insn[off_index].mnemonic, "add")) {
            int add_imm = getSingleIMM(handle, &insn[off_index]);

            int read_reg_index = cs_op_index(handle, &insn[off_index], ARM64_OP_REG, 2);
            this_read_reg = insn[off_index].detail->arm64.operands[read_reg_index].reg;

            if (this_read_reg == reg) {
                if (!find_first_off) {
                    first_off = add_imm;
                    find_first_off = true;
                    // printf("Find first off at 0x%llx(0x%lx)\n", insn[off_index].address, first_off);
                }
                this_off = add_imm;
                find_this_off = true;
            }

            int write_reg_index = cs_op_index(handle, &insn[off_index], ARM64_OP_REG, 1);
            this_write_reg = insn[off_index].detail->arm64.operands[write_reg_index].reg;
        } else if (!strcmp(insn[off_index].mnemonic, "sub")) {
            int write_reg_index = cs_op_index(handle, &insn[off_index], ARM64_OP_REG, 1);
            int read_reg_index = cs_op_index(handle, &insn[off_index], ARM64_OP_REG, 2);

            this_write_reg = insn[off_index].detail->arm64.operands[write_reg_index].reg;
            this_read_reg = insn[off_index].detail->arm64.operands[read_reg_index].reg;

            if (this_read_reg == this_write_reg && this_write_reg == ARM64_REG_SP) { // 遇到函数头或者结束
                break;
            }

        } else if (strstr(insn[off_index].mnemonic, "ldr")) {
            int ldr_off_index = cs_op_index(handle, &insn[off_index], ARM64_OP_MEM, 1);
            uint32_t ldr_off = insn[off_index].detail->arm64.operands[ldr_off_index].mem.disp;
            this_read_reg = insn[off_index].detail->arm64.operands[ldr_off_index].mem.base;

            if (this_read_reg == reg) {
                if (!find_first_off) {
                    first_off = ldr_off;
                    find_first_off = true;
                    // printf("Find first off at 0x%llx(0x%lx)\n", insn[off_index].address, first_off);
                }
                this_off = ldr_off;
                find_this_off = true;

                // printf("Reg cound: %d\n", cs_op_count(handle, &insn[off_index], ARM64_OP_REG));
            }

            int reg_index = cs_op_index(handle, &insn[off_index], ARM64_OP_REG, 1);
            this_write_reg = insn[off_index].detail->arm64.operands[reg_index].reg;
        } else if (strstr(insn[off_index].mnemonic, "str")) {
            int str_off_index = cs_op_index(handle, &insn[off_index], ARM64_OP_MEM, 1);
            uint32_t str_off = insn[off_index].detail->arm64.operands[str_off_index].mem.disp;
            this_read_reg = insn[off_index].detail->arm64.operands[str_off_index].mem.base;

            if (this_read_reg == reg) {
                if (!find_first_off) {
                    first_off = str_off;
                    find_first_off = true;
                    // printf("Find first off at 0x%llx(0x%lx)\n", insn[off_index].address, first_off);
                }
                this_off = str_off;
                find_this_off = true;
            }
        }

        if (find_this_off) {
            // 如果偏移量相同就添加进offs中
            // printf("Debug：firstoff: %x, thisoff: %x, thisreg: %d, reg: %d\n", first_off, this_off, this_read_reg, reg);
            if (first_off != std::numeric_limits<uint32_t>::max() && first_off == this_off && this_read_reg == reg) {
                off = this_off;
                // printf("Found off: 0x%lx 0x%llx\n", this_off, insn[off_index].address);
                indexs.insert(off_index);
            }

            // 检测当前寄存器是否被修改，是的话就停止搜查
            if (this_write_reg == reg || (this_write_reg + 31 == reg)) {
                // printf("Over: %llx\n", insn[off_index].address);
                break;
            }
        }
    }

    return find_first_off;
}

size_t patch_kext_to_kernel(KernelMacho& y_kernel, KernelMacho& i_kernel, const LinkResolver* resolver)
{
    size_t unresolved_externals = 0;
    if (y_kernel.is_newer_ver) {
        uint32_t prelink_text_size = y_kernel.get_prelink_text_size();
        uint32_t prelink_text_exec_size = y_kernel.get_prelink_segment_size("__TEXT_EXEC", 1 << 12);
        uint32_t prelink_data_size = y_kernel.get_prelink_data_size(SEG_ALIGN);
        uint32_t prelink_data_const_size = y_kernel.get_prelink_segment_size("__DATA_CONST", SEG_ALIGN);

        printf("pre text size: %x\n", prelink_text_size);
        printf("pre text exec size: %x\n", prelink_text_exec_size);
        printf("pre data size: %x\n", prelink_data_size);
        printf("pre data const size: %x\n", prelink_data_const_size);

        prelink_text_size = ALIGN_UP(prelink_text_size, 1 << 12);
        prelink_text_exec_size = ALIGN_UP(prelink_text_exec_size, 1 << 12);
        prelink_data_size = ALIGN_UP(prelink_data_size, 1 << 12);
        prelink_data_const_size = ALIGN_UP(prelink_data_const_size, 1 << 12);

        void* prelink_text_buf = calloc(prelink_text_size, sizeof(char));
        void* prelink_text_exec_buf = calloc(prelink_text_exec_size, sizeof(char));
        void* prelink_data_buf = calloc(prelink_data_size, sizeof(char));
        void* prelink_data_const_buf = calloc(prelink_data_const_size, sizeof(char));

        // 将对应kext拷贝到目标段缓冲区中
        uint64_t kerenl_text_off = 0;
        uint64_t kerenl_text_exec_off = 0;
        uint64_t kerenl_data_off = 0;
        uint64_t kerenl_data_const_off = 0;
        uint32_t size = 0;

        for (auto kext : y_kernel.kexts) {
            if (kext->exec_macho) {
                kext->text_off = kerenl_text_off;
                segment_command_64_t* text_seg = (segment_command_64_t*)(kext->exec_macho->find_segment("__TEXT"));
                if (text_seg && text_seg->filesize > 0) {
                    memset((void*)((uint64_t)prelink_text_buf + kerenl_text_off), 0, text_seg->filesize);
                    memcpy((char*)((uint64_t)prelink_text_buf + kerenl_text_off),
                        (char*)(uint64_t)kext->exec_macho->file_buf + text_seg->fileoff,
                        text_seg->filesize);
                    // printf("Copy 0x%016llx -> 0x%016llx\n", text_seg->fileoff, kerenl_text_off);
                    kerenl_text_off += ALIGN_UP(text_seg->filesize, SEG_ALIGN);
                } else {
                    if (kext->exec_macho->header->sizeofcmds) {
                        size = ALIGN_UP(kext->exec_macho->header->sizeofcmds, SEG_ALIGN);
                        memcpy((char*)((uint64_t)prelink_text_buf + kerenl_text_off),
                            (char*)(uint64_t)kext->exec_macho->file_buf,
                            size);

                        kerenl_text_off += size;
                    }
                }
                kext->text_exec_off = kerenl_text_exec_off;
                copy_segment_from_kext(kext, i_kernel, "__TEXT_EXEC", "__PLK_TEXT_EXEC", prelink_text_exec_buf, kerenl_text_exec_off, 1 << 12);
                kext->data_off = kerenl_data_off;
                copy_segment_from_kext(kext, i_kernel, "__DATA", "__PRELINK_DATA", prelink_data_buf, kerenl_data_off, SEG_ALIGN);
                kext->data_const_off = kerenl_data_const_off;
                copy_segment_from_kext(kext, i_kernel, "__DATA_CONST", "__PLK_DATA_CONST", prelink_data_const_buf, kerenl_data_const_off, SEG_ALIGN);
            }
        }

        // 重新设定头部地址
        // 先计算各段基址
        uint64_t new_prelink_text_base = 0;
        uint64_t new_prelink_text_exec_base = 0;
        uint64_t new_prelink_data_base = 0;
        uint64_t new_prelink_data_const_base = 0;
        segment_command_64_t* y_text_segment = (segment_command_64_t*)(y_kernel.find_segment("__TEXT"));
        segment_command_64_t* y_linkedit_seg = (segment_command_64_t*)y_kernel.find_segment("__LINKEDIT");

        segment_command_64_t* i_prelink_text_segment = (segment_command_64_t*)(i_kernel.find_segment("__PRELINK_TEXT"));
        segment_command_64_t* i_prelink_data_segment = (segment_command_64_t*)(i_kernel.find_segment("__PRELINK_DATA"));

        uint64_t kernel_text_vmbase = y_text_segment->vmaddr;
        new_prelink_data_const_base = kernel_text_vmbase - prelink_data_const_size;
        new_prelink_data_base = ALIGN_UP(y_linkedit_seg->vmaddr + y_linkedit_seg->vmsize, 1 << 12);
        new_prelink_text_exec_base = new_prelink_data_const_base - prelink_text_exec_size;
        new_prelink_text_base = new_prelink_text_exec_base - prelink_text_size;

        y_kernel.prelink_text_base = new_prelink_text_base;
        printf("Prelink text will at 0x%016" PRIx64 "\n", new_prelink_text_base);
        printf("Prelink data will at 0x%016" PRIx64 "\n", new_prelink_data_base);

        // 获取内核末尾
        uint64_t end_fileoff = y_linkedit_seg->fileoff + y_linkedit_seg->filesize;
        end_fileoff = ALIGN_UP(end_fileoff, 1 << 12);
        printf("End at 0x%016" PRIx64 "\n", end_fileoff);
        uint64_t new_prelink_text_fileoff = end_fileoff;
        uint64_t new_prelink_text_exec_fileoff = new_prelink_text_fileoff + prelink_text_size;
        uint64_t new_prelink_data_const_fileoff = new_prelink_text_exec_fileoff + prelink_text_exec_size;
        printf("data const off: 0x%" PRIx64 "\n", new_prelink_data_const_fileoff);
        uint64_t new_prelink_data_fileoff = new_prelink_data_const_fileoff + prelink_data_const_size;

        // 修改Kext符号表
        csh handle;
        if (cs_open(CS_ARCH_ARM64, (cs_mode)(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN), &handle)) {
            printf("ERROR: Failed to initialize engine!\n");
            return SIZE_MAX;
        }
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
        ks_engine* ks;
        if (ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks)) {
            printf("ERROR: failed on ks_open(), quit\n");
            return SIZE_MAX;
        }

        for (auto kext : y_kernel.kexts) {
            // KMOD处理
            if (kext->exec_macho) {
                segment_command_64_t* kext_text_seg = (segment_command_64_t*)kext->exec_macho->find_segment("__TEXT");
                segment_command_64_t* kext_data_const_seg = (segment_command_64_t*)kext->exec_macho->find_segment("__DATA_CONST");
                segment_command_64_t* kext_text_exec_seg = (segment_command_64_t*)kext->exec_macho->find_segment("__TEXT_EXEC");
                segment_command_64_t* kext_data_seg = (segment_command_64_t*)kext->exec_macho->find_segment("__DATA");

                if (kext->is_from_file) {
                    if (kext->exec_macho->find_segment("__TEXT")) {
                        Symbol* kmod_symbol = kext->exec_macho->find_symbol_by_name("_kmod_info");
                        if (kmod_symbol && kext_data_seg) {
                            kext->kmod_addr = kmod_symbol->symbol_addr - kext_data_seg->vmaddr;
                            kext->kmod_addr += new_prelink_data_base + kext->data_off;
                            printf("New kmod addr: 0x%" PRIx64 "\n", kext->kmod_addr);
                        }
                    } else {
                        kext->kmod_addr = 0;
                    }
                } else {
                    if (kext->kmod_addr && kext_data_seg)
                        kext->kmod_addr = kext->kmod_addr - kext_data_seg->vmaddr + new_prelink_data_base + kext->data_off;
                }

                if (kext->kmod_addr) {
                    kmod_info_64_v1_t* kext_kmod = (kmod_info_64_v1_t*)(kext->kmod_addr - new_prelink_data_base + (uint64_t)prelink_data_buf);
                    printf("K add: 0x%" PRIx64 "\n", kext_kmod->address);
                    printf("K n: %s\n", kext_kmod->name);
                    kext_kmod->address = new_prelink_text_base + kext->text_off;
                    segment_command_64_t* kext_text_exec_seg = (segment_command_64_t*)kext->exec_macho->find_segment("__TEXT_EXEC");
                    if (kext_kmod->start_addr) {
                        kext_kmod->start_addr -= kext_text_exec_seg->vmaddr;
                        kext_kmod->start_addr += new_prelink_text_exec_base + kext->text_exec_off;
                        printf("k start at: 0x%" PRIx64 "\n", kext_kmod->start_addr);
                    }
                    if (kext_kmod->stop_addr) {
                        kext_kmod->stop_addr -= kext_text_exec_seg->vmaddr;
                        kext_kmod->stop_addr += new_prelink_text_exec_base + kext->text_exec_off;
                    }
                }

                // 处理DATA段的地址
                if (kext_data_seg) {
                    section_64_t* kext_cstring_sect = (section_64*)kext->exec_macho->find_section("__TEXT", "__cstring");
                    uint64_t kext_start_addr = (kext->is_from_file && kext_cstring_sect)
                        ? kext_cstring_sect->addr : kext_text_seg->vmaddr;
                    uint64_t* addrs = (uint64_t*)((uint64_t)prelink_data_buf + kext->data_off);
                    for (size_t i = 0; i < kext_data_seg->vmsize / sizeof(uint64_t); i++) {
                        if (addrs[i] >= kext_start_addr && addrs[i] < kext_text_seg->vmaddr + kext_text_seg->vmsize) {
                            // printf("Data in __TEXT, addr: %llx\n", addrs[i]);
                            addrs[i] -= kext_text_seg->vmaddr;
                            addrs[i] += new_prelink_text_base + kext->text_off;
                        } else if (addrs[i] >= kext_text_exec_seg->vmaddr && addrs[i] < kext_text_exec_seg->vmaddr + kext_text_exec_seg->vmsize) {
                            // printf("Data in __TEXT_EXEC, addr: %llx\n", addrs[i]);
                            addrs[i] -= kext_text_exec_seg->vmaddr;
                            addrs[i] += new_prelink_text_exec_base + kext->text_exec_off;
                        } else if (addrs[i] >= kext_data_seg->vmaddr && addrs[i] < kext_data_seg->vmaddr + kext_data_seg->vmsize) {
                            // printf("Data in __DATA, addr: %llx\n", addrs[i]);
                            addrs[i] -= kext_data_seg->vmaddr;
                            addrs[i] += new_prelink_data_base + kext->data_off;
                        } else if (IN_SEGMENT_RANGE(addrs[i], kext_data_const_seg)) {
                            // printf("Data in __DATA_CONST, addr: %llx\n", addrs[i]);
                            addrs[i] -= kext_data_const_seg->vmaddr;
                            addrs[i] += new_prelink_data_const_base + kext->data_const_off;
                        } else if (!kext->is_from_file) {
                            if (addrs[i]) {
                                uint64_t resolved_address = 0;
                                if (rebase_dependency_reference(kext, addrs[i], new_prelink_text_base,
                                        new_prelink_text_exec_base, new_prelink_data_base,
                                        new_prelink_data_const_base, resolved_address)
                                    || resolve_kernel_reference(addrs[i], i_kernel, y_kernel, resolver, resolved_address)) {
                                    addrs[i] = resolved_address;
                                } else if (!i_kernel.find_symbol_by_addr(addrs[i])) {
                                    bool found_symbol = false;
                                    // 找不到再从i_kernel的kext里面找
                                    for (size_t j = 0; j < kext->depends.size(); j++) {
                                        if (!kext->depends[j]->is_from_file && kext->depends[j]->exec_macho) {
                                            segment_command_64_t* dep_text_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__TEXT");
                                            segment_command_64_t* dep_text_exec_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__TEXT_EXEC");
                                            segment_command_64_t* dep_data_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__DATA");
                                            segment_command_64_t* dep_data_const_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__DATA_CONST");

                                            if (kext->depends[j]->exec_macho->addr_in_segment(dep_text_seg, addrs[i])) {
                                                addrs[i] -= dep_text_seg->vmaddr;
                                                addrs[i] += new_prelink_text_base + kext->depends[j]->text_off;
                                                found_symbol = true;
                                            } else if (kext->depends[j]->exec_macho->addr_in_segment(dep_text_exec_seg, addrs[i])) {
                                                addrs[i] -= dep_text_exec_seg->vmaddr;
                                                addrs[i] += new_prelink_text_exec_base + kext->depends[j]->text_exec_off;
                                                found_symbol = true;
                                            } else if (kext->depends[j]->exec_macho->addr_in_segment(dep_data_seg, addrs[i])) {
                                                addrs[i] -= dep_data_seg->vmaddr;
                                                addrs[i] += new_prelink_data_base + kext->depends[j]->data_off;
                                                found_symbol = true;
                                            // } else if (addrs[i] >= dep_data_const_seg->vmaddr && addrs[i] < dep_data_const_seg->vmaddr + dep_data_const_seg->vmsize) {
                                            } else if (IN_SEGMENT_RANGE(addrs[i], dep_data_const_seg)) {
                                                addrs[i] -= dep_data_const_seg->vmaddr;
                                                addrs[i] += new_prelink_data_const_base + kext->depends[j]->data_const_off;
                                                found_symbol = true;
                                            }
                                        }
                                    }
                                    if (!found_symbol)
                                        if (addrs[i] >= i_prelink_text_segment->vmaddr && addrs[i] < i_prelink_data_segment->vmaddr + i_prelink_data_segment->vmsize)
                                            printf("%d: Not found kernel symbol %" PRIx64 " at 0x%" PRIx64 "\n", __LINE__, addrs[i], kext_data_seg->vmaddr + i * sizeof(uint64_t));
                                } else {
                                    Symbol* source_symbol = i_kernel.find_symbol_by_addr(addrs[i]);
                                    printf("Not found kernel symbol(%s)\n", source_symbol->symbol_name);
                                }
                            }
                        }
                        // i_kernel!!!
                    }
                }

                // 修复data const段的地址
                // 修复mod_init_func和mod_term_func

                if (kext_data_const_seg) {
                    section_64_t* init_sect = (section_64_t*)kext->exec_macho->find_section("__DATA_CONST", "__mod_init_func");
                    section_64_t* term_sect = (section_64_t*)kext->exec_macho->find_section("__DATA_CONST", "__mod_term_func");
                    if (init_sect && term_sect && kext_text_exec_seg) {
                        uint64_t* mod_addr = (uint64_t*)((uint64_t)prelink_data_const_buf + kext->data_const_off + init_sect->addr - kext_data_const_seg->vmaddr);
                        for (size_t i = 0; i < init_sect->size / sizeof(uint64_t); i++) {
                            *mod_addr = *mod_addr - kext_text_exec_seg->vmaddr;
                            *mod_addr = *mod_addr + kext->text_exec_off + new_prelink_text_exec_base;

                            mod_addr++;
                        }

                        mod_addr = (uint64_t*)((uint64_t)prelink_data_const_buf + kext->data_const_off + term_sect->addr - kext_data_const_seg->vmaddr);
                        for (size_t i = 0; i < term_sect->size / sizeof(uint64_t); i++) {
                            *mod_addr = *mod_addr - kext_text_exec_seg->vmaddr;
                            *mod_addr = *mod_addr + kext->text_exec_off + new_prelink_text_exec_base;

                            mod_addr++;
                        }
                    }

                    if (kext_text_exec_seg)
                        printf("Kext __TEXT_EXEC at %" PRIx64 "\n", kext_text_exec_seg->vmaddr);
                    if (kext_data_seg)
                        printf("Kext __DATA at %" PRIx64 "\n", kext_data_seg->vmaddr);
                    printf("Kext __DATA_CONST at %" PRIx64 "\n", kext_data_const_seg->vmaddr);

                    section_64_t* kext_cstring_sect = (section_64*)kext->exec_macho->find_section("__TEXT", "__cstring");
                    section_64_t* kext_const_sect = (section_64*)kext->exec_macho->find_section("__DATA_CONST", "__const");

                    section_64_t* kext_got_sect = (section_64*)kext->exec_macho->find_section("__DATA_CONST", "__got");

                    if (!kext_const_sect) {
                        kext_const_sect = (section_64*)kext->exec_macho->find_section("__DATA_CONST", "__kalloc_type");
                    }
                    if (kext_data_const_seg) {
                        uint64_t* addrs = 0;
                        if (kext_const_sect) {
                            addrs = (uint64_t*)((uint64_t)prelink_data_const_buf + kext->data_const_off + kext_const_sect->addr - kext_data_const_seg->vmaddr);
                            for (size_t i = 0; i < (kext_data_const_seg->vmaddr + kext_data_const_seg->vmsize - kext_const_sect->addr) / sizeof(uint64_t); i++) {
                                if (kext_got_sect && addrs[i] >= kext_got_sect->addr && addrs[i] < kext_got_sect->addr + kext_got_sect->size) {
                                    printf("?In?\n");
                                    continue;
                                }
                                if (kext->exec_macho->addr_in_segment(kext_text_seg, addrs[i])) {
                                    // printf("Data in __TEXT, addr: %llx\n", addrs[i]);
                                    if (kext->is_from_file) {
                                        if (kext_cstring_sect && addrs[i] >= kext_cstring_sect->addr) {
                                            addrs[i] -= kext_text_seg->vmaddr;
                                            addrs[i] += new_prelink_text_base + kext->text_off;
                                        }
                                    } else {
                                        addrs[i] -= kext_text_seg->vmaddr;
                                        addrs[i] += new_prelink_text_base + kext->text_off;
                                    }

                                } else if (kext->exec_macho->addr_in_segment(kext_text_exec_seg, addrs[i])) {
                                    // printf("Data in __TEXT_EXEC, addr: %llx\n", addrs[i]);
                                    addrs[i] -= kext_text_exec_seg->vmaddr;
                                    addrs[i] += new_prelink_text_exec_base + kext->text_exec_off;
                                } else if (kext->exec_macho->addr_in_segment(kext_data_seg, addrs[i])) {
                                    // printf("Data in __DATA, addr: %llx\n", addrs[i]);
                                    addrs[i] -= kext_data_seg->vmaddr;
                                    addrs[i] += new_prelink_data_base + kext->data_off;
                                } else if (kext->exec_macho->addr_in_segment(kext_data_const_seg, addrs[i])) {
                                    // printf("Data in __DATA_CONST, addr: %llx\n", addrs[i]);
                                    addrs[i] -= kext_data_const_seg->vmaddr;
                                    addrs[i] += new_prelink_data_const_base + kext->data_const_off;
                                } else if (!kext->is_from_file) {
                                    if (addrs[i]) {
                                        uint64_t resolved_address = 0;
                                        if (rebase_dependency_reference(kext, addrs[i], new_prelink_text_base,
                                                new_prelink_text_exec_base, new_prelink_data_base,
                                                new_prelink_data_const_base, resolved_address)
                                            || resolve_kernel_reference(addrs[i], i_kernel, y_kernel, resolver, resolved_address)) {
                                            addrs[i] = resolved_address;
                                        } else if (!i_kernel.find_symbol_by_addr(addrs[i])) {
                                            bool found_symbol = false;
                                            // 找不到再从i_kernel的kext里面找
                                            for (size_t j = 0; j < kext->depends.size(); j++) {
                                                if (!kext->depends[j]->is_from_file && kext->depends[j]->exec_macho) {
                                                    segment_command_64_t* dep_text_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__TEXT");
                                                    segment_command_64_t* dep_text_exec_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__TEXT_EXEC");
                                                    segment_command_64_t* dep_data_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__DATA");
                                                    segment_command_64_t* dep_data_const_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__DATA_CONST");

                                                    if (kext->depends[j]->exec_macho->addr_in_segment(dep_text_seg, addrs[i])) {
                                                        addrs[i] -= dep_text_seg->vmaddr;
                                                        addrs[i] += new_prelink_text_base + kext->depends[j]->text_off;
                                                        found_symbol = true;
                                                    } else if (kext->depends[j]->exec_macho->addr_in_segment(dep_text_exec_seg, addrs[i])) {
                                                        addrs[i] -= dep_text_exec_seg->vmaddr;
                                                        addrs[i] += new_prelink_text_exec_base + kext->depends[j]->text_exec_off;
                                                        found_symbol = true;
                                                    } else if (kext->depends[j]->exec_macho->addr_in_segment(dep_data_seg, addrs[i])) {
                                                        addrs[i] -= dep_data_seg->vmaddr;
                                                        addrs[i] += new_prelink_data_base + kext->depends[j]->data_off;
                                                        found_symbol = true;
                                                    } else if (IN_SEGMENT_RANGE(addrs[i], dep_data_const_seg)) {
                                                        addrs[i] -= dep_data_const_seg->vmaddr;
                                                        addrs[i] += new_prelink_data_const_base + kext->depends[j]->data_const_off;
                                                        found_symbol = true;
                                                    }

                                                    if (found_symbol)
                                                        break;
                                                }
                                            }
                                            if (!found_symbol)
                                                if (addrs[i] >= i_prelink_text_segment->vmaddr && addrs[i] < i_prelink_data_segment->vmaddr + i_prelink_data_segment->vmsize)
                                                    printf("%d: Not found kernel symbol %" PRIx64 " at 0x%" PRIx64 "\n", __LINE__, addrs[i], kext_const_sect->addr + i * sizeof(uint64_t));
                                            // printf("%d: Not found kernel symbol %llx at 0x%llx\n", __LINE__, addrs[i], &addrs[i] - ((uint64_t)prelink_data_const_buf + kext->data_const_off) + kext_data_const_seg->vmaddr);
                                        } else {
                                            Symbol* source_symbol = i_kernel.find_symbol_by_addr(addrs[i]);
                                            printf("Not found kernel symbol(%s)\n", source_symbol->symbol_name);
                                        }
                                    }
                                }
                            }
                        }

                        if (kext_got_sect) {
                            if (!kext->is_from_file) {
                                addrs = (uint64_t*)((uint64_t)prelink_data_const_buf + kext->data_const_off + kext_got_sect->addr - kext_data_const_seg->vmaddr);
                                for (size_t i = 0; i < kext_got_sect->size / sizeof(uint64_t); i++) {
                                    uint64_t resolved_address = 0;
                                    if (rebase_dependency_reference(kext, addrs[i], new_prelink_text_base,
                                            new_prelink_text_exec_base, new_prelink_data_base,
                                            new_prelink_data_const_base, resolved_address)
                                        || resolve_kernel_reference(addrs[i], i_kernel, y_kernel, resolver, resolved_address)) {
                                        addrs[i] = resolved_address;
                                    } else if (i_kernel.find_symbol_by_addr(addrs[i])) {
                                        printf("%d: Not found symbol %s\n", __LINE__, i_kernel.find_symbol_by_addr(addrs[i])->symbol_name);
                                    } else {
                                        bool found_symbol = false;
                                        // 找不到再从i_kernel的kext里面找
                                        for (size_t j = 0; j < kext->depends.size(); j++) {
                                            if (!kext->depends[j]->is_from_file && kext->depends[j]->exec_macho) {
                                                segment_command_64_t* dep_text_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__TEXT");
                                                segment_command_64_t* dep_text_exec_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__TEXT_EXEC");
                                                segment_command_64_t* dep_data_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__DATA");
                                                segment_command_64_t* dep_data_const_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__DATA_CONST");

                                                if (kext->depends[j]->exec_macho->addr_in_segment(dep_text_seg, addrs[i])) {
                                                    addrs[i] -= dep_text_seg->vmaddr;
                                                    addrs[i] += new_prelink_text_base + kext->depends[j]->text_off;
                                                    found_symbol = true;
                                                } else if (kext->depends[j]->exec_macho->addr_in_segment(dep_text_exec_seg, addrs[i])) {
                                                    addrs[i] -= dep_text_exec_seg->vmaddr;
                                                    addrs[i] += new_prelink_text_exec_base + kext->depends[j]->text_exec_off;
                                                    found_symbol = true;
                                                } else if (kext->depends[j]->exec_macho->addr_in_segment(dep_data_seg, addrs[i])) {
                                                    addrs[i] -= dep_data_seg->vmaddr;
                                                    addrs[i] += new_prelink_data_base + kext->depends[j]->data_off;
                                                    found_symbol = true;
                                                } else if (IN_SEGMENT_RANGE(addrs[i], dep_data_const_seg)) {
                                                    addrs[i] -= dep_data_const_seg->vmaddr;
                                                    addrs[i] += new_prelink_data_const_base + kext->depends[j]->data_const_off;
                                                    found_symbol = true;
                                                }

                                                if (found_symbol) {
                                                    break;
                                                }
                                            }
                                        }
                                        if (!found_symbol)
                                            if (addrs[i] >= i_prelink_text_segment->vmaddr && addrs[i] < i_prelink_data_segment->vmaddr + i_prelink_data_segment->vmsize)
                                                printf("%d:Not found kernel symbol %" PRIx64 " at 0x%" PRIx64 "\n", __LINE__, addrs[i], kext_got_sect->addr + i * sizeof(uint64_t));
                                    }
                                }
                            }
                        }
                    } else {
                        printf("Kext not have __DATA_CONST.__const\n");
                    }
                }

                // 修补adrp
                if (kext_text_seg) {
                    printf("Kext TEXT at 0x%" PRIx64 "\n", kext_text_seg->vmaddr);
                }
                if (kext_text_exec_seg) {
                    size_t count;
                    cs_insn* insn;
                    uint64_t kext_text_exec_buf_addr = (uint64_t)prelink_text_exec_buf + kext->text_exec_off;

                    count = cs_disasm(handle, (const uint8_t*)kext_text_exec_buf_addr, kext_text_exec_seg->filesize, kext_text_exec_seg->vmaddr, 0, &insn);
                    printf("Disassembled %zu instructions\n", count);
                    // printf("Nedd: %x\n", kext_text_exec_seg->filesize / 4);

                    char new_insn[128];
                    if (count > 0) {
                        for (size_t i = 0; i < count; i++) {
                            if (strstr(insn[i].mnemonic, "adrp")) {
                                int acount = cs_op_count(handle, &insn[i], ARM64_OP_IMM);
                                // printf("acount: %d\n", acount);
                                if (acount == 1) {
                                    uint64_t imm = getSingleIMM(handle, &insn[i]);

                                    unsigned char* encode;
                                    size_t encode_size;
                                    size_t stat_count;
                                    int reg_index = cs_op_index(handle, &insn[i], ARM64_OP_REG, 1);
                                    const char* write_reg = cs_reg_name(handle, insn[i].detail->arm64.operands[reg_index].reg);
                                    uint64_t patch_addr = 0;

                                    // 寻找匹配的off
                                    std::set<int> off_indexs;
                                    std::unordered_set<int> jumps;
                                    uint32_t off = 0;
                                    // printf("Found next for 0x%llx(%s)\n", insn[i].address, kext->kext_id);
                                    bool find_off = find_offs(handle, insn, i, count, insn[i].detail->arm64.operands[reg_index].reg, off_indexs, jumps, off);
                                    if (!find_off) {
                                        printf("Not found offs for 0x%" PRIx64 "\n", insn[i].address);
                                        off = 0;
                                    }

                                    if (kext->exec_macho->addr_in_segment(kext_text_seg, off + imm)) {
                                        patch_addr = off + imm - kext_text_seg->vmaddr;
                                        patch_addr += new_prelink_text_base + kext->text_off;
                                    } else if (kext->exec_macho->addr_in_segment(kext_text_exec_seg, off + imm)) {
                                        patch_addr = off + imm - kext_text_exec_seg->vmaddr;
                                        patch_addr += new_prelink_text_exec_base + kext->text_exec_off;
                                    } else if (kext->exec_macho->addr_in_segment(kext_data_seg, off + imm)) {
                                        patch_addr = off + imm - kext_data_seg->vmaddr;
                                        patch_addr += new_prelink_data_base + kext->data_off;

                                    // } else if (off + imm >= kext_data_const_seg->vmaddr && off + imm < (kext_data_const_seg->vmaddr + kext_data_const_seg->vmsize)) {
                                    } else if (IN_SEGMENT_RANGE(off + imm, kext_data_const_seg)) {
                                        patch_addr = off + imm - kext_data_const_seg->vmaddr;
                                        patch_addr += new_prelink_data_const_base + kext->data_const_off;
                                    } else {
                                        continue;
                                    }

                                    // printf("old off: %llx\n", off);
                                    off = patch_addr & 0xFFF;
                                    // printf("Addr: %llx\n", patch_addr);
                                    // printf("New off: %llx\n", off);
                                    patch_addr &= ~0xFFF;

                                    snprintf(new_insn, sizeof(new_insn), "adrp %s, 0x%" PRIx64, write_reg, patch_addr);
                                    uint64_t insn_addr = insn[i].address - kext_text_exec_seg->vmaddr + new_prelink_text_exec_base + kext->text_exec_off;
                                    // printf("%llx\n", insn_addr);
                                    if (ks_asm(ks, new_insn, insn_addr, &encode, &encode_size, &stat_count)) {
                                        printf("Can not ks_asm code %s(0x%" PRIx64 ")\n", new_insn, insn[i].address);
                                        exit(-1);
                                    } else {
                                        for (size_t j = 0; j < encode_size; j++) {
                                            ((unsigned char*)((uint64_t)prelink_text_exec_buf + insn_addr - new_prelink_text_exec_base))[j] = encode[j];
                                        }
                                        ks_free(encode);
                                    }

                                    // 处理匹配的off
                                    if (find_off) {
                                        for (auto off_index : off_indexs) {
                                            bool assembled_consumer = false;
                                            if (!strcmp(insn[off_index].mnemonic, "add")) {
                                                int rcount = cs_op_count(handle, &insn[off_index], ARM64_OP_REG);
                                                const char* reg1_name;
                                                const char* reg2_name;
                                                if (rcount == 2) {
                                                    int reg1_index = cs_op_index(handle, &insn[off_index], ARM64_OP_REG, 1);
                                                    int reg2_index = cs_op_index(handle, &insn[off_index], ARM64_OP_REG, 2);
                                                    reg1_name = cs_reg_name(handle, insn[off_index].detail->arm64.operands[reg1_index].reg);
                                                    reg2_name = cs_reg_name(handle, insn[off_index].detail->arm64.operands[reg2_index].reg);

                                                    snprintf(new_insn, sizeof(new_insn), "add %s, %s, #0x%x", reg1_name, reg2_name, off);
                                                    assembled_consumer = true;
                                                }
                                            } else if (strstr(insn[off_index].mnemonic, "ldr")) {
                                                int reg1_index = cs_op_index(handle, &insn[off_index], ARM64_OP_REG, 1);
                                                const char* reg1_name = cs_reg_name(handle, insn[off_index].detail->arm64.operands[reg1_index].reg);
                                                int reg2_index = cs_op_index(handle, &insn[off_index], ARM64_OP_MEM, 1);
                                                const char* reg2_name = cs_reg_name(handle, insn[off_index].detail->arm64.operands[reg2_index].mem.base);

                                                snprintf(new_insn, sizeof(new_insn), "%s %s, [%s, #0x%x]", insn[off_index].mnemonic, reg1_name, reg2_name, off);
                                                assembled_consumer = true;
                                            } else if (strstr(insn[off_index].mnemonic, "str")) {
                                                int reg1_index = cs_op_index(handle, &insn[off_index], ARM64_OP_REG, 1);
                                                const char* reg1_name = cs_reg_name(handle, insn[off_index].detail->arm64.operands[reg1_index].reg);
                                                int reg2_index = cs_op_index(handle, &insn[off_index], ARM64_OP_MEM, 1);
                                                const char* reg2_name = cs_reg_name(handle, insn[off_index].detail->arm64.operands[reg2_index].mem.base);

                                                snprintf(new_insn, sizeof(new_insn), "%s %s, [%s, #0x%x]", insn[off_index].mnemonic, reg1_name, reg2_name, off);
                                                assembled_consumer = true;
                                            }

                                            if (!assembled_consumer)
                                                continue;
                                            insn_addr = insn[off_index].address - kext_text_exec_seg->vmaddr + new_prelink_text_exec_base + kext->text_exec_off;
                                            if (ks_asm(ks, new_insn, insn_addr, &encode, &encode_size, &stat_count)) {
                                                printf("Can not ks_asm code %s(0x%" PRIx64 ")\n", new_insn, insn[off_index].address);
                                                exit(-1);
                                            } else {
                                                for (size_t j = 0; j < encode_size; j++) {
                                                    ((unsigned char*)((uint64_t)prelink_text_exec_buf + insn_addr - new_prelink_text_exec_base))[j] = encode[j];
                                                }
                                                ks_free(encode);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if (count > 0)
                        cs_free(insn, count);
                }

                // 处理外部符号
                struct dysymtab_command* kext_dysymtab = (struct dysymtab_command*)find_command((mach_header_64_t*)((uint64_t)prelink_text_buf + kext->text_off), LC_DYSYMTAB);
                if (kext->is_from_file && kext_dysymtab) {
                    segment_command_64_t* kext_linkedit_seg = (segment_command_64_t*)kext->exec_macho->find_segment("__LINKEDIT");
                    if (kext_linkedit_seg) {
                        struct relocation_info* ext_ri = (struct relocation_info*)((uint64_t)kext->exec_macho->file_buf + kext_dysymtab->extreloff);

                        for (uint32_t i = 0; i < kext_dysymtab->nextrel; i++) {
                            if (ext_ri[i].r_extern == 1) {
                                const char* symbol_name = NULL;
                                if (ext_ri[i].r_symbolnum < kext->exec_macho->symbol_count)
                                    symbol_name = kext->exec_macho->symbol_list[ext_ri[i].r_symbolnum]->symbol_name;

                                if (!symbol_name)
                                    continue;

                                uint64_t found_addr = 0;
                                // Prefer an explicitly declared Kext dependency. The local
                                // kernel's old prelink segments are replaced below, so using
                                // one of their symbol addresses would leave a dangling link.
                                for (auto dep_kext : kext->depends) {
                                    Symbol* dependency_symbol = dep_kext->exec_macho
                                        ? dep_kext->exec_macho->find_symbol_by_name(symbol_name) : nullptr;
                                    if (!dependency_symbol || !dependency_symbol->symbol_addr)
                                        continue;
                                    segment_command_64_t* dep_text_seg = (segment_command_64_t*)dep_kext->exec_macho->find_segment("__TEXT");
                                    segment_command_64_t* dep_text_exec_seg = (segment_command_64_t*)dep_kext->exec_macho->find_segment("__TEXT_EXEC");
                                    segment_command_64_t* dep_data_seg = (segment_command_64_t*)dep_kext->exec_macho->find_segment("__DATA");
                                    segment_command_64_t* dep_data_const_seg = (segment_command_64_t*)dep_kext->exec_macho->find_segment("__DATA_CONST");

                                    found_addr = dependency_symbol->symbol_addr;
                                    if (dep_kext->exec_macho->addr_in_segment(dep_text_seg, found_addr)) {
                                        found_addr = found_addr - dep_text_seg->vmaddr + new_prelink_text_base + dep_kext->text_off;
                                    } else if (dep_kext->exec_macho->addr_in_segment(dep_text_exec_seg, found_addr)) {
                                        found_addr = found_addr - dep_text_exec_seg->vmaddr + new_prelink_text_exec_base + dep_kext->text_exec_off;
                                    } else if (dep_kext->exec_macho->addr_in_segment(dep_data_seg, found_addr)) {
                                        found_addr = found_addr - dep_data_seg->vmaddr + new_prelink_data_base + dep_kext->data_off;
                                    } else if (dep_kext->exec_macho->addr_in_segment(dep_data_const_seg, found_addr)) {
                                        found_addr = found_addr - dep_data_const_seg->vmaddr + new_prelink_data_const_base + dep_kext->data_const_off;
                                    } else {
                                        found_addr = 0;
                                        continue;
                                    }
                                    break;
                                }

                                if (!found_addr) {
                                    Symbol* kernel_symbol = y_kernel.find_symbol_by_name(symbol_name);
                                    if (kernel_symbol && kernel_symbol->symbol_addr)
                                        found_addr = kernel_symbol->symbol_addr;
                                }
                                if (!found_addr) {
                                    ++unresolved_externals;
                                    printf("Not found external symbol %s required by %s\n",
                                        symbol_name, kext->kext_id ? kext->kext_id : "<unknown>");
                                }

                                if (found_addr) {
                                    uint64_t* patch_symbol = NULL;
                                    if (kext->exec_macho->addr_in_segment(kext_data_const_seg, ext_ri[i].r_address)) {
                                        // patch_symbol -= kext_data_const_seg->vmaddr;
                                        // printf("PP: %llx\n", (ext_ri[i].r_address - kext_data_const_seg->vmaddr));
                                        patch_symbol = (uint64_t*)((uint64_t)prelink_data_const_buf + kext->data_const_off + ext_ri[i].r_address - kext_data_const_seg->vmaddr);
                                        *patch_symbol = found_addr;
                                        // printf("Patch addr: 0x%llx\n", (uint64_t)patch_symbol - (uint64_t)prelink_data_const_buf + new_prelink_data_const_base);
                                    } else if (kext->exec_macho->addr_in_segment(kext_data_seg, ext_ri[i].r_address)) {
                                        patch_symbol = (uint64_t*)((uint64_t)prelink_data_buf + kext->data_off + ext_ri[i].r_address - kext_data_seg->vmaddr);
                                        *patch_symbol = found_addr;
                                    }
                                } else {

                                    // printf("Not found symbol %s\n", symbol_name);
                                }
                            }
                        }
                    }
                }

                // 清空symtab
                struct symtab_command* kext_symtab = (struct symtab_command*)find_command((mach_header_64_t*)((uint64_t)prelink_text_buf + kext->text_off), LC_SYMTAB);
                // struct dysymtab_command* kext_dysymtab = (struct dysymtab_command*)find_command((mach_header_64_t*)((uint64_t)prelink_text_buf + kext->text_off), LC_DYSYMTAB);
                if (kext_symtab) {
                    printf("Found kext symtab\n");
                    kext_symtab->nsyms = 0;
                    kext_symtab->stroff = 0;
                    kext_symtab->strsize = 0;
                    kext_symtab->symoff = 0;
                }

                if (kext_dysymtab) {
                    printf("Found kext dysymtab\n");
                    memset((void*)((uint64_t)kext_dysymtab + 8), 0, sizeof(struct dysymtab_command) - 8);
                }
            }
        }

        ks_close(ks);
        cs_close(&handle);

        // 创建 PRELINK_INFO
        char* prelink_info_buf;
        uint64_t prelink_info_size;
        prelink_info_buf = make_prelink_info(y_kernel, prelink_info_size);
        uint64_t new_prelink_info_fileoff = new_prelink_data_fileoff + prelink_data_size;
        uint64_t new_kernel_size = new_prelink_info_fileoff + prelink_info_size;
        uint64_t new_prelink_info_base = new_prelink_data_base + prelink_data_size;

        // 修改内核基址
        patch_seg_base((segment_command_64_t*)y_kernel.find_segment("__PRELINK_TEXT"), new_prelink_text_fileoff, new_prelink_text_base, prelink_text_size);
        patch_seg_base((segment_command_64_t*)y_kernel.find_segment("__PLK_TEXT_EXEC"), new_prelink_text_exec_fileoff, new_prelink_text_exec_base, prelink_text_exec_size);
        patch_seg_base((segment_command_64_t*)y_kernel.find_segment("__PRELINK_DATA"), new_prelink_data_fileoff, new_prelink_data_base, prelink_data_size);
        patch_seg_base((segment_command_64_t*)y_kernel.find_segment("__PLK_DATA_CONST"), new_prelink_data_const_fileoff, new_prelink_data_const_base, prelink_data_const_size);
        patch_seg_base((segment_command_64_t*)y_kernel.find_segment("__PLK_LLVM_COV"), new_prelink_info_fileoff, new_prelink_info_base, 0);
        patch_seg_base((segment_command_64_t*)y_kernel.find_segment("__PLK_LINKEDIT"), new_prelink_info_fileoff, new_prelink_info_base, 0);
        patch_seg_base((segment_command_64_t*)y_kernel.find_segment("__PRELINK_INFO"), new_prelink_info_fileoff, new_prelink_info_base, prelink_info_size);

        // 修改Kext段基址
        // 20240526: fileoff也要修改
        for (auto kext : y_kernel.kexts) {
            if (kext->exec_macho) {
                if (kext->exec_macho->find_segment("__TEXT")) {
                    mach_header_64_t* new_hdr = (mach_header_64_t*)((uint64_t)prelink_text_buf + kext->text_off);
                    struct load_command* lcd = (struct load_command*)(new_hdr + 1);
                    for (uint32_t i = 0; i < new_hdr->ncmds; i++) {
                        if (lcd->cmd == LC_SEGMENT_64) {
                            segment_command_64_t* seg = (segment_command_64_t*)lcd;
                            if (!strncmp(seg->segname, "__TEXT", 16)) {
                                patch_seg_vmbase((segment_command_64_t*)lcd, new_prelink_text_base + kext->text_off, seg->filesize);
                                printf("Kext %s new __TEXT at 0x%" PRIx64 "\n", kext->kext_id, new_prelink_text_base + kext->text_off);
                            } else if (!strncmp(seg->segname, "__TEXT_EXEC", 16)) {
                                patch_seg_vmbase((segment_command_64_t*)lcd, new_prelink_text_exec_base + kext->text_exec_off, seg->vmsize);
                                printf("Kext new __TEXT_EXEC at 0x%" PRIx64 "\n", new_prelink_text_exec_base + kext->text_exec_off);
                                patch_seg_fileoff((segment_command_64_t*)lcd, (new_prelink_text_exec_fileoff + kext->text_exec_off) - (new_prelink_text_fileoff + kext->text_off), seg->filesize);
                                // printf("%p -- %p\n", (kerenl_text_exec_off + kext->text_exec_off), (new_prelink_text_fileoff + kext->text_off));
                            } else if (!strncmp(seg->segname, "__DATA", 16)) {
                                patch_seg_vmbase((segment_command_64_t*)lcd, new_prelink_data_base + kext->data_off, seg->filesize);
                                printf("Kext new __DATA at 0x%" PRIx64 "\n", new_prelink_data_base + kext->data_off);
                                patch_seg_fileoff((segment_command_64_t*)lcd, (new_prelink_data_fileoff + kext->data_off) - (new_prelink_text_fileoff + kext->text_off), seg->filesize);
                            } else if (!strncmp(seg->segname, "__DATA_CONST", 16)) {
                                patch_seg_vmbase((segment_command_64_t*)lcd, new_prelink_data_const_base + kext->data_const_off, seg->filesize);
                                printf("Kext new __DATA_CONST at 0x%" PRIx64 "\n", new_prelink_data_const_base + kext->data_const_off);
                                patch_seg_fileoff((segment_command_64_t*)lcd, (new_prelink_data_const_fileoff + kext->data_const_off) - (new_prelink_text_fileoff + kext->text_off), seg->filesize);
                            } else if (!strncmp(seg->segname, "__LINKEDIT", 16)) {
                                patch_seg_vmbase((segment_command_64_t*)lcd, new_prelink_info_base, 0);
                                patch_seg_fileoff((segment_command_64_t*)lcd, new_prelink_info_fileoff, 0);
                            }
                        } else if (lcd->cmd == LC_SEGMENT) {
                        }
                        lcd = (struct load_command*)((uint64_t)lcd + lcd->cmdsize);
                    }
                }
            }
        }
        // 最后将段复制到内核中
        printf("New kernel filesize: 0x%" PRIx64 "\n", new_kernel_size);
        y_kernel.file_buf = (char*)realloc(y_kernel.file_buf, new_kernel_size);
        y_kernel.file_size = new_kernel_size;
        memcpy((void*)((uint64_t)y_kernel.file_buf + new_prelink_text_fileoff), prelink_text_buf, prelink_text_size);
        memcpy((void*)((uint64_t)y_kernel.file_buf + new_prelink_text_exec_fileoff), prelink_text_exec_buf, prelink_text_exec_size);
        memcpy((void*)((uint64_t)y_kernel.file_buf + new_prelink_data_const_fileoff), prelink_data_const_buf, prelink_data_const_size);
        memcpy((void*)((uint64_t)y_kernel.file_buf + new_prelink_data_fileoff), prelink_data_buf, prelink_data_size);
        memcpy((void*)((uint64_t)y_kernel.file_buf + new_prelink_info_fileoff), prelink_info_buf, prelink_info_size);

        free(prelink_text_buf);
        free(prelink_text_exec_buf);
        free(prelink_data_const_buf);
        free(prelink_data_buf);
        free(prelink_info_buf);
    }
    return unresolved_externals;
}

uint32_t patch_ios_kernel(KernelMacho& kernel, const char* patch_path)
{
    std::ifstream patch_file_fs(patch_path);
    if (!patch_file_fs) {
        printf("Faild to load kernel patch list file %s!\n", patch_path);
        return 1;
    }

    char tmp_line[255];
    uint64_t dst_addr = 0;
    uint32_t file_off = 0;
    uint32_t length;
    uint32_t value = 0;

    while (patch_file_fs.getline(tmp_line, 255)) {
        if (tmp_line[0] == '#') {
            continue;
        } else if (tmp_line[0] == '*') {
            // 目标地址
            unsigned long long parsed_addr = 0;
            if (sscanf(tmp_line, "*0x%llx:", &parsed_addr) <= 0) {
                return 1;
            }
            dst_addr = static_cast<uint64_t>(parsed_addr);

            file_off = kernel.get_fileoff(dst_addr);
            if (!file_off) {
                printf("Faild to get dst addr 0x%" PRIx64 " fileoff\n", dst_addr);
                return 1;
            }
        } else if (tmp_line[0] == '+') {
            // 补丁内容
            length = strlen(tmp_line);
            if ((length - 1) % 2 == 0) {
                sscanf(tmp_line, "+%x", &value);
                // printf("Patching 0x%llx(0x%x)\n", dst_addr, file_off);
                // printf("%x\n", *((uint32_t*)((uint64_t)kernel.file_buf + file_off)));
                *((uint32_t*)((uint64_t)kernel.file_buf + file_off)) = value;
                file_off += sizeof(uint32_t);
                // printf("%x\n", n);
            }
        }
    }

    return 0;
}
