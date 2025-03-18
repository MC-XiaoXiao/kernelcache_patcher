
#include <unordered_set>

#include <capstone/capstone.h>
#include <keystone/keystone.h>
#include <tinyxml2.h>

#include <Patcher.h>
#include <Plist.h>

// 得到单条指令的立即数
#pragma mark imp:得到单条指令的立即数
static uint64_t getSingleIMM(csh handle, const cs_insn* insn)
{
    int i;
    uint64_t imm;
    int acount = cs_op_count(handle, insn, ARM64_OP_IMM);
    if (acount) {
        if (acount > 1)
            printf("getSingleIMM Immediate number more than one\n");
        for (i = 1; i < acount + 1; /*i++*/) {
            int index = cs_op_index(handle, insn, ARM64_OP_IMM, i);
            imm = insn->detail->arm64.operands[index].imm;
            return imm;
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
    for (int i = 0; i < seg->nsects; i++) {
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
    for (int i = 0; i < seg->nsects; i++) {
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
    uint64_t start,
    uint64_t end,
    uint32_t reg,
    std::vector<int>& indexs,
    uint32_t& off)
{
    std::unordered_set<int> used_addr;
    bool find_first_off = false;
    bool find_this_off = false;
    uint32_t first_off = ~0;
    uint32_t this_off = ~0;
    uint32_t this_write_reg;
    uint32_t this_read_reg;

    for (size_t off_index = start + 1; off_index < end; off_index++) {
        this_write_reg = 0;
        this_read_reg = 0;
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
            } else {
                // printf("%s, 0x%llx\n", insn[off_index].mnemonic, insn[off_index].address);
            }
        } else if (!strcmp(insn[off_index].mnemonic, "adrp")) {
            int reg_index = cs_op_index(handle, &insn[off_index], ARM64_OP_REG, 1);
            if (reg == insn[off_index].detail->arm64.operands[reg_index].reg) {
                // printf("Over\n");
                uint64_t this_base = getSingleIMM(handle, &insn[off_index]);
                uint64_t need_base = getSingleIMM(handle, insn);
                if (this_base == need_base) {
                    printf("%d\n", __LINE__);
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
            
            // if(read_tmp == reg) {
            //     printf("0x%llx: mov: %s, %s\n", insn[off_index].address, cs_reg_name(handle, write_tmp), cs_reg_name(handle, read_tmp));
            //     reg = write_tmp;
            // } else {
                this_write_reg  = insn[off_index].detail->arm64.operands[write_reg_index].reg;
            // }
            
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
            if (first_off == this_off && this_read_reg == reg) {
                off = this_off;
                // printf("Found off: 0x%lx 0x%llx\n", this_off, insn[off_index].address);
                indexs.push_back(off_index);
            }

            if (this_write_reg == reg) {
                // printf("Over: %llx\n", insn[off_index].address);
                break;
            }
        }
    }

    return find_first_off;
}

int vmaddr_segment_rebase(uint64_t addr, segment_command_64_t *segment, uint64_t new_base)
{
    return 0;
}

void patch_kext_to_kernel(KernelMacho& y_kernel, KernelMacho& i_kernel)
{
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

        void* prelink_text_buf = calloc(sizeof(char), prelink_text_size);
        void* prelink_text_exec_buf = calloc(sizeof(char), prelink_text_exec_size);
        void* prelink_data_buf = calloc(sizeof(char), prelink_data_size);
        void* prelink_data_const_buf = calloc(sizeof(char), prelink_data_const_size);

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
        segment_command_64_t* y_prelink_text_segment = (segment_command_64_t*)(y_kernel.find_segment("__PRELINK_TEXT"));
        segment_command_64_t* y_prelink_text_exec_segment = (segment_command_64_t*)(y_kernel.find_segment("__PLK_TEXT_EXEC"));
        segment_command_64_t* y_prelink_data_segment = (segment_command_64_t*)(y_kernel.find_segment("__PRELINK_DATA"));
        segment_command_64_t* y_prelink_data_const_segment = (segment_command_64_t*)(y_kernel.find_segment("__PLK_DATA_CONST"));
        segment_command_64_t* y_linkedit_seg = (segment_command_64_t*)y_kernel.find_segment("__LINKEDIT");

        segment_command_64_t* i_text_segment = (segment_command_64_t*)(i_kernel.find_segment("__TEXT"));
        segment_command_64_t* i_prelink_text_segment = (segment_command_64_t*)(i_kernel.find_segment("__PRELINK_TEXT"));
        segment_command_64_t* i_prelink_text_exec_segment = (segment_command_64_t*)(i_kernel.find_segment("__PLK_TEXT_EXEC"));
        segment_command_64_t* i_prelink_data_segment = (segment_command_64_t*)(i_kernel.find_segment("__PRELINK_DATA"));
        segment_command_64_t* i_prelink_data_const_segment = (segment_command_64_t*)(i_kernel.find_segment("__PLK_DATA_CONST"));
        segment_command_64_t* i_linkedit_seg = (segment_command_64_t*)y_kernel.find_segment("__LINKEDIT");

        uint64_t kernel_text_vmbase = y_text_segment->vmaddr;
        new_prelink_data_const_base = kernel_text_vmbase - prelink_data_const_size;
        new_prelink_data_base = ALIGN_UP(y_linkedit_seg->vmaddr + y_linkedit_seg->vmsize, 1 << 12);
        new_prelink_text_exec_base = new_prelink_data_const_base - prelink_text_exec_size;
        new_prelink_text_base = new_prelink_text_exec_base - prelink_text_size;

        y_kernel.prelink_text_base = new_prelink_text_base;
        printf("Prelink text will at 0x%016llx\n", new_prelink_text_base);
        printf("Prelink data will at 0x%016llx\n", new_prelink_data_base);

        // 获取内核末尾
        uint64_t end_fileoff = y_linkedit_seg->fileoff + y_linkedit_seg->filesize;
        end_fileoff = ALIGN_UP(end_fileoff, 1 << 12);
        printf("End ad 0x%016llx\n", end_fileoff);
        uint64_t new_prelink_text_fileoff = end_fileoff;
        uint64_t new_prelink_text_exec_fileoff = new_prelink_text_fileoff + prelink_text_size;
        uint64_t new_prelink_data_const_fileoff = new_prelink_text_exec_fileoff + prelink_text_exec_size;
        printf("data const off: %p\n", new_prelink_data_const_fileoff);
        uint64_t new_prelink_data_fileoff = new_prelink_data_const_fileoff + prelink_data_const_size;

        // 修改Kext符号表
        csh handle;
        if (cs_open(CS_ARCH_ARM64, (cs_mode)(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN), &handle)) {
            printf("ERROR: Failed to initialize engine!\n");
            return;
        }
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
        cs_insn* insn;

        ks_engine* ks;
        if (ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks)) {
            printf("ERROR: failed on ks_open(), quit\n");
            return;
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
                        if (kext->exec_macho->symbol_name_map["_kmod_info"]) {
                            kext->kmod_addr = kext->exec_macho->symbol_name_map["_kmod_info"]->symbol_addr - kext_data_seg->vmaddr;
                            kext->kmod_addr += new_prelink_data_base + kext->data_off;
                            printf("New kmod addr: %p\n", kext->kmod_addr);
                        }
                    } else {
                        kext->kmod_addr = 0;
                    }
                } else {
                    kext->kmod_addr = kext->kmod_addr - kext_data_seg->vmaddr + new_prelink_data_base + kext->data_off;
                }

                if (kext->kmod_addr) {
                    kmod_info_64_v1_t* kext_kmod = (kmod_info_64_v1_t*)(kext->kmod_addr - new_prelink_data_base + (uint64_t)prelink_data_buf);
                    printf("K add: 0x%llx\n", kext_kmod->address);
                    printf("K n: %s\n", kext_kmod->name);
                    kext_kmod->address = new_prelink_text_base + kext->text_off;
                    segment_command_64_t* kext_text_exec_seg = (segment_command_64_t*)kext->exec_macho->find_segment("__TEXT_EXEC");
                    if (kext_kmod->start_addr) {
                        kext_kmod->start_addr -= kext_text_exec_seg->vmaddr;
                        kext_kmod->start_addr += new_prelink_text_exec_base + kext->text_exec_off;
                        printf("k start at: 0x%llx\n", kext_kmod->start_addr);
                    }
                    if (kext_kmod->stop_addr) {
                        kext_kmod->stop_addr -= kext_text_exec_seg->vmaddr;
                        kext_kmod->stop_addr += new_prelink_text_exec_base + kext->text_exec_off;
                    }
                }

                // 处理DATA段的地址
                if (kext_data_seg) {
                    section_64_t* kext_cstring_sect = (section_64*)kext->exec_macho->find_section("__TEXT", "__cstring");
                    uint64_t kext_start_addr = kext->is_from_file ? kext_cstring_sect->addr : kext_text_seg->vmaddr;
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
                                if (!i_kernel.symbol_addr_map[addrs[i]]) {
                                    bool found_symbol = false;
                                    // 找不到再从i_kernel的kext里面找
                                    for (size_t j = 0; j < kext->depends.size(); j++) {
                                        if (!kext->depends[j]->is_from_file && kext->depends[j]->exec_macho) {
                                            segment_command_64_t* dep_text_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__TEXT");
                                            segment_command_64_t* dep_text_exec_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__TEXT_EXEC");
                                            segment_command_64_t* dep_data_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__DATA");
                                            segment_command_64_t* dep_data_const_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__DATA_CONST");

                                            if (addrs[i] >= dep_text_seg->vmaddr && addrs[i] < dep_text_seg->vmaddr + dep_text_seg->vmsize) {
                                                addrs[i] -= dep_text_seg->vmaddr;
                                                addrs[i] += new_prelink_text_base + kext->depends[j]->text_off;
                                                found_symbol = true;
                                            } else if (addrs[i] >= dep_text_exec_seg->vmaddr && addrs[i] < dep_text_exec_seg->vmaddr + dep_text_exec_seg->vmsize) {
                                                addrs[i] -= dep_text_exec_seg->vmaddr;
                                                addrs[i] += new_prelink_text_exec_base + kext->depends[j]->text_exec_off;
                                                found_symbol = true;
                                            } else if (addrs[i] >= dep_data_seg->vmaddr && addrs[i] < dep_data_seg->vmaddr + dep_data_seg->vmsize) {
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
                                            printf("%d: Not found kernel symbol %llx at 0x%llx\n", __LINE__, addrs[i], kext_data_seg->vmaddr + i * sizeof(uint64_t));
                                } else {
                                    const char* need_symbol_name = i_kernel.symbol_addr_map[addrs[i]]->symbol_name;
                                    if (y_kernel.symbol_name_map[need_symbol_name]) {
                                        // printf("%s\n", i_kernel.symbol_addr_map[addrs[i]]->symbol_name);
                                        addrs[i] = y_kernel.symbol_name_map[need_symbol_name]->symbol_addr;
                                    } else {
                                        printf("Not found kernel symbol(%s)\n", need_symbol_name);
                                    }
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
                    if (init_sect && init_sect && kext_text_exec_seg) {
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

                    printf("Kext __TEXT_EXEC at %llx\n", kext_text_exec_seg->vmaddr);
                    printf("Kext __DATA at %llx\n", kext_data_seg->vmaddr);
                    printf("Kext __DATA_CONST at %llx\n", kext_data_const_seg->vmaddr);

                    section_64_t* kext_cstring_sect = (section_64*)kext->exec_macho->find_section("__TEXT", "__cstring");
                    section_64_t* kext_text_const_sect = (section_64*)kext->exec_macho->find_section("__TEXT", "__const");
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
                                if (addrs[i] >= kext_text_seg->vmaddr && addrs[i] < kext_text_seg->vmaddr + kext_text_seg->vmsize) {
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

                                } else if (addrs[i] >= kext_text_exec_seg->vmaddr && addrs[i] < kext_text_exec_seg->vmaddr + kext_text_exec_seg->vmsize) {
                                    // printf("Data in __TEXT_EXEC, addr: %llx\n", addrs[i]);
                                    addrs[i] -= kext_text_exec_seg->vmaddr;
                                    addrs[i] += new_prelink_text_exec_base + kext->text_exec_off;
                                } else if (addrs[i] >= kext_data_seg->vmaddr && addrs[i] < kext_data_seg->vmaddr + kext_data_seg->vmsize) {
                                    // printf("Data in __DATA, addr: %llx\n", addrs[i]);
                                    addrs[i] -= kext_data_seg->vmaddr;
                                    addrs[i] += new_prelink_data_base + kext->data_off;
                                } else if (addrs[i] >= kext_data_const_seg->vmaddr && addrs[i] < kext_data_const_seg->vmaddr + kext_data_const_seg->vmsize) {
                                    // printf("Data in __DATA_CONST, addr: %llx\n", addrs[i]);
                                    addrs[i] -= kext_data_const_seg->vmaddr;
                                    addrs[i] += new_prelink_data_const_base + kext->data_const_off;
                                } else if (!kext->is_from_file) {
                                    if (addrs[i]) {
                                        if (!i_kernel.symbol_addr_map[addrs[i]]) {
                                            bool found_symbol = false;
                                            // 找不到再从i_kernel的kext里面找
                                            for (size_t j = 0; j < kext->depends.size(); j++) {
                                                if (!kext->depends[j]->is_from_file && kext->depends[j]->exec_macho) {
                                                    segment_command_64_t* dep_text_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__TEXT");
                                                    segment_command_64_t* dep_text_exec_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__TEXT_EXEC");
                                                    segment_command_64_t* dep_data_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__DATA");
                                                    segment_command_64_t* dep_data_const_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__DATA_CONST");

                                                    if (addrs[i] >= dep_text_seg->vmaddr && addrs[i] < dep_text_seg->vmaddr + dep_text_seg->vmsize) {
                                                        addrs[i] -= dep_text_seg->vmaddr;
                                                        addrs[i] += new_prelink_text_base + kext->depends[j]->text_off;
                                                        found_symbol = true;
                                                    } else if (addrs[i] >= dep_text_exec_seg->vmaddr && addrs[i] < dep_text_exec_seg->vmaddr + dep_text_exec_seg->vmsize) {
                                                        addrs[i] -= dep_text_exec_seg->vmaddr;
                                                        addrs[i] += new_prelink_text_exec_base + kext->depends[j]->text_exec_off;
                                                        found_symbol = true;
                                                    } else if (addrs[i] >= dep_data_seg->vmaddr && addrs[i] < dep_data_seg->vmaddr + dep_data_seg->vmsize) {
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
                                                    printf("%d: Not found kernel symbol %llx at 0x%llx\n", __LINE__, addrs[i], kext_const_sect->addr + i * sizeof(uint64_t));
                                            // printf("%d: Not found kernel symbol %llx at 0x%llx\n", __LINE__, addrs[i], &addrs[i] - ((uint64_t)prelink_data_const_buf + kext->data_const_off) + kext_data_const_seg->vmaddr);
                                        } else {
                                            const char* need_symbol_name = i_kernel.symbol_addr_map[addrs[i]]->symbol_name;
                                            if (y_kernel.symbol_name_map[need_symbol_name]) {
                                                // printf("%s\n", i_kernel.symbol_addr_map[addrs[i]]->symbol_name);
                                                addrs[i] = y_kernel.symbol_name_map[need_symbol_name]->symbol_addr;
                                            } else {
                                                printf("Not found kernel symbol(%s)\n", need_symbol_name);
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if (kext_got_sect) {
                            if (!kext->is_from_file) {
                                addrs = (uint64_t*)((uint64_t)prelink_data_const_buf + kext->data_const_off + kext_got_sect->addr - kext_data_const_seg->vmaddr);
                                for (size_t i = 0; i < kext_got_sect->size / sizeof(uint64_t); i++) {
                                    if (i_kernel.symbol_addr_map[addrs[i]]) {
                                        const char* find_symbol_name = i_kernel.symbol_addr_map[addrs[i]]->symbol_name;
                                        if (y_kernel.symbol_name_map[find_symbol_name]) {
                                            addrs[i] = y_kernel.symbol_name_map[find_symbol_name]->symbol_addr;
                                        } else {
                                            printf("%d: Not fount symbol %s\n", __LINE__, find_symbol_name);
                                            // addrs[i] = 0;
                                        }
                                    } else {
                                        bool found_symbol = false;
                                        // 找不到再从i_kernel的kext里面找
                                        for (size_t j = 0; j < kext->depends.size(); j++) {
                                            if (!kext->depends[j]->is_from_file && kext->depends[j]->exec_macho) {
                                                segment_command_64_t* dep_text_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__TEXT");
                                                segment_command_64_t* dep_text_exec_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__TEXT_EXEC");
                                                segment_command_64_t* dep_data_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__DATA");
                                                segment_command_64_t* dep_data_const_seg = (segment_command_64_t*)kext->depends[j]->exec_macho->find_segment("__DATA_CONST");

                                                if (addrs[i] >= dep_text_seg->vmaddr && addrs[i] < dep_text_seg->vmaddr + dep_text_seg->vmsize) {
                                                    addrs[i] -= dep_text_seg->vmaddr;
                                                    addrs[i] += new_prelink_text_base + kext->depends[j]->text_off;
                                                    found_symbol = true;
                                                } else if (addrs[i] >= dep_text_exec_seg->vmaddr && addrs[i] < dep_text_exec_seg->vmaddr + dep_text_exec_seg->vmsize) {
                                                    addrs[i] -= dep_text_exec_seg->vmaddr;
                                                    addrs[i] += new_prelink_text_exec_base + kext->depends[j]->text_exec_off;
                                                    found_symbol = true;
                                                } else if (addrs[i] >= dep_data_seg->vmaddr && addrs[i] < dep_data_seg->vmaddr + dep_data_seg->vmsize) {
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
                                                printf("%d:Not found kernel symbol %llx at 0x%llx\n", __LINE__, addrs[i], kext_got_sect->addr + i * sizeof(uint64_t));
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
                    printf("Kext TEXT at 0x%llx\n", kext_text_seg->vmaddr);
                }
                if (kext_text_exec_seg) {
                    size_t count;
                    cs_insn* insn;
                    uint64_t kext_text_exec_buf_addr = (uint64_t)prelink_text_exec_buf + kext->text_exec_off;

                    count = cs_disasm(handle, (const uint8_t*)kext_text_exec_buf_addr, kext_text_exec_seg->filesize, kext_text_exec_seg->vmaddr, 0, &insn);
                    printf("Count: %x\n");
                    // printf("Nedd: %x\n", kext_text_exec_seg->filesize / 4);

                    char new_insn[30];
                    if (count > 0) {
                        for (size_t i = 0; i < count; i++) {
                            if (strstr(insn[i].mnemonic, "adrp")) {
                                int acount = cs_op_count(handle, &insn[i], ARM64_OP_IMM);
                                // printf("acount: %d\n", acount);
                                if (acount == 1) {
                                    uint64_t* xx = NULL;
                                    uint64_t imm = getSingleIMM(handle, &insn[i]);

                                    unsigned char* encode;
                                    size_t encode_size;
                                    size_t stat_count;
                                    int reg_index = cs_op_index(handle, &insn[i], ARM64_OP_REG, 1);
                                    const char* write_reg = cs_reg_name(handle, insn[i].detail->arm64.operands[reg_index].reg);
                                    uint64_t patch_addr = 0;

                                    // 寻找匹配的off
                                    std::vector<int> off_indexs;
                                    uint32_t off = 0;
                                    // printf("Found next for 0x%llx\n", insn[i].address);
                                    bool find_off = find_offs(handle, insn, i, count, insn[i].detail->arm64.operands[reg_index].reg, off_indexs, off);
                                    if (!find_off) {
                                        printf("Not found offs for 0x%llx\n", insn[i].address);
                                        off = 0;
                                    }

                                    if (off + imm >= kext_text_seg->vmaddr && off + imm < kext_text_seg->vmaddr + kext_text_seg->vmsize) {
                                        patch_addr = off + imm - kext_text_seg->vmaddr;
                                        patch_addr += new_prelink_text_base + kext->text_off;
                                    } else if (off + imm >= kext_text_exec_seg->vmaddr && off + imm < kext_text_exec_seg->vmaddr + kext_text_exec_seg->vmsize) {
                                        patch_addr = off + imm - kext_text_exec_seg->vmaddr;
                                        patch_addr += new_prelink_text_exec_base + kext->text_exec_off;
                                    } else if (off + imm >= kext_data_seg->vmaddr && off + imm < kext_data_seg->vmaddr + kext_data_seg->vmsize) {
                                        patch_addr = off + imm - kext_data_seg->vmaddr;
                                        patch_addr += new_prelink_data_base + kext->data_off;

                                    // } else if (off + imm >= kext_data_const_seg->vmaddr && off + imm < (kext_data_const_seg->vmaddr + kext_data_const_seg->vmsize)) {
                                    } else if(IN_SEGMENT_RANGE(off + imm, kext_data_const_seg)) {
                                        patch_addr = off + imm - kext_data_const_seg->vmaddr;
                                        patch_addr += new_prelink_data_const_base + kext->data_const_off;
                                    } else {
                                        continue;
                                    }
                                    off = patch_addr & 0xFFF;
                                    // printf("Addr: %llx\n", patch_addr);
                                    // printf("off: %llx\n", off);
                                    patch_addr &= ~0xFFF;

                                    sprintf(new_insn, "adrp %s, 0x%llx", write_reg, patch_addr);
                                    uint64_t insn_addr = insn[i].address - kext_text_exec_seg->vmaddr + new_prelink_text_exec_base + kext->text_exec_off;
                                    // printf("%llx\n", insn_addr);
                                    if (ks_asm(ks, new_insn, insn_addr, &encode, &encode_size, &stat_count)) {
                                        printf("Can not ks_asm code %s(0x%llx)\n", new_insn, insn[i].address);
                                        exit(-1);
                                    } else {
                                        for (size_t j = 0; j < encode_size; j++) {
                                            ((unsigned char*)((uint64_t)prelink_text_exec_buf + insn_addr - new_prelink_text_exec_base))[j] = encode[j];
                                        }
                                    }

                                    // 处理匹配的off
                                    if (find_off) {
                                        for (auto off_index : off_indexs) {
                                            if (!strcmp(insn[off_index].mnemonic, "add")) {
                                                int rcount = cs_op_count(handle, &insn[off_index], ARM64_OP_REG);
                                                const char* reg1_name;
                                                const char* reg2_name;
                                                if (rcount == 2) {
                                                    int reg1_index = cs_op_index(handle, &insn[off_index], ARM64_OP_REG, 1);
                                                    int reg2_index = cs_op_index(handle, &insn[off_index], ARM64_OP_REG, 2);
                                                    reg1_name = cs_reg_name(handle, insn[off_index].detail->arm64.operands[reg1_index].reg);
                                                    reg2_name = cs_reg_name(handle, insn[off_index].detail->arm64.operands[reg2_index].reg);

                                                    sprintf(new_insn, "add %s, %s, #0x%lx", reg1_name, reg2_name, off);
                                                }
                                            } else if (strstr(insn[off_index].mnemonic, "ldr")) {
                                                int reg1_index = cs_op_index(handle, &insn[off_index], ARM64_OP_REG, 1);
                                                const char* reg1_name = cs_reg_name(handle, insn[off_index].detail->arm64.operands[reg1_index].reg);
                                                int reg2_index = cs_op_index(handle, &insn[off_index], ARM64_OP_MEM, 1);
                                                const char* reg2_name = cs_reg_name(handle, insn[off_index].detail->arm64.operands[reg2_index].mem.base);

                                                sprintf(new_insn, "%s %s, [%s, #0x%lx]", insn[off_index].mnemonic, reg1_name, reg2_name, off);
                                            } else if (strstr(insn[off_index].mnemonic, "str")) {
                                                int reg1_index = cs_op_index(handle, &insn[off_index], ARM64_OP_REG, 1);
                                                const char* reg1_name = cs_reg_name(handle, insn[off_index].detail->arm64.operands[reg1_index].reg);
                                                int reg2_index = cs_op_index(handle, &insn[off_index], ARM64_OP_MEM, 1);
                                                const char* reg2_name = cs_reg_name(handle, insn[off_index].detail->arm64.operands[reg2_index].mem.base);

                                                sprintf(new_insn, "%s %s, [%s, #0x%lx]", insn[off_index].mnemonic, reg1_name, reg2_name, off);
                                            }

                                            insn_addr = insn[off_index].address - kext_text_exec_seg->vmaddr + new_prelink_text_exec_base + kext->text_exec_off;
                                            if (ks_asm(ks, new_insn, insn_addr, &encode, &encode_size, &stat_count)) {
                                                printf("Can not ks_asm code %s(0x%llx)\n", new_insn, insn[off_index].address);
                                                exit(-1);
                                            } else {
                                                for (size_t j = 0; j < encode_size; j++) {
                                                    ((unsigned char*)((uint64_t)prelink_text_exec_buf + insn_addr - new_prelink_text_exec_base))[j] = encode[j];
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // 处理外部符号
                struct dysymtab_command* kext_dysymtab = (struct dysymtab_command*)find_command((mach_header_64_t*)((uint64_t)prelink_text_buf + kext->text_off), LC_DYSYMTAB);
                if (kext->is_from_file && kext_dysymtab) {
                    segment_command_64_t* kext_linkedit_seg = (segment_command_64_t*)kext->exec_macho->find_segment("__LINKEDIT");
                    if (kext_linkedit_seg) {
                        struct relocation_info* ext_ri = (struct relocation_info*)((uint64_t)kext->exec_macho->file_buf + kext_dysymtab->extreloff);

                        for (int i = 0; i < kext_dysymtab->nextrel; i++) {
                            if (ext_ri[i].r_extern == 1) {
                                const char* symbol_name = NULL;
                                if (ext_ri[i].r_symbolnum < kext->exec_macho->symbol_count)
                                    symbol_name = kext->exec_macho->symbol_list[ext_ri[i].r_symbolnum]->symbol_name;

                                if (!symbol_name)
                                    continue;

                                uint64_t found_addr = 0;
                                if (!y_kernel.symbol_name_map[symbol_name]) {
                                    bool found_symbol = false;
                                    for (auto dep_kext : kext->depends) {
                                        if (dep_kext->exec_macho->symbol_name_map[symbol_name]) {
                                            // 处理符号地址
                                            segment_command_64_t* dep_text_seg = (segment_command_64_t*)dep_kext->exec_macho->find_segment("__TEXT");
                                            segment_command_64_t* dep_text_exec_seg = (segment_command_64_t*)dep_kext->exec_macho->find_segment("__TEXT_EXEC");
                                            segment_command_64_t* dep_data_seg = (segment_command_64_t*)dep_kext->exec_macho->find_segment("__DATA");
                                            segment_command_64_t* dep_data_const_seg = (segment_command_64_t*)dep_kext->exec_macho->find_segment("__DATA_CONST");

                                            found_addr = dep_kext->exec_macho->symbol_name_map[symbol_name]->symbol_addr;
                                            if (dep_kext->exec_macho->addr_in_segment(dep_text_seg, found_addr)) {
                                                found_addr -= dep_text_seg->vmaddr;
                                                found_addr += new_prelink_text_base + dep_kext->text_off;
                                            } else if (dep_kext->exec_macho->addr_in_segment(dep_text_exec_seg, found_addr)) {
                                                found_addr -= dep_text_exec_seg->vmaddr;
                                                found_addr += new_prelink_text_exec_base + dep_kext->text_exec_off;
                                            } else if (dep_kext->exec_macho->addr_in_segment(dep_data_seg, found_addr)) {
                                                found_addr -= dep_data_seg->vmaddr;
                                                found_addr += new_prelink_data_base + dep_kext->data_off;
                                            } else if (dep_kext->exec_macho->addr_in_segment(dep_data_const_seg, found_addr)) {
                                                found_addr -= dep_data_const_seg->vmaddr;
                                                found_addr += new_prelink_data_const_base + dep_kext->data_const_off;
                                            } else {
                                                printf("Symbol %s out range\n", symbol_name);
                                                continue;
                                            }

                                            found_symbol = true;
                                        }
                                    }

                                    if (!found_symbol)
                                        printf("Not found symbol %s\n", symbol_name);
                                } else {
                                    Symbol* symbol = y_kernel.symbol_name_map[symbol_name];
                                    if (symbol->symbol_addr) {
                                        found_addr = symbol->symbol_addr;
                                    } else {
                                        printf("symbol not in kernel\n");
                                    }
                                }

                                if (found_addr) {
                                    uint64_t* patch_symbol = NULL;
                                    if (ext_ri[i].r_address >= kext_data_const_seg->vmaddr && ext_ri[i].r_address < kext_data_const_seg->vmaddr + kext_data_const_seg->vmsize) {
                                        // patch_symbol -= kext_data_const_seg->vmaddr;
                                        // printf("PP: %llx\n", (ext_ri[i].r_address - kext_data_const_seg->vmaddr));
                                        patch_symbol = (uint64_t*)((uint64_t)prelink_data_const_buf + kext->data_const_off + ext_ri[i].r_address - kext_data_const_seg->vmaddr);
                                        *patch_symbol = found_addr;
                                        // printf("Patch addr: 0x%llx\n", (uint64_t)patch_symbol - (uint64_t)prelink_data_const_buf + new_prelink_data_const_base);
                                    } else if (ext_ri[i].r_address >= kext_data_seg->vmaddr && ext_ri[i].r_address < kext_data_seg->vmaddr + kext_data_seg->vmsize) {
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
                    for (int i = 0; i < new_hdr->ncmds; i++) {
                        if (lcd->cmd == LC_SEGMENT_64) {
                            segment_command_64_t* seg = (segment_command_64_t*)lcd;
                            if (!strncmp(seg->segname, "__TEXT", 16)) {
                                patch_seg_vmbase((segment_command_64_t*)lcd, new_prelink_text_base + kext->text_off, seg->filesize);
                                printf("Kext %s new __TEXT at 0x%llx\n", kext->kext_id, new_prelink_text_base + kext->text_off, seg->filesize);
                            } else if (!strncmp(seg->segname, "__TEXT_EXEC", 16)) {
                                patch_seg_vmbase((segment_command_64_t*)lcd, new_prelink_text_exec_base + kext->text_exec_off, seg->vmsize);
                                printf("Kext new __TEXT_EXEC at 0x%llx\n", new_prelink_text_exec_base + kext->text_exec_off);
                                patch_seg_fileoff((segment_command_64_t*)lcd, (new_prelink_text_exec_fileoff + kext->text_exec_off) - (new_prelink_text_fileoff + kext->text_off), seg->filesize);
                                // printf("%p -- %p\n", (kerenl_text_exec_off + kext->text_exec_off), (new_prelink_text_fileoff + kext->text_off));
                            } else if (!strncmp(seg->segname, "__DATA", 16)) {
                                patch_seg_vmbase((segment_command_64_t*)lcd, new_prelink_data_base + kext->data_off, seg->filesize);
                                printf("Kext new __DATA at 0x%llx\n", new_prelink_data_base + kext->data_off);
                                patch_seg_fileoff((segment_command_64_t*)lcd, (new_prelink_data_fileoff + kext->data_off) - (new_prelink_text_fileoff + kext->text_off), seg->filesize);
                            } else if (!strncmp(seg->segname, "__DATA_CONST", 16)) {
                                patch_seg_vmbase((segment_command_64_t*)lcd, new_prelink_data_const_base + kext->data_const_off, seg->filesize);
                                printf("Kext new __DATA_CONST at 0x%llx\n", new_prelink_data_const_base + kext->data_const_off);
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
        printf("New kernel filesize: 0x%x\n", new_kernel_size);
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
}

uint32_t patch_ios_kernel(KernelMacho& kernel, const char* patch_path)
{
    std::ifstream patch_file_fs(patch_path);
    if (!patch_file_fs) {
        printf("Faild to load kernel patch list file %s!\n", patch_path);
        return 1;
    }

    char tmp_line[255];
    uint64_t dst_addr;
    uint32_t file_off;
    segment_command_64_t* exec_seg = (segment_command_64_t*)kernel.find_segment("__TEXT_EXEC");
    uint32_t length;
    uint32_t value = 0;

    while (patch_file_fs.getline(tmp_line, 255)) {
        if (tmp_line[0] == '#') {
            continue;
        } else if (tmp_line[0] == '*') {
            // 目标地址
            if (sscanf(tmp_line, "*0x%llx:", &dst_addr) <= 0) {
                return 1;
            }

            file_off = kernel.get_fileoff(dst_addr);
            if (!file_off) {
                printf("Faild to get dst addr 0x%lx fileoff\n", dst_addr);
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