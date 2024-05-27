#include <cstring>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <vector>

#include <KernelMacho.h>
#include <KextMacho.h>
#include <Macho.h>
#include <tinyxml2.h>

#define PATH_LENGTH 255

#define ALIGN_UP(x, y) (((x) + (y)) & ~((y) - 1))

using namespace tinyxml2;

void format_prelink_info(KernelMacho& kernel);
Kext* load_kext_from_file(const char* path);
uint32_t get_filesize(std::ifstream& fd);
XMLElement* plist_get_item(XMLElement* elm, const char* keyName);
const char* plist_get_string(XMLElement* dictElem, const char* keyName);
uint64_t plist_get_uint64(XMLElement* dictElem, const char* keyName);
void init_kext_depends(KernelMacho& kernel, Kext* kext);
void patch_kext_to_kernel(KernelMacho& y_kernel, KernelMacho& i_kerenl);
void useage();

int main(int argc, char** argv)
{
    char your_kernel_path[PATH_LENGTH];
    char ios_kernel_path[PATH_LENGTH];
    char symbol_list_path[PATH_LENGTH];
    char kexts_path[PATH_LENGTH];
    char output_path[PATH_LENGTH];
    char kexts_list_path[PATH_LENGTH];

#if DEBUG
    strcpy(your_kernel_path, "./mach.development.bcm2837");
    strcpy(ios_kernel_path, "./kernelcache.release.ipad7.arm64");
    strcpy(symbol_list_path, "./symbols.txt");
    strcpy(kexts_path, "./kexts");
    strcpy(output_path, "./output.kernel");
#else
    if (argc < 6) {
        useage();
        exit(0);
    }
#endif

    sprintf(kexts_list_path, "%s/kexts.txt", kexts_path);
    std::ifstream kexts_list_fs(kexts_list_path);

    if (!kexts_list_fs.is_open()) {
        printf("Cannot open kexts list file!\n");
        exit(1);
    }

    KernelMacho y_kernel(your_kernel_path);
    KernelMacho i_kernel(ios_kernel_path);

    y_kernel.format_macho();
    y_kernel.init_symbols();

    i_kernel.format_macho();
    i_kernel.init_symbols();
    format_prelink_info(i_kernel);

    std::ifstream symbol_list_fs(symbol_list_path);

    if (!symbol_list_fs.is_open()) {
        printf("Cannot open iOS kernel symbol list file!\n");
        exit(1);
    }

    std::vector<const char*> kext_paths;
    char kext_path[PATH_LENGTH];
    while (kexts_list_fs.getline(kext_path, PATH_LENGTH)) {
        if (kext_path[0] == '#' || kext_path[0] == ' ')
            continue;
        char* tmp_kext_path = (char*)malloc(strlen(kext_path) + 1);
        memset(tmp_kext_path, 0, strlen(kext_path));
        strcpy(tmp_kext_path, kext_path);
        kext_paths.push_back(tmp_kext_path);
    }

    printf("Will load %ld kexts from list\n", kext_paths.size());
    for (size_t i = 0; i < kext_paths.size(); i++) {
        char kext_dir[PATH_LENGTH];
        sprintf(kext_dir, "%s/%s", kexts_path, kext_paths[i]);

        Kext* kext = load_kext_from_file(kext_dir);
        if (kext) {
            // Kext 在文件夹中
            // printf("ID: %s\n", kext->kext_id);
            // y_kernel.kexts[kext_ID] = kext;
            y_kernel.kexts.push_back(kext);
        } else if ((kext = i_kernel.find_kext(kext_paths[i])) != NULL) {
            // Kext 在Kernelcache中

            // printf("ID: %s\n", kext->kext_id);
            y_kernel.kexts.push_back(kext);
        } else {
            printf("Not found kext %s\n", kext_paths[i]);
            exit(1);
        }
    }

    for (auto kext : y_kernel.kexts) {
        printf("Loading : %s\n", kext->kext_id);
        init_kext_depends(y_kernel, kext);
        if (kext->exec_macho) {
            kext->exec_macho->init_symbols();
        }
    }

    patch_kext_to_kernel(y_kernel, i_kernel);

    std::ofstream output_file_fs(output_path, std::ios::binary);
    output_file_fs.write(y_kernel.file_buf, y_kernel.file_size);
    output_file_fs.close();
}

uint32_t get_prelink_text_size(KernelMacho& kernel)
{
    uint32_t size = 0;
    for (auto kext : kernel.kexts) {
        if (kext->exec_macho) {
            segment_command_64_t* text_seg = (segment_command_64_t*)(kext->exec_macho->find_segment("__TEXT"));
            if (text_seg) {
                size += ALIGN_UP(text_seg->vmsize, 1 << 5);
            } else if (kext->exec_macho->header) {
                if (kext->exec_macho->header->sizeofcmds) {
                    size += ALIGN_UP(kext->exec_macho->header->sizeofcmds, 1 << 5);
                }
            }
        }
    }

    return size;
}

uint32_t get_prelink_segment_size(KernelMacho& kernel, const char* seg_name)
{
    uint32_t size = 0;

    for (auto kext : kernel.kexts) {
        if (kext->exec_macho) {
            segment_command_64_t* text_exec_seg = (segment_command_64_t*)(kext->exec_macho->find_segment(seg_name));
            if (text_exec_seg) {
                size += ALIGN_UP(text_exec_seg->vmsize, 1 << 5);
            }
        }
    }

    return size;
}

void copy_segment_from_kext(Kext* kext, KernelMacho& i_kerenl, const char* kext_segname, const char* kernel_segname, void* buf, uint64_t& off)
{
    uint64_t copy_des = 0;
    uint64_t copy_src = 0;
    uint64_t copy_size = 0;

    segment_command_64_t* i_seg = (segment_command_64_t*)(i_kerenl.find_segment(kernel_segname));

    segment_command_64_t* text_exec_seg = (segment_command_64_t*)(kext->exec_macho->find_segment(kext_segname));
    if (text_exec_seg) {
        if (kext->is_from_file) {
            copy_src = (uint64_t)kext->exec_macho->file_buf + text_exec_seg->fileoff;
        } else {
            copy_src = text_exec_seg->vmaddr;
            copy_src -= i_seg->vmaddr;
            copy_src += (uint64_t)i_kerenl.file_buf + i_seg->fileoff;
        }

        copy_des = (uint64_t)buf + off;
        copy_size = text_exec_seg->filesize;
        // printf("Copy 0x%016llx -> 0x%016llx(0x%08x)\n", copy_src, off, copy_size);
        memset((void*)copy_des, 0, copy_size);
        memcpy((char*)copy_des, (char*)copy_src, copy_size);
        copy_size = ALIGN_UP(text_exec_seg->vmsize, 1 << 5);
        off += copy_size;
    }
}

void patch_seg_fileoff(segment_command_64_t* seg, uint64_t fileoff, uint64_t size)
{
    section_64_t* sect = (section_64_t*)((uint64_t)seg + sizeof(segment_command_64_t));
    for (int i = 0; i < seg->nsects; i++) {
        sect->offset = sect->offset - seg->fileoff + fileoff;
        sect = (section_64_t*)(sect + 1);
    }

    seg->fileoff = fileoff;
    seg->filesize = size;
}

void patch_seg_vmbase(segment_command_64_t* seg, uint64_t vmaddr, uint64_t size)
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

void patch_seg_base(segment_command_64_t* seg, uint64_t fileoff, uint64_t vmaddr, uint64_t size)
{
    patch_seg_vmbase(seg, vmaddr, size);
    seg->fileoff = fileoff;
    seg->filesize = size;

    section_64_t* sect = (section_64_t*)((uint64_t)seg + sizeof(segment_command_64_t));
    sect->offset = fileoff;
    sect->size = size;
}

XMLElement* new_plist_elem(XMLDocument* doc, XMLElement* ins_ele, const char* type_name, const char* key_name)
{
    XMLElement* key = doc->NewElement("key");
    key->SetText(key_name);
    XMLElement* value = doc->NewElement(type_name);

    if (ins_ele) {
        ins_ele->InsertFirstChild(key);
        ins_ele->InsertAfterChild(key, value);
    }

    return value;
}

void plist_add_int(XMLDocument* doc, XMLElement* elem, const char* name, uint64_t value, uint32_t size)
{
    XMLElement* valueElem;
    char tmp_str[20];
    char tmp_format[20];
    // if (size == 64)
    //     sprintf(tmp_format, "0x%%%dllx", size / 4);
    // else if (size == 32)
    //     sprintf(tmp_format, "0x%%%dx", size / 4);
    sprintf(tmp_format, "0xllx");
    // printf("%s\n", tmp_format);

    sprintf(tmp_str, "0x%llx", value);
    // printf("%s\n", tmp_str);

    if ((valueElem = plist_get_item(elem, name))) {
        valueElem->SetText(tmp_str);
    } else {
        XMLElement* new_elem = new_plist_elem(doc, elem, "integer", name);
        new_elem->SetAttribute("size", 64);
        new_elem->SetText(tmp_str);
    }
}

char* make_prelink_info(KernelMacho& kernel, uint64_t& info_size)
{
    char* result = 0;
    XMLDocument* prelink_info_doc = new XMLDocument();
    XMLElement* root_dict = prelink_info_doc->NewElement("dict");

    prelink_info_doc->InsertFirstChild(root_dict);
    XMLElement* root_array = new_plist_elem(prelink_info_doc, root_dict, "array", "_PrelinkInfoDictionary");

    for (auto kext : kernel.kexts) {
        if (kext->exec_macho) {
            XMLNode* kext_element = kext->kextInfoElement->DeepClone(prelink_info_doc);
            plist_add_int(prelink_info_doc, kext_element->ToElement(),
                "_PrelinkExecutableLoadAddr", kernel.prelink_text_base + kext->text_off, 64);

            plist_add_int(prelink_info_doc, kext_element->ToElement(),
                "_PrelinkExecutableSize", kext->exec_macho->file_size, 64);

            plist_add_int(prelink_info_doc, kext_element->ToElement(),
                "_PrelinkExecutableSourceAddr", kernel.prelink_text_base + kext->text_off, 64);
            plist_add_int(prelink_info_doc, kext_element->ToElement(),
                "_PrelinkKmodInfo", kext->kmod_addr, 64);
            // printf("%p\n", kernel.prelink_text_base + kext->text_off);
            root_array->InsertEndChild(kext_element);
        }
    }

    XMLPrinter streamer;
    prelink_info_doc->Print(&streamer);

    // printf("%s", streamer.CStr());
    info_size = streamer.CStrSize();
    info_size = ALIGN_UP(info_size, 1 << 13);
    printf("Preinfo size: %x\n", info_size);
    result = (char*)malloc(info_size);
    const char* tmp = streamer.CStr();
    memcpy((void*)result, tmp, info_size);
    // printf("%s\n", (char *)result);
    return result;
}

void patch_kext_to_kernel(KernelMacho& y_kernel, KernelMacho& i_kerenl)
{
    if (y_kernel.is_newer_ver) {
        uint32_t prelink_text_size = get_prelink_text_size(y_kernel);
        uint32_t prelink_text_exec_size = get_prelink_segment_size(y_kernel, "__TEXT_EXEC");
        uint32_t prelink_data_size = get_prelink_segment_size(y_kernel, "__DATA");
        uint32_t prelink_data_const_size = get_prelink_segment_size(y_kernel, "__DATA_CONST");

        printf("pre text size: %x\n", prelink_text_size);
        printf("pre text exec size: %x\n", prelink_text_exec_size);
        printf("pre data size: %x\n", prelink_data_size);
        printf("pre data const size: %x\n", prelink_data_const_size);

        prelink_text_size = ALIGN_UP(prelink_text_size, 1 << 13);
        prelink_text_exec_size = ALIGN_UP(prelink_text_exec_size, 1 << 13);
        prelink_data_size = ALIGN_UP(prelink_data_size, 1 << 13);
        prelink_data_const_size = ALIGN_UP(prelink_data_const_size, 1 << 13);

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
                    kerenl_text_off += ALIGN_UP(text_seg->filesize, 1 << 5);
                } else {
                    if (kext->exec_macho->header->sizeofcmds) {
                        size = ALIGN_UP(kext->exec_macho->header->sizeofcmds, 1 << 5);
                        memcpy((char*)((uint64_t)prelink_text_buf + kerenl_text_off),
                            (char*)(uint64_t)kext->exec_macho->file_buf,
                            size);

                        kerenl_text_off += size;
                    }
                }
                kext->text_exec_off = kerenl_text_exec_off;
                copy_segment_from_kext(kext, i_kerenl, "__TEXT_EXEC", "__PLK_TEXT_EXEC", prelink_text_exec_buf, kerenl_text_exec_off);
                kext->data_off = kerenl_data_off;
                copy_segment_from_kext(kext, i_kerenl, "__DATA", "__PRELINK_DATA", prelink_data_buf, kerenl_data_off);
                kext->data_const_off = kerenl_data_const_off;
                copy_segment_from_kext(kext, i_kerenl, "__DATA_CONST", "__PLK_DATA_CONST", prelink_data_const_buf, kerenl_data_const_off);
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

        uint64_t kernel_text_vmbase = y_text_segment->vmaddr;
        new_prelink_data_const_base = kernel_text_vmbase - prelink_data_const_size;
        new_prelink_data_base = ALIGN_UP(y_linkedit_seg->vmaddr + y_linkedit_seg->vmsize, 1 << 13);
        new_prelink_text_exec_base = new_prelink_data_const_base - prelink_text_exec_size;
        new_prelink_text_base = new_prelink_text_exec_base - prelink_text_size;

        y_kernel.prelink_text_base = new_prelink_text_base;
        printf("Prelink text will at 0x%016llx\n", new_prelink_text_base);
        printf("Prelink data will at 0x%016llx\n", new_prelink_data_base);

        // 获取内核末尾
        uint64_t end_fileoff = y_linkedit_seg->fileoff + y_linkedit_seg->filesize;
        end_fileoff = ALIGN_UP(end_fileoff, 1 << 13);
        printf("End ad 0x%016llx\n", end_fileoff);
        uint64_t new_prelink_text_fileoff = end_fileoff;
        uint64_t new_prelink_text_exec_fileoff = new_prelink_text_fileoff + prelink_text_size;
        uint64_t new_prelink_data_const_fileoff = new_prelink_text_exec_fileoff + prelink_text_exec_size;
        printf("data const off: %p\n", new_prelink_data_const_fileoff);
        uint64_t new_prelink_data_fileoff = new_prelink_data_const_fileoff + prelink_data_const_size;

        // 修改Kext符号表
        for (auto kext : y_kernel.kexts) {
            // KMOD处理
            if (kext->exec_macho) {
                segment_command_64_t* kext_data_const_seg = (segment_command_64_t*)kext->exec_macho->find_segment("__DATA_CONST");
                segment_command_64_t* kext_text_exec_const_seg = (segment_command_64_t*)kext->exec_macho->find_segment("__TEXT_EXEC");
                segment_command_64_t* kext_data_seg = (segment_command_64_t*)kext->exec_macho->find_segment("__DATA");

                if (kext->is_from_file) {
                    if (kext->exec_macho->find_segment("__TEXT")) {
                        // printf(">>>>>>>>>>>>>>>>>%d\n", kext->exec_macho->symbol_name_map.find("_kmod_info") == kext->exec_macho->symbol_name_map.end());
                        if (kext->exec_macho->symbol_name_map["_kmod_info"]) {
                            kext->kmod_addr = kext->exec_macho->symbol_name_map["_kmod_info"]->symbol_addr - kext_data_seg->vmaddr;
                            kext->kmod_addr += new_prelink_data_base + kext->data_off;
                            printf("New kmod addr: %p\n", kext->kmod_addr);
                        }
                    } else {
                        kext->kmod_addr = 0;
                    }
                } else {
                    // segment_command_64_t* kext_data_seg = (segment_command_64_t*)kext->exec_macho->find_segment("__DATA");
                    kext->kmod_addr = kext->kmod_addr - kext_data_seg->vmaddr + new_prelink_data_base + kext->data_off;
                }

                if (kext->kmod_addr) {
                    kmod_info_64_v1_t* kext_kmod = (kmod_info_64_v1_t*)(kext->kmod_addr - new_prelink_data_base + (uint64_t)prelink_data_buf);
                    printf("K add: 0x%llx\n", kext_kmod->address);
                    printf("K n: %s\n", kext_kmod->name);
                    kext_kmod->address = new_prelink_text_base + kext->text_off;
                    segment_command_64_t* kext_text_exec_seg = (segment_command_64_t*)kext->exec_macho->find_segment("__TEXT_EXEC");
                    kext_kmod->start_addr -= kext_text_exec_seg->vmaddr;
                    kext_kmod->start_addr += new_prelink_text_exec_base;
                    kext_kmod->stop_addr -= kext_text_exec_seg->vmaddr;
                    kext_kmod->stop_addr += new_prelink_text_exec_base;
                }

                // 修复data const段的地址
                // 修复mod_init_func和mod_term_func
                section_64_t* init_sect = (section_64_t*)kext->exec_macho->find_section("__DATA_CONST", "__mod_init_func");
                section_64_t* term_sect = (section_64_t*)kext->exec_macho->find_section("__DATA_CONST", "__mod_term_func");

                if (kext_data_const_seg && init_sect && init_sect && kext_data_const_seg) {
                    uint64_t* mod_addr = (uint64_t*)((uint64_t)prelink_data_const_buf + kext->data_const_off + init_sect->addr - kext_data_const_seg->vmaddr);
                    for (size_t i = 0; i < init_sect->size / sizeof(uint64_t); i++) {
                        *mod_addr = *mod_addr - kext_text_exec_const_seg->vmaddr;
                        *mod_addr = *mod_addr + kext->text_exec_off + new_prelink_text_exec_base;
                        mod_addr++;
                    }

                    mod_addr = (uint64_t*)((uint64_t)prelink_data_const_buf + kext->data_const_off + term_sect->addr - kext_data_const_seg->vmaddr);
                    for (size_t i = 0; i < init_sect->size / sizeof(uint64_t); i++) {
                        *mod_addr = *mod_addr - kext_text_exec_const_seg->vmaddr;
                        *mod_addr = *mod_addr + kext->text_exec_off + new_prelink_text_exec_base;
                        mod_addr++;
                    }
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
                            } else if (!strncmp(seg->segname, "__TEXT_EXEC", 16)) {
                                patch_seg_vmbase((segment_command_64_t*)lcd, new_prelink_text_exec_base + kext->text_exec_off, seg->vmsize);

                                patch_seg_fileoff((segment_command_64_t*)lcd, (new_prelink_text_exec_fileoff + kext->text_exec_off) - (new_prelink_text_fileoff + kext->text_off), seg->filesize);
                                printf("%p -- %p\n", (kerenl_text_exec_off + kext->text_exec_off), (new_prelink_text_fileoff + kext->text_off));
                            } else if (!strncmp(seg->segname, "__DATA", 16)) {
                                patch_seg_vmbase((segment_command_64_t*)lcd, new_prelink_data_base + kext->data_off, seg->filesize);
                                patch_seg_fileoff((segment_command_64_t*)lcd, (new_prelink_data_fileoff + kext->data_off) - (new_prelink_text_fileoff + kext->text_off), seg->filesize);
                            } else if (!strncmp(seg->segname, "__DATA_CONST", 16)) {
                                patch_seg_vmbase((segment_command_64_t*)lcd, new_prelink_data_const_base + kext->data_const_off, seg->filesize);
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
    }
}

const char* kext_id_list[1000];

void format_info_ids(XMLElement* kextsNode)
{
    if (kextsNode->ChildElementCount() > 0) {
        XMLElement* tmpElement = kextsNode->FirstChildElement();
        while (tmpElement) {
            format_info_ids(tmpElement);
            tmpElement = tmpElement->NextSiblingElement();
        }
    } else {
        XMLElement* tmpElement = kextsNode;
        if (tmpElement->Attribute("ID")) {
            kext_id_list[tmpElement->IntAttribute("ID")] = tmpElement->GetText();
            tmpElement->DeleteAttribute("ID");
        } else if (tmpElement->Attribute("IDREF")) {
            int id = tmpElement->IntAttribute("IDREF");
            if (kext_id_list[id]) {
                tmpElement->SetText(kext_id_list[id]);
                tmpElement->DeleteAttribute("IDREF");
            } else {
                tmpElement->SetText("");
                tmpElement->DeleteAttribute("IDREF");
            }
        }
    }
}

void format_prelink_info(KernelMacho& kernel)
{
    segment_command_64_t* pre_info_seg = (segment_command_64_t*)kernel.find_segment("__PRELINK_INFO");
    if (pre_info_seg) {
        if (pre_info_seg->filesize > 0) {
            printf("Found prelink info\n");
            uint32_t prelink_info_size = pre_info_seg->filesize;
            char* prelink_info_buf = (char*)malloc(prelink_info_size);
            memcpy(prelink_info_buf, (void*)((uint64_t)kernel.file_buf + pre_info_seg->fileoff), prelink_info_size);

            printf("Prelink info size: %x\n", prelink_info_size);
            kernel.prlink_info_doc.Parse(prelink_info_buf);
            if (kernel.prlink_info_doc.ErrorID()) {
                printf("Error to parse prelink(%d)\n", kernel.prlink_info_doc.ErrorID());
            }
            free(prelink_info_buf);

            XMLElement* rootDict = kernel.prlink_info_doc.FirstChildElement("dict");
            if (strcmp(rootDict->FirstChildElement("key")->GetText(), "_PrelinkInfoDictionary")) {
                printf("Prelink info not have _PrelinkInfoDictionary\n");
                return;
            }

            XMLElement* rootArray = rootDict->FirstChildElement("array");
            XMLElement* kextNode = rootArray->FirstChildElement("dict");
            printf("iOS kernelcache has %d kexts\n", rootArray->ChildElementCount());

            const char* kext_id_list[1000];
            format_info_ids(rootArray);

            while (kextNode) {
                Kext* kext = new Kext();
                // printf("0x%016llx\n", plist_get_uint64(kextNode, "_PrelinkExecutableLoadAddr"));
                uint64_t kext_vmaddr = plist_get_uint64(kextNode, "_PrelinkExecutableLoadAddr");
                // 找到文件偏移量
                if (kext_vmaddr) {
                    segment_command_64_t* prelink_text = (segment_command_64_t*)kernel.find_segment("__PRELINK_TEXT");
                    uint64_t prelink_text_base = prelink_text->vmaddr;
                    uint64_t kext_fileoff = (uint64_t)kernel.file_buf + kext_vmaddr - prelink_text_base + prelink_text->fileoff;
                    // printf("off: 0x%016x\n", kext_vmaddr - prelink_text_base + prelink_text->fileoff);

                    KextMacho* kext_macho = new KextMacho((char*)kext_fileoff, 0);
                    kext_macho->format_macho();
                    kext->exec_macho = kext_macho;
                    kext->exec_macho->file_size = plist_get_uint64(kextNode, "_PrelinkExecutableSize");
                    kext->kmod_addr = plist_get_uint64(kextNode, "_PrelinkKmodInfo");
                }
                kext->kextInfoElement = kextNode;
                kext->kext_id = plist_get_string(kextNode, "CFBundleIdentifier");

                kernel.kexts.push_back(kext);

                kextNode = kextNode->NextSiblingElement();
            }
        }
    }
}

XMLElement* plist_get_item(XMLElement* elm, const char* keyName)
{
    if (!elm)
        return NULL;
    XMLElement* keyElem = elm->FirstChildElement("key");

    while (keyElem) {
        if (keyElem->GetText()) {
            if (!strcmp(keyElem->GetText(), keyName)) {
                if (keyElem->NextSiblingElement()) {
                    return keyElem->NextSiblingElement();
                }
            }
        }
        keyElem = keyElem->NextSiblingElement("key");
    }

    return NULL;
}

uint64_t plist_get_uint64(XMLElement* dictElem, const char* keyName)
{
    uint64_t result = 0;
    if (!dictElem)
        return 0;

    dictElem = plist_get_item(dictElem, keyName);
    if (!dictElem) {
        return 0;
    }

    if (!dictElem->GetText()) {
        return 0;
    }

    result = std::stoull(dictElem->GetText(), NULL, 16);

    return result;
}

const char* plist_get_string(XMLElement* dictElem, const char* keyName)
{
    const char* result = NULL;
    if (!dictElem)
        return NULL;

    dictElem = plist_get_item(dictElem, keyName);
    if (!dictElem) {
        return NULL;
    }

    result = dictElem->GetText();

    return result;
}

void init_kext_depends(KernelMacho& kernel, Kext* kext)
{
    XMLElement* depes_el = plist_get_item(kext->kextInfoElement, "OSBundleLibraries");
    if (!depes_el)
        return;
    XMLElement* depend_cld = depes_el->FirstChildElement("key");

    Kext* depend_kext;
    while (depend_cld) {
        depend_kext = kernel.find_kext(depend_cld->GetText());
        printf("....dep: %s, %p\n", depend_cld->GetText(), depend_kext);
        if (depend_kext == NULL) {
            printf("Not found kext depend %s\n", depend_cld->GetText());
            exit(1);
        }
        kext->depends.push_back(depend_kext);

        depend_cld = depend_cld->NextSiblingElement("key");
    }
}

Kext* load_kext_from_file(const char* path)
{
    char kext_dir[PATH_LENGTH];
    const char* kext_name;

    kext_name = strrchr(path, '/');
    kext_name++;

    sprintf(kext_dir, "%s.kext", path);

    char kext_exec_path[PATH_LENGTH];
    char kext_info_path[PATH_LENGTH];

    sprintf(kext_exec_path, "%s/%s", kext_dir, kext_name);
    sprintf(kext_info_path, "%s/Info.plist", kext_dir);

    if (access(kext_info_path, F_OK) || access(kext_exec_path, F_OK)) {
        return NULL;
    }

    // printf("Load KEXT %s\n", kext_name);
    Kext* kext = new Kext();
    // Kext *kext = (Kext *)malloc(sizeof(Kext));
    KextMacho* kext_file = new KextMacho(kext_exec_path);
    kext->is_from_file = true;
    kext->exec_macho = kext_file;
    kext_file->format_macho();

    std::ifstream kext_info_fd(kext_info_path, std::ios::binary);
    char* kext_info_buf = (char*)malloc(get_filesize(kext_info_fd));
    kext_info_fd.read(kext_info_buf, get_filesize(kext_info_fd));
    char* tmp_buf = kext_info_buf;

    // tinyxml2 无法解析xml doctype定义，跳过这部分
    while (*tmp_buf++) {
        if (!strncmp(tmp_buf, "<dict>", 6)) {
            break;
        }
    }
    if (kext->kextInfoDoc.Parse(tmp_buf)) {
        return NULL;
    }
    free(kext_info_buf);
    kext_info_fd.close();

    kext->kextInfoElement = kext->kextInfoDoc.FirstChildElement();
    if (!kext->kextInfoElement) {
        return NULL;
    }

    kext->kext_id = plist_get_string(kext->kextInfoElement, "CFBundleIdentifier");

    return kext;
}

uint32_t get_filesize(std::ifstream& fd)
{
    uint32_t filesize = 0;
    fd.seekg(0, std::ios::end);
    filesize = fd.tellg();

    fd.seekg(0, std::ios::beg);
    return filesize;
}

void useage()
{
    printf("kernelcache_patcher <your kernel> <iOS kernel> <symbol list> <your kexts path> <output filename>\n");
}