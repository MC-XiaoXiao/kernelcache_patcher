#include <assert.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <vector>

#include <KernelMacho.h>
#include <KextMacho.h>
#include <Macho.h>
#include <Patcher.h>
#include <Plist.h>

#define PATH_LENGTH 255

void format_prelink_info(KernelMacho& kernel);
Kext* load_kext_from_file(const char* path);
uint32_t get_filesize(std::ifstream& fd);
void init_kext_depends(KernelMacho& kernel, Kext* kext);
void useage();

int main(int argc, char** argv)
{
    char your_kernel_path[PATH_LENGTH];
    char ios_kernel_path[PATH_LENGTH];
    char symbol_list_path[PATH_LENGTH];
    char kexts_path[PATH_LENGTH];
    char output_path[PATH_LENGTH];
    char kexts_list_path[PATH_LENGTH];
    char ikernel_patch_list_path[PATH_LENGTH] = { 0 };

    if (argc < 6) {
        useage();
        exit(0);
    }

    strcpy(your_kernel_path, argv[1]);
    strcpy(ios_kernel_path, argv[2]);
    strcpy(symbol_list_path, argv[3]);
    strcpy(kexts_path, argv[4]);
    strcpy(output_path, argv[5]);
    strcpy(ikernel_patch_list_path, argv[6]);

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
    if (ikernel_patch_list_path[0])
        assert(patch_ios_kernel(i_kernel, ikernel_patch_list_path) == 0);

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

    char tmp_symbol[255];
    while (symbol_list_fs.getline(tmp_symbol, 255)) {
        if (kext_path[0] == '#' || kext_path[0] == ' ')
            continue;
        uint64_t addr = 0;
        char* symbol_name = (char*)malloc(100);
        // printf("%s\n", tmp_symbol);
        sscanf(tmp_symbol, "%lx,%s", &addr, symbol_name);
        Symbol* symbol = new Symbol();
        symbol->symbol_addr = addr;
        symbol->symbol_name = symbol_name;
        // i_kernel.symbol_addr_map[addr] = symbol;
        // i_kernel.symbol_list.push_back(symbol);
        // i_kernel.symbol_name_map[symbol_name] = symbol;

        for (auto kext : y_kernel.kexts) {
            if (!kext->is_from_file) {
                segment_command_64_t* kext_text_seg = (segment_command_64_t*)kext->exec_macho->find_segment("__TEXT");
                segment_command_64_t* kext_text_const_seg = (segment_command_64_t*)kext->exec_macho->find_segment("__TEXT_EXEC");
                segment_command_64_t* kext_data_seg = (segment_command_64_t*)kext->exec_macho->find_segment("__DATA");
                segment_command_64_t* kext_data_const_seg = (segment_command_64_t*)kext->exec_macho->find_segment("__DATA_CONST");
                if (kext_text_seg) {
                    if ((IN_SEGMENT_RANGE(addr, kext_text_seg))
                        || (IN_SEGMENT_RANGE(addr, kext_text_const_seg))
                        || (IN_SEGMENT_RANGE(addr, kext_data_seg))
                        || (IN_SEGMENT_RANGE(addr, kext_data_const_seg))) {
                        kext->exec_macho->symbol_addr_map[addr] = symbol;
                        kext->exec_macho->symbol_list.push_back(symbol);
                        kext->exec_macho->symbol_name_map[symbol_name] = symbol;
                        break;
                    }
                }
            }
        }
    }

    patch_kext_to_kernel(y_kernel, i_kernel);

    std::ofstream output_file_fs(output_path, std::ios::binary);
    output_file_fs.write(y_kernel.file_buf, y_kernel.file_size);
    output_file_fs.close();

    printf("Finish!\n");

    return 0;
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
    segment_command_64_t* prelink_text = (segment_command_64_t*)kernel.find_segment("__PRELINK_TEXT");
    segment_command_64_t* kenrel_exec_seg = (segment_command_64_t*)kernel.find_segment("__TEXT_EXEC");
    section_64_t* pre_info_sect = (section_64_t*)kernel.find_section("__PRELINK_INFO", "__info");
    section_64_t* pre_info_kmod_infos = (section_64_t*)kernel.find_section("__PRELINK_INFO", "__kmod_info");
    section_64_t* pre_info_kmod_starts = (section_64_t*)kernel.find_section("__PRELINK_INFO", "__kmod_start");

    if (pre_info_seg && pre_info_sect) {
        if (pre_info_seg->filesize > 0 && pre_info_sect->size > 0) {
            printf("Found prelink info\n");
            uint32_t prelink_info_size = pre_info_sect->size;
            char* prelink_info_buf = (char*)malloc(prelink_info_size);
            memcpy(prelink_info_buf, (void*)((uint64_t)kernel.file_buf + pre_info_sect->offset), prelink_info_size);

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

                    uint64_t prelink_text_base = prelink_text->vmaddr;
                    uint64_t kext_fileoff = (uint64_t)kernel.file_buf + kext_vmaddr - prelink_text_base + prelink_text->fileoff;
                    // printf("off: 0x%016x\n", kext_vmaddr - prelink_text_base + prelink_text->fileoff);

                    KextMacho* kext_macho = new KextMacho((char*)kext_fileoff, 0);
                    kext_macho->format_macho();
                    kext->exec_macho = kext_macho;
                    kext->exec_macho->file_size = plist_get_uint64(kextNode, "_PrelinkExecutableSize");
                    kext->kmod_addr = plist_get_uint64(kextNode, "_PrelinkKmodInfo");
                } else if (plist_has_item(kextNode, "ModuleIndex")) {
                    kext_vmaddr = plist_get_uint64(kextNode, "ModuleIndex");
                    uint64_t kext_start = ((uintptr_t*)((uint64_t)kernel.file_buf + pre_info_kmod_starts->addr - pre_info_seg->vmaddr + pre_info_seg->fileoff))[kext_vmaddr];
                    uint64_t kext_end = ((uintptr_t*)((uint64_t)kernel.file_buf + pre_info_kmod_starts->addr - pre_info_seg->vmaddr + pre_info_seg->fileoff))[kext_vmaddr + 1];

                    if (!(kext_start & 0xFF00000000000000)) {
                        kext_start |= 0xFFFF000000000000;
                        kext_end |= 0xFFFF000000000000;
                    }

                    uint64_t kext_fileoff = (uint64_t)kernel.file_buf + kext_start - kenrel_exec_seg->vmaddr + kenrel_exec_seg->fileoff;
                    KextMacho* kext_macho = new KextMacho((char*)kext_fileoff, 0);
                    kext_macho->format_macho();
                    kext->exec_macho = kext_macho;
                    kext->exec_macho->file_size = kext_start - kext_end;
                    kext->kmod_addr = ((uintptr_t*)((uint64_t)kernel.file_buf + pre_info_kmod_infos->addr - pre_info_seg->vmaddr + pre_info_seg->fileoff))[kext_vmaddr];
                    uint64_t kmod_end = ((uintptr_t*)((uint64_t)kernel.file_buf + pre_info_kmod_infos->addr - pre_info_seg->vmaddr + pre_info_seg->fileoff))[kext_vmaddr + 1];
                    if (!(kext->kmod_addr & 0xFF00000000000000)) {
                        kext->kmod_addr |= 0xFFFF000000000000;
                        kmod_end |= 0xFFFF000000000000;
                    }
                    kext->data_size = kmod_end - kext->kmod_addr;
                }
                kext->kextInfoElement = kextNode;
                kext->kext_id = plist_get_string(kextNode, "CFBundleIdentifier");

                kernel.kexts.push_back(kext);

                kextNode = kextNode->NextSiblingElement();
            }
        }
    }
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

    if (access(kext_info_path, F_OK)) {
        return NULL;
    }

    // printf("Load KEXT %s\n", kext_name);
    Kext* kext = new Kext();
    kext->exec_macho = NULL;
    // Kext *kext = (Kext *)malloc(sizeof(Kext));
    if (!access(kext_exec_path, F_OK)) {
        KextMacho* kext_file = new KextMacho(kext_exec_path);
        kext->is_from_file = true;
        kext->exec_macho = kext_file;
        kext_file->format_macho();
    }

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
    printf("kernelcache_patcher <your kernel> <iOS kernel> <symbol list> <your kexts path> <output filename> [iOS kernel patch list]\n");
}