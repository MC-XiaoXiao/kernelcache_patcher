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

using namespace tinyxml2;

void format_prelink_info(KernelMacho& kernel);
Kext* load_kext_from_file(const char* path);
uint32_t get_filesize(std::ifstream& fd);
const char* getValueFromDict(XMLElement* dictElem, const char* keyName);
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
    i_kernel.format_macho();
    format_prelink_info(i_kernel);

    std::ifstream symbol_list_fs(symbol_list_path);

    if (!symbol_list_fs.is_open()) {
        printf("Cannot open iOS kernel symbol list file!\n");
        exit(1);
    }

    std::vector<const char*> kext_paths;
    char kext_path[PATH_LENGTH];
    while (kexts_list_fs.getline(kext_path, PATH_LENGTH)) {
        if (kext_path[0] == '#')
            continue;
        char* tmp_kext_path = (char*)malloc(strlen(kext_path));
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
            printf("ID: %s\n", kext->kext_id);
            // y_kernel.kexts[kext_ID] = kext;
            y_kernel.kexts.push_back(kext);
        } else if ((kext = i_kernel.find_kext(kext_paths[i])) != NULL) {
            // Kext 在Kernelcache中

            printf("ID: %s\n", kext->kext_id);
            y_kernel.kexts.push_back(kext);
        } else {
            printf("Not found kext %s\n", kext_paths[i]);
            exit(1);
        }
    }

    for (auto kext : y_kernel.kexts) {
        init_kext_depends(y_kernel, kext);
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

            XMLElement* rootDict = kernel.prlink_info_doc.FirstChildElement("dict");
            if (strcmp(rootDict->FirstChildElement("key")->GetText(), "_PrelinkInfoDictionary")) {
                printf("Prelink info not have _PrelinkInfoDictionary\n");
                return;
            }

            XMLElement* rootArray = rootDict->FirstChildElement("array");
            XMLElement* kextNode = rootArray->FirstChildElement("dict");
            printf("iOS kernelcache has %d kexts\n", rootArray->ChildElementCount());

            const char* kext_id_list[1000];

            while (kextNode) {
                XMLElement* tmpElement = kextNode->FirstChildElement("key");
                while (tmpElement) {
                    tmpElement = tmpElement->NextSiblingElement();
                    if (tmpElement->Attribute("ID")) {
                        kext_id_list[tmpElement->IntAttribute("ID")] = tmpElement->GetText();
                    } else if (tmpElement->Attribute("IDREF")) {
                        int id = tmpElement->IntAttribute("IDREF");
                        if (kext_id_list[id]) {
                            tmpElement->SetText(kext_id_list[id]);
                        }
                    }

                    tmpElement = tmpElement->NextSiblingElement("key");
                }

                Kext* kext = new Kext();
                kext->kext_id = getValueFromDict(kextNode, "CFBundleIdentifier");
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

const char* getValueFromDict(XMLElement* dictElem, const char* keyName)
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
        printf("dep: %s, %p\n", depend_cld->GetText(), depend_kext);

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

    printf("Load KEXT %s\n", kext_name);
    Kext* kext = new Kext();
    KextMacho* kext_file = new KextMacho(kext_exec_path);
    kext->from_file = true;
    kext->exec_file = kext_file;

    std::ifstream kext_info_fd(kext_info_path, std::ios::binary);
    char* kext_info_buf = (char*)malloc(get_filesize(kext_info_fd));
    kext_info_fd.read(kext_info_buf, get_filesize(kext_info_fd));

    // tinyxml2 无法解析xml doctype定义，跳过这部分
    while (*kext_info_buf++) {
        if (!strncmp(kext_info_buf, "<dict>", 6)) {
            break;
        }
    }
    if (kext->kextInfoDoc.Parse(kext_info_buf)) {
        return NULL;
    }
    kext->kextInfoElement = kext->kextInfoDoc.FirstChildElement();
    if (!kext->kextInfoElement) {
        return NULL;
    }

    kext->kext_id = getValueFromDict(kext->kextInfoElement, "CFBundleIdentifier");

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