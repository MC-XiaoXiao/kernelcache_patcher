#include <Macho.h>

#include <cstring>
#include <iostream>

void Macho::format_macho()
{
    printf("Formating %s\n", file_path);

    header = (mach_header_64_t*)file_buf;

    if (header->magic == MH_MAGIC_64) {
        is_64 = true;
#if DEBUG
        printf("Macho: 64bit Kernel!\n");
#endif
    } else if (header->magic == MH_MAGIC) {
        is_64 = false;
    } else {
        printf("Macho: Unknown magic 0x%08x!\n", header->magic);
        return;
    }
}

void Macho::copy_from_file(uint64_t offset, char* targetBuff, size_t size)
{
    if (targetBuff || size) {
        if (filefs.is_open()) {
            filefs.seekg(offset, std::ios::beg);
            filefs.read(targetBuff, size);
        }
    }
}

uint32_t Macho::get_file_size()
{
    uint32_t result = 0;
    if (filefs.is_open()) {
        filefs.seekg(0, std::ios::end);
        result = filefs.tellg();
        filefs.seekg(0, std::ios::beg);
    }

    return result;
}

void* Macho::find_segment(const char* segment_name)
{
    load_command* lcd = NULL;
    if(is_64) {
        lcd = (load_command *)(header + 1);
    } else {
        lcd = (load_command *)((mach_header_t *)header + 1);
    }
    for (int i = 0; i < header->ncmds; i++) {
        if (is_64) {
            if (lcd->cmd == LC_SEGMENT_64) {
                segment_command_64_t* seg_cmd = (segment_command_64_t*)lcd;
                if (!strncmp(seg_cmd->segname, segment_name, 16)) {
                    return seg_cmd;
                }
            }
        } else {
            if (lcd->cmd == LC_SEGMENT) {
                segment_command_t* seg_cmd = (segment_command_t*)lcd;
                if (!strncmp(seg_cmd->segname, segment_name, 16)) {
                    return seg_cmd;
                }
            }
        }

        lcd = (load_command*)((uint64_t)lcd + lcd->cmdsize);
    }

    return NULL;
}

Macho::Macho()
{

}

Macho::Macho(const char* path)
{
    if (path) {
        filefs.open(path, std::ios::binary | std::ios::in);
        if (!filefs.is_open()) {
            printf("Macho file %s was not open!\n", path);
            return;
        }

        strcpy(file_path, path);

        file_size = get_file_size();
        file_buf = (char*)malloc(file_size);
        filefs.read(file_buf, file_size);
    }
}

Macho::~Macho()
{
    filefs.close();
}