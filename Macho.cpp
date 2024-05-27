#include <Macho.h>

#include <cstring>
#include <iostream>

void Macho::init_symbols()
{
    struct symtab_command* k_symtab = (struct symtab_command*)find_command(LC_SYMTAB);
    if (!k_symtab) {
        return;
    }

    struct nlist_64* sym_list = (struct nlist_64*)((uint64_t)this->file_buf + k_symtab->symoff);
    symbol_count = k_symtab->nsyms;
    void* symstr = (void*)((uint64_t)file_buf + k_symtab->stroff);
    printf("Mach-o has %d symbols\n", symbol_count);

    for (int i = 0; i < symbol_count; i++) {
        Symbol* sym = new Symbol();
        sym->symbol_addr = sym_list[i].n_value;
        sym->symbol_name = (const char*)((uint64_t)symstr + sym_list[i].n_un.n_strx);

        if (sym->symbol_addr) {
            symbol_addr_map[sym->symbol_addr] = sym;
        }
        if (sym->symbol_name) {
            symbol_name_map[sym->symbol_name] = sym;
        }
        symbol_list.push_back(sym);
    }
}

void Macho::format_macho()
{
    // printf("Formating %s\n", file_path);

    header = (mach_header_64_t*)file_buf;

    if (header->magic == MH_MAGIC_64) {
        is_64 = true;
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

load_command* Macho::find_command(uint32_t cmd)
{
    load_command* lcd = NULL;
    if (is_64) {
        lcd = (load_command*)(header + 1);
    } else {
        lcd = (load_command*)((mach_header_t*)header + 1);
    }

    for (int i = 0; i < header->ncmds; i++) {
        if (lcd->cmd == cmd) {
            return lcd;
        }

        lcd = (load_command*)((uint64_t)lcd + lcd->cmdsize);
    }

    return NULL;
}

void* Macho::find_section(const char* segname, const char* section_name)
{
    segment_command_64_t* seg = (segment_command_64_t*)find_segment(segname);
    if (seg) {
        section_64_t* sect = (section_64_t*)((uint64_t)seg + sizeof(segment_command_64_t));
        for (int i = 0; i < seg->nsects; i++) {
            if(!strncmp(sect->sectname, section_name, 16)) {
                return sect;
            }
            sect = (section_64_t*)(sect + 1);
        }
    }

    return NULL;
}

void* Macho::find_segment(const char* segment_name)
{
    load_command* lcd = NULL;
    if (is_64) {
        lcd = (load_command*)(header + 1);
    } else {
        lcd = (load_command*)((mach_header_t*)header + 1);
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

Macho::Macho(char* buf, uint32_t file_size)
    : file_buf(buf)
    , file_size(file_size)
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
        filefs.close();
    }
}

Macho::~Macho()
{
    filefs.close();
}