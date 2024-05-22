#include <KernelMacho.h>

Kext *KernelMacho::find_kext(const char *id)
{
    for(auto kext : kexts) {
        if(!strcmp(kext->kext_id, id)) {
            return kext;
        }
    }
    return NULL;
}

void KernelMacho::format_macho()
{
    Macho::format_macho();


    if (find_segment("__PRELINK_DATA")) {
        is_newer_ver = true;
        printf("Kernel has __PRELINK_DATA!\n");
    }
}

KernelMacho::~KernelMacho()
{
    
}