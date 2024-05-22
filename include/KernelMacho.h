#pragma once

#include <map>
#include <vector>
#include <string>

#include <Macho.h>
#include <Kext.h>

class KernelMacho : public Macho
{
private:
    /* data */
public:
    std::vector<Kext *> kexts;
    XMLDocument prlink_info_doc;

    virtual void format_macho() override;

    Kext *find_kext(const char *id);

    using Macho::Macho;
    ~KernelMacho();
};

