#pragma once

#include <vector>

#include <tinyxml2.h>

#include <KextMacho.h>

using namespace tinyxml2;

class Kext
{
private:
    /* data */
public:
    XMLDocument kextInfoDoc;
    XMLElement *kextInfoElement;
    KextMacho *exec_macho;
    std::vector<Kext *> depends;
    const char *kext_id;
    bool from_file;

    uint64_t text_off;
    uint64_t text_exec_off;
    uint64_t data_off;
    uint64_t data_const_off;

    Kext(/* args */);
    ~Kext();
};
