#pragma once

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
    KextMacho *exec_file;
    const char *kext_id;
    char *exec_buf;
    bool from_file;

    Kext(/* args */);
    ~Kext();
};
