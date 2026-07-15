
#include <Plist.h>
#include <cinttypes>

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
    snprintf(tmp_str, sizeof(tmp_str), "0x%" PRIx64, value);

    if ((valueElem = plist_get_item(elem, name))) {
        valueElem->SetText(tmp_str);
    } else {
        XMLElement* new_elem = new_plist_elem(doc, elem, "integer", name);
        new_elem->SetAttribute("size", size);
        new_elem->SetText(tmp_str);
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

bool plist_has_item(XMLElement* dictElem, const char* keyName)
{
    if (!dictElem)
        return 0;

    dictElem = plist_get_item(dictElem, keyName);
    if (!dictElem) {
        return 0;
    }

    return 1;
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
    const size_t xml_size = streamer.CStrSize();
    info_size = xml_size;
    info_size = ALIGN_UP(info_size, 1 << 12);
    printf("Preinfo size: 0x%" PRIx64 "\n", info_size);
    result = (char*)calloc(info_size, 1);
    const char* tmp = streamer.CStr();
    memcpy((void*)result, tmp, xml_size);
    delete prelink_info_doc;
    // printf("%s\n", (char *)result);
    return result;
}
