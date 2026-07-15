#include <CppAnalyzer.h>

#include <cstring>
#include <iostream>
#include <vector>

namespace {

struct TestImage {
    std::vector<char> bytes;
    Macho macho;

    TestImage()
        : bytes(0x2000, 0)
        , macho(bytes.data(), static_cast<uint32_t>(bytes.size()))
    {
        auto* header = reinterpret_cast<mach_header_64_t*>(bytes.data());
        header->magic = MH_MAGIC_64;
        header->ncmds = 1;
        header->sizeofcmds = sizeof(segment_command_64_t);

        auto* text = reinterpret_cast<segment_command_64_t*>(header + 1);
        text->cmd = LC_SEGMENT_64;
        text->cmdsize = sizeof(*text);
        memcpy(text->segname, "__TEXT_EXEC", 11);
        text->vmaddr = 0x1000;
        text->vmsize = 0x1000;
        text->fileoff = 0x1000;
        text->filesize = 0x1000;
        text->initprot = 5;

        macho.format_macho();
    }

    void write(uint64_t address, uint32_t instruction)
    {
        memcpy(bytes.data() + address, &instruction, sizeof(instruction));
    }
};

} // namespace

#define CHECK(condition) do { \
    if (!(condition)) { \
        std::cerr << "CHECK failed at line " << __LINE__ << ": " #condition << '\n'; \
        return 1; \
    } \
} while (false)

int main()
{
    TestImage image;
    constexpr uint64_t constructor = 0x1100;
    image.write(constructor, 0xd503201fU);      // nop
    image.write(constructor + 4, 0xd65f03c0U);  // ret
    image.write(constructor + 8, 0x14000000U);  // b . (D2 tail thunk)
    image.write(constructor + 12, 0xd4200020U); // brk #1 (D1)
    image.write(constructor + 16, 0xd4200040U); // brk #2 (D0)

    uint64_t d2 = 0, d1 = 0, d0 = 0;
    CHECK(cpp_analyzer_detail::find_abstract_structor_layout(
        image.macho, constructor, d2, d1, d0));
    CHECK(d2 == constructor + 8);
    CHECK(d1 == constructor + 12);
    CHECK(d0 == constructor + 16);

    image.write(constructor + 16, 0xd503201fU);
    CHECK(!cpp_analyzer_detail::find_abstract_structor_layout(
        image.macho, constructor, d2, d1, d0));
    CHECK(d2 == 0 && d1 == 0 && d0 == 0);
    return 0;
}
