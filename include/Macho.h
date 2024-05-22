#pragma once

#include <fstream>
#include <cstdint>

typedef struct mach_header {
	uint32_t	magic;		/* mach magic number identifier */
	uint32_t	cputype;	/* cpu specifier */
	uint32_t	cpusubtype;	/* machine specifier */
	uint32_t	filetype;	/* type of file */
	uint32_t	ncmds;		/* number of load commands */
	uint32_t	sizeofcmds;	/* the size of all the load commands */
	uint32_t	flags;		/* flags */
}mach_header_t;

#define	MH_MAGIC	0xfeedface	/* the mach magic number */

typedef struct mach_header_64
{
    uint32_t magic;           /* mach magic number identifier */
    uint32_t cputype;         /* cpu specifier */
    uint32_t cpusubtype;      /* machine specifier */
    uint32_t filetype;        /* type of file */
    uint32_t ncmds;           /* number of load commands */
    uint32_t sizeofcmds;      /* the size of all the load commands */
    uint32_t flags;           /* flags */
    uint32_t reserved;        /* reserved */
} mach_header_64_t;

#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */

struct load_command {
	uint32_t cmd;		/* type of load command */
	uint32_t cmdsize;	/* total size of command in bytes */
};

#define	LC_SEGMENT	0x1	/* segment of this file to be mapped */
#define	LC_SYMTAB	0x2	/* link-edit stab symbol table info */
#define	LC_THREAD	0x4	/* thread */
#define	LC_UNIXTHREAD	0x5	/* unix thread (includes a stack) */
#define	LC_DYSYMTAB	0xb	/* dynamic link-edit symbol table info */
#define LC_SEGMENT_64   0x19    /* 64-bit segment of this file to be mapped */

typedef struct segment_command { /* for 32-bit architectures */
	uint32_t	cmd;		/* LC_SEGMENT */
	uint32_t	cmdsize;	/* includes sizeof section structs */
	char		segname[16];	/* segment name */
	uint32_t	vmaddr;		/* memory address of this segment */
	uint32_t	vmsize;		/* memory size of this segment */
	uint32_t	fileoff;	/* file offset of this segment */
	uint32_t	filesize;	/* amount to map from the file */
	int     	maxprot;	/* maximum VM protection */
	int     	initprot;	/* initial VM protection */
	uint32_t	nsects;		/* number of sections in segment */
	uint32_t	flags;		/* flags */
} segment_command_t;

typedef struct segment_command_64 { /* for 64-bit architectures */
	uint32_t	cmd;		/* LC_SEGMENT_64 */
	uint32_t	cmdsize;	/* includes sizeof section_64 structs */
	char		segname[16];	/* segment name */
	uint64_t	vmaddr;		/* memory address of this segment */
	uint64_t	vmsize;		/* memory size of this segment */
	uint64_t	fileoff;	/* file offset of this segment */
	uint64_t	filesize;	/* amount to map from the file */
	int     	maxprot;	/* maximum VM protection */
	int     	initprot;	/* initial VM protection */
	uint32_t	nsects;		/* number of sections in segment */
	uint32_t	flags;		/* flags */
} segment_command_64_t;

class Macho
{
private:
    std::ifstream filefs;
    char file_path[255];
    uint32_t get_file_size();

public:
    char *file_buf;
    uint32_t file_size;
    mach_header_64_t *header;
    bool is_64 = false;
    bool is_newer_ver = false;

    virtual void format_macho();
    void copy_from_file(uint64_t offset, char *targetBuff, size_t size);
    void *find_segment(const char *segment_name);

	Macho();
    Macho(const char *path);
    ~Macho();
};
