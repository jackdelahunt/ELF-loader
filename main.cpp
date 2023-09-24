#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>

#define E_IDENT_SIZE 16

#define BIT_SET(n, flag) \
    (flag) == ((n) & (flag))

enum ELFIdentifier {
    EI_MAG_0,
    EI_MAG_1,
    EI_MAG_2,
    EI_MAG_3,
    EI_CLASS,
    EI_DATA,
    EI_VERSION,
    EI_OSABI,
    EI_ABIVERSION,
    EI_PAD
};

enum ELFType {
    ET_NONE,
    ET_REL,
    ET_EXEC,
    ET_DYN,
    ET_CORE,
    ET_LOOS = 0xfe00,
    ET_HIOS = 0xfeff,
    ET_LOPROC = 0xff00,
    ET_HIPROC = 0xffff
};

enum ELFProgramHeaderType {
    PT_NULL,                    // Program header table entry unused
    PT_LOAD,                    // Loadable segment
    PT_DYNAMIC,                 // Dynamic linking information
    PT_INTERP,                  // Interpreter information
    PT_NOTE,                    // Auxiliary information
    PT_SHLIB,                   // Reserved
    PT_PHDR,                    // Segment containing program header table itself
    PT_TLS,                     // Thread-Local Storage template
    PT_LOOS = 0x60000000,       // Operating system specific
    PT_HIOS = 0x6FFFFFFF,       // Operating system specific
    PT_LOPROC = 0x70000000,     // Operating system specific
    PT_HIPROC = 0x7FFFFFFF      // Operating system specific
};

enum ELFProgramFlags {
    PF_X = 0x1,
    PF_W = 0x2,
    PF_R = 0x4
};

struct ELFProgramHeader {
    uint32_t p_type;    // Identifies the type of the segment
    uint32_t p_flags;  // Segment-dependent flags
    uint64_t p_offset;  // Offset of the segment in the file image
    uint64_t p_vaddr;   // Virtual address of the segment in memory
    uint64_t p_paddr;   // Reserved for segment's physical address, if needed
    uint64_t filez;     // Size in bytes of the segment in the file image maybe 0
    uint64_t memsz;     // Size in bytes of the segment in memory maybe 0
    uint64_t align;     // 0 and 1 specify no alignment. Otherwise should be a positive, integral power of 2, with p_vaddr equating p_offset modulus p_align

    void print_header() {
        printf("Program Header\n");
        this->print_type();
        this->print_flags();
        this->print_offset();
        this->print_virtual_address();
        this->print_physical_address();
        this->print_filez();
        this->print_memsz();
        this->print_allignment();
    }

    void print_type() {
        const char *type = nullptr;

        switch (this->p_type) {
            case PT_NULL:
                type = "NULL";
                break;
            case PT_LOAD:
                type = "LOAD";
                break;
            case PT_DYNAMIC:
                type = "DYNAMIC";
                break;
            case PT_INTERP:
                type = "INTERP";
                break;
            case PT_NOTE:
                type = "NOTE";
                break;
            case PT_SHLIB:
                type = "SHLIB";
                break;
            case PT_PHDR:
                type = "PHDR";
                break;
            case PT_TLS:
                type = "TLS";
                break;
            default:
                if (this->p_type >= PT_LOOS && this->p_type <= PT_HIOS) {
                    type = "LOOS - HIOS";
                } else {
                    type = "LOPROC - HIPROC";
                }
        }

        printf("  %-35s %s\n", "Type:", type);
    }

    void print_flags() {

        char read = '-';
        char write = '-';
        char execute = '-';

        if (BIT_SET(this->p_flags, PF_R)) {
            read = 'r';
        }

        if (BIT_SET(this->p_flags, PF_W)) {
            write = 'w';
        }

        if (BIT_SET(this->p_flags, PF_X)) {
            execute = 'x';
        }

        printf("  %-35s %c%c%c\n", "FLags:", read, write, execute);
    }

    void print_offset() {
        printf("  %-35s 0x%llx\n", "Offset:", this->p_offset);
    }

    void print_virtual_address() {
        printf("  %-35s 0x%llx\n", "Virtual Address:", this->p_vaddr);
    }

    void print_physical_address() {
        printf("  %-35s 0x%llx\n", "Physical Address:", this->p_paddr);
    }

    void print_filez() {
        printf("  %-35s 0x%llx\n", "Filez:", this->filez);
    }

    void print_memsz() {
        printf("  %-35s 0x%llx\n", "Memsz:", this->memsz);
    }

    void print_allignment() {
        // pow(2, X) = align
        int power = (int) (log(this->align) / log(2.0));
        printf("  %-35s 2**%d\n", "Alignment:", power);
    }
};

struct ELFHeader {
    uint8_t e_ident[E_IDENT_SIZE]; // magic
    uint16_t e_type;               // type of elf file
    uint16_t e_machine;            // machine type
    uint32_t e_version;            // always 1
    uint64_t e_entry;              // address of entry point
    uint64_t e_phoff;              // offset from file start of program headers
    uint64_t e_shoff;              // offset from file start of section headers
    uint32_t e_flags;              // flags
    uint16_t e_ehsize;             // 52(32 bit), 64(64 bit)
    uint16_t e_phentsize;          // size of program header
    uint16_t e_phnum;              // number of program headers
    uint16_t e_shentsize;          // size of section header
    uint16_t e_shnum;              // number of section headers
    uint16_t e_shstrndx;           // section index for names
};

// Each ELF file is made up of one ELF header, followed by file data. The data can include:
// 1. Program header table:  describing zero or more memory segments
// 2. Section header table:  describing zero or more sections
// 2. Data: referred to by entries in the program header table or section header table
struct ELF {
    uint8_t *buffer;
    uint64_t size;

    static ELF make(uint8_t *buffer, uint64_t size) {
        return ELF{.buffer = buffer, .size = size};
    }

    ELFHeader *header() {
        return (ELFHeader *) this->buffer;
    }

    ELFProgramHeader *get_program_header(uint32_t index) {
        return (ELFProgramHeader *) ((this->buffer + this->header()->e_phoff) + (this->header()->e_phentsize * index));
    }

    bool is_64_bit() {
        return this->header()->e_ident[EI_CLASS] == 2;
    }

    bool is_big_endian() {
        return this->header()->e_ident[EI_DATA] == 2;
    }

    bool verify_magic() {
        // 52 is the minimum size of the elf header in 32 bit
        // in 64 bit the size is 64 bytes
        if (this->size < 52) return false;

        if (this->header()->e_ident[EI_MAG_0] != 0x7f) {
            return false;
        }

        if (this->header()->e_ident[EI_MAG_1] != 0x45) {
            return false;
        }

        if (this->header()->e_ident[EI_MAG_2] != 0x4c) {
            return false;
        }

        if (this->header()->e_ident[EI_MAG_3] != 0x46) {
            return false;
        }

        return true;
    }

    void print_header() {
        printf("ELF Header\n");
        this->print_magic();
        this->print_class();
        this->print_data();
        this->print_version_1();
        this->print_os();
        this->print_abi_version();
        this->print_type();
        this->print_machine();
        this->print_version_2();
        this->print_entry_point();
        this->print_start_of_program_headers();
        this->print_start_of_section_headers();
        this->print_flags();
        this->print_size_of_this_header();
        this->print_size_of_program_headers();
        this->print_number_of_program_headers();
        this->print_size_of_section_headers();
        this->print_number_of_section_headers();
        this->print_string_table_index();
    }

    void print_magic() {
        printf("  Magic:    %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",
               this->header()->e_ident[EI_MAG_0],
               this->header()->e_ident[EI_MAG_1],
               this->header()->e_ident[EI_MAG_2],
               this->header()->e_ident[EI_MAG_3],
               this->header()->e_ident[EI_CLASS],
               this->header()->e_ident[EI_DATA],
               this->header()->e_ident[EI_VERSION],
               this->header()->e_ident[EI_OSABI],
               this->header()->e_ident[EI_ABIVERSION],
               this->header()->e_ident[EI_PAD],
               this->header()->e_ident[EI_PAD + 1],
               this->header()->e_ident[EI_PAD + 2],
               this->header()->e_ident[EI_PAD + 3],
               this->header()->e_ident[EI_PAD + 4],
               this->header()->e_ident[EI_PAD + 5],
               this->header()->e_ident[EI_PAD + 6]
        );
    }

    void print_class() {
        if (this->is_64_bit()) {
            printf("  %-35s ELF64\n", "Class:");
        } else {
            printf("  %-35s ELF32\n", "Class:");
        }
    }

    void print_data() {
        if (this->is_big_endian()) {
            printf("  %-35s big endian\n", "Data:");
        } else {
            printf("  %-35s little endian\n", "Data:");
        }
    }

    void print_version_1() {
        printf("  %-35s %d\n", "Version:", this->header()->e_ident[EI_VERSION]);
    }

    void print_os() {
        const char *operating_systems[19] = {
                "UNIX - System V",
                "HP-UX",
                "NetBSD",
                "Linux",
                "GNU Hurd",
                "Solaris",
                "AIX (Monterey)",
                "IRIX",
                "FreeBSD",
                "Tru64",
                "Novell Modesto",
                "OpenBSD",
                "OpenVMS",
                "NonStop Kernel",
                "AROS",
                "FenixOS",
                "Nuxi CloudABI",
                "Stratus Technologies OpenVOS"
        };

        printf("  %-35s %s\n", "OS/ABI:", operating_systems[this->header()->e_ident[EI_OSABI]]);
    }

    void print_abi_version() {
        printf("  %-35s %d\n", "ABI Version:", this->header()->e_ident[EI_ABIVERSION]);
    }

    void print_type() {
        const char *type = nullptr;

        uint16_t e_type = this->header()->e_type;
        switch (e_type) {
            case ET_NONE:
                type = "NONE";
                break;
            case ET_REL:
                type = "REL";
                break;
            case ET_EXEC:
                type = "EXEC";
                break;
            case ET_DYN:
                type = "DYN";
                break;
            case ET_CORE:
                type = "CORE";
                break;
            default:
                if (e_type >= ET_LOOS && e_type <= ET_HIOS) {
                    type = "LOOS - HIOS";
                } else {
                    type = "LOPROC - HIPROC";
                }
        }

        printf("  %-35s %s\n", "Type:", type);
    }

    void print_machine() {
        printf("  %-35s NOT IMPLEMENTED\n", "Machine:");
    }

    void print_version_2() {
        printf("  %-35s 0x%x\n", "Version:", this->header()->e_version);
    }

    void print_entry_point() {
        printf("  %-35s 0x%llx\n", "Entry Point Address:", this->header()->e_entry);
    }

    void print_start_of_program_headers() {
        printf("  %-35s %llu (bytes into file)\n", "Start of program headers:", this->header()->e_phoff);
    }

    void print_start_of_section_headers() {
        printf("  %-35s %llu (bytes into file)\n", "Start of section headers:", this->header()->e_shoff);
    }

    void print_flags() {
        printf("  %-35s 0x%x\n", "Flags:", this->header()->e_flags);
    }

    void print_size_of_this_header() {
        printf("  %-35s %d (bytes)\n", "Size of this header:", this->header()->e_ehsize);
    }

    void print_size_of_program_headers() {
        printf("  %-35s %d (bytes)\n", "Size of program headers:", this->header()->e_phentsize);
    }

    void print_number_of_program_headers() {
        printf("  %-35s %d\n", "Number of program headers:", this->header()->e_phnum);
    }

    void print_size_of_section_headers() {
        printf("  %-35s %d (bytes)\n", "Size of section headers:", this->header()->e_shentsize);
    }

    void print_number_of_section_headers() {
        printf("  %-35s %d\n", "Number of section headers:", this->header()->e_shnum);
    }

    void print_string_table_index() {
        printf("  %-35s %d\n", "Section header string table index:", this->header()->e_shstrndx);
    }
};

uint64_t read_file(const char *path, uint8_t **buffer) {
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        buffer = nullptr;
        return 0;
    }

    fseek(file, 0L, SEEK_END);
    int64_t byte_count = ftell(file);

    *buffer = (uint8_t *) malloc(byte_count);

    fseek(file, 0L, SEEK_SET);

    /* copy all the text into the buffer */
    fread(*buffer, sizeof(char), byte_count, file);
    fclose(file);

    return byte_count;
}

int main(int argc, char **argv) {

    if (argc != 2) {
        printf("USAGE: elf <PATH>");
        return 0;
    }

    uint8_t *buffer = nullptr;
    uint64_t byte_count = read_file(argv[1], &buffer);
    if (buffer == nullptr) {
        printf("error reading file");
        return 0;
    }

    ELF elf = ELF::make(buffer, byte_count);

    if (!elf.verify_magic()) {
        printf("could not verify elf magic");
        return 0;
    }

    elf.print_header();

    for (int i = 0; i < elf.header()->e_phnum; i++) {
        elf.get_program_header(i)->print_header();
    }

//    printf("\n\n\n Program Header:\n"
//           "    PHDR off    0x0000000000000040 vaddr 0x0000000000010040 paddr 0x0000000000010040 align 2**16\n"
//           "         filesz 0x0000000000000150 memsz 0x0000000000000150 flags r--\n"
//           "    NOTE off    0x0000000000000f9c vaddr 0x0000000000010f9c paddr 0x0000000000010f9c align 2**2\n"
//           "         filesz 0x0000000000000064 memsz 0x0000000000000064 flags r--\n"
//           "    LOAD off    0x0000000000000000 vaddr 0x0000000000010000 paddr 0x0000000000010000 align 2**16\n"
//           "         filesz 0x000000000007b1c4 memsz 0x000000000007b1c4 flags r-x\n"
//           "    LOAD off    0x0000000000080000 vaddr 0x0000000000090000 paddr 0x0000000000090000 align 2**16\n"
//           "         filesz 0x0000000000096238 memsz 0x0000000000096238 flags r--\n"
//           "    LOAD off    0x0000000000120000 vaddr 0x0000000000130000 paddr 0x0000000000130000 align 2**16\n"
//           "         filesz 0x00000000000094e0 memsz 0x0000000000041470 flags rw-\n"
//           "   STACK off    0x0000000000000000 vaddr 0x0000000000000000 paddr 0x0000000000000000 align 2**3\n"
//           "         filesz 0x0000000000000000 memsz 0x0000000000000000 flags rw-\n"
//           "private flags = 0x0:");


    return 0;
}
