#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define E_IDENT_SIZE 16

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


struct ELFHeader {
    uint8_t e_ident[E_IDENT_SIZE];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
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

        uint16_t  e_type = this->header()->e_type;
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
                if(e_type >= ET_LOOS && e_type <= ET_HIOS) {
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

int main(int argc, char** argv) {

    if(argc != 2) {
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

    return 0;
}
