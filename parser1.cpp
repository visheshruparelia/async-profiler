#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <elf.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#ifdef __LP64__
typedef Elf64_Ehdr ElfHeader;
typedef Elf64_Shdr ElfSection;
#else
typedef Elf32_Ehdr ElfHeader;
typedef Elf32_Shdr ElfSection;
#endif

// DWARF CFA instruction constants
enum {
    DW_CFA_nop                     = 0x0,
    DW_CFA_set_loc                 = 0x1,
    DW_CFA_advance_loc1            = 0x2,
    DW_CFA_advance_loc2            = 0x3,
    DW_CFA_advance_loc4            = 0x4,
    DW_CFA_offset_extended         = 0x5,
    DW_CFA_restore_extended        = 0x6,
    DW_CFA_undefined               = 0x7,
    DW_CFA_same_value              = 0x8,
    DW_CFA_register                = 0x9,
    DW_CFA_remember_state          = 0xa,
    DW_CFA_restore_state           = 0xb,
    DW_CFA_def_cfa                 = 0xc,
    DW_CFA_def_cfa_register        = 0xd,
    DW_CFA_def_cfa_offset          = 0xe,
    DW_CFA_def_cfa_expression      = 0xf,
    DW_CFA_expression              = 0x10,
    DW_CFA_offset_extended_sf      = 0x11,
    DW_CFA_def_cfa_sf              = 0x12,
    DW_CFA_def_cfa_offset_sf       = 0x13,
    DW_CFA_val_offset              = 0x14,
    DW_CFA_val_offset_sf           = 0x15,
    DW_CFA_val_expression          = 0x16,
    DW_CFA_GNU_args_size           = 0x2e,

    DW_CFA_advance_loc             = 0x1,
    DW_CFA_offset                  = 0x2,
    DW_CFA_restore                 = 0x3,
};

class DebugFrameParser {
private:
    const char* _data;
    const char* _ptr;
    const char* _end;
    
    bool checkBounds(size_t bytes) {
        return _ptr + bytes <= _end;
    }
    
    uint32_t get32() {
        if (!checkBounds(4)) return 0;
        uint32_t value = *(uint32_t*)_ptr;
        _ptr += 4;
        return value;
    }
    
    uint8_t get8() {
        if (!checkBounds(1)) return 0;
        return *_ptr++;
    }
    
    uint32_t getLeb() {
        uint32_t result = 0;
        int shift = 0;
        uint8_t byte;
        do {
            byte = get8();
            result |= (byte & 0x7f) << shift;
            shift += 7;
        } while (byte & 0x80);
        return result;
    }
    
    int32_t getSLeb() {
        int32_t result = 0;
        int shift = 0;
        uint8_t byte;
        do {
            byte = get8();
            result |= (byte & 0x7f) << shift;
            shift += 7;
        } while (byte & 0x80);
        
        if (shift < 32 && (byte & 0x40)) {
            result |= -(1 << shift);
        }
        return result;
    }
    
public:
    DebugFrameParser(const char* debug_frame_data, size_t size) : _data(debug_frame_data), _end(debug_frame_data + size) {}
    
    void parse() {
        _ptr = _data;
        int fde_count = 0;
        
        std::cout << "Parsing .debug_frame section:\n\n";
        
        while (true) {
            uint32_t length = get32();
            if (length == 0) {
                std::cout << "End of .debug_frame section\n";
                break;
            }
            
            const char* entry_start = _ptr;
            uint32_t cie_id = get32();
            
            if (cie_id == 0xffffffff) {
                std::cout << "CIE at offset " << (_ptr - _data - 8) << ", length: " << length << "\n";
                parseCie(entry_start, length);
            } else {
                std::cout << "FDE #" << ++fde_count << " at offset " << (_ptr - _data - 8) << ", length: " << length << "\n";
                parseFde(entry_start, length, cie_id);
            }
            
            // Skip to next entry
            _ptr = entry_start + length;
            std::cout << "\n";
        }
        
        std::cout << "Total FDEs found: " << fde_count << "\n";
    }
    
private:
    void parseCie(const char* start, uint32_t length) {
        uint8_t version = get8();
        std::cout << "  CFI Version: " << (int)version << " (independent of DWARF version)\n";
        
        // Augmentation string
        const char* aug_start = _ptr;
        while (*_ptr++) {}
        std::cout << "  Augmentation: \"" << aug_start << "\"\n";
        
        // CFI version 4+ has additional fields (not DWARF version)
        uint8_t address_size = 0;
        uint8_t segment_size = 0;
        
        if (version >= 4) {
            address_size = get8();
            segment_size = get8();
            std::cout << "  Address size: " << (int)address_size << "\n";
            std::cout << "  Segment selector size: " << (int)segment_size << "\n";
        }
        
        uint32_t code_align = getLeb();
        int32_t data_align = getSLeb();
        
        // Return register encoding varies by CFI version
        uint32_t return_reg;
        if (version >= 3) {
            return_reg = getLeb();  // ULEB128 in CFI v3+
        } else {
            return_reg = get8();    // Single byte in CFI v1-v2
        }
        
        std::cout << "  Code alignment: " << code_align << "\n";
        std::cout << "  Data alignment: " << data_align << "\n";
        std::cout << "  Return register: " << return_reg << "\n";
    }
    
    void parseInstructions(const char* end) {
        std::cout << "  Parsed instructions:\n";
        int instruction_num = 0;
        
        while (_ptr < end && instruction_num < 20) { // Limit output
            uint8_t op = get8();
            std::cout << "    [" << instruction_num++ << "] ";
            
            switch (op >> 6) {
                case 0:
                    parseExtendedInstruction(op);
                    break;
                case DW_CFA_advance_loc:
                    std::cout << "DW_CFA_advance_loc(" << (op & 0x3f) << ")\n";
                    break;
                case DW_CFA_offset:
                    std::cout << "DW_CFA_offset(reg=" << (op & 0x3f) << ", offset=" << getLeb() << ")\n";
                    break;
                case DW_CFA_restore:
                    std::cout << "DW_CFA_restore(reg=" << (op & 0x3f) << ")\n";
                    break;
            }
        }
        
        if (_ptr < end) {
            std::cout << "    ... (" << (end - _ptr) << " more bytes)\n";
        }
    }
    
    void parseExtendedInstruction(uint8_t op) {
        switch (op) {
            case DW_CFA_nop:
                std::cout << "DW_CFA_nop\n";
                break;
            case DW_CFA_set_loc:
                std::cout << "DW_CFA_set_loc\n";
                break;
            case DW_CFA_advance_loc1:
                std::cout << "DW_CFA_advance_loc1(" << (int)get8() << ")\n";
                break;
            case DW_CFA_advance_loc2: {
                uint16_t val = *(uint16_t*)_ptr;
                _ptr += 2;
                std::cout << "DW_CFA_advance_loc2(" << val << ")\n";
                break;
            }
            case DW_CFA_advance_loc4: {
                uint32_t val = get32();
                std::cout << "DW_CFA_advance_loc4(" << val << ")\n";
                break;
            }
            case DW_CFA_offset_extended:
                std::cout << "DW_CFA_offset_extended(reg=" << getLeb() << ", offset=" << getLeb() << ")\n";
                break;
            case DW_CFA_restore_extended:
                std::cout << "DW_CFA_restore_extended(reg=" << getLeb() << ")\n";
                break;
            case DW_CFA_undefined:
                std::cout << "DW_CFA_undefined(reg=" << getLeb() << ")\n";
                break;
            case DW_CFA_same_value:
                std::cout << "DW_CFA_same_value(reg=" << getLeb() << ")\n";
                break;
            case DW_CFA_register:
                std::cout << "DW_CFA_register(reg1=" << getLeb() << ", reg2=" << getLeb() << ")\n";
                break;
            case DW_CFA_remember_state:
                std::cout << "DW_CFA_remember_state\n";
                break;
            case DW_CFA_restore_state:
                std::cout << "DW_CFA_restore_state\n";
                break;
            case DW_CFA_def_cfa:
                std::cout << "DW_CFA_def_cfa(reg=" << getLeb() << ", offset=" << getLeb() << ")\n";
                break;
            case DW_CFA_def_cfa_register:
                std::cout << "DW_CFA_def_cfa_register(reg=" << getLeb() << ")\n";
                break;
            case DW_CFA_def_cfa_offset:
                std::cout << "DW_CFA_def_cfa_offset(offset=" << getLeb() << ")\n";
                break;
            case DW_CFA_def_cfa_expression: {
                uint32_t len = getLeb();
                std::cout << "DW_CFA_def_cfa_expression(len=" << len << ")\n";
                _ptr += len; // Skip expression
                break;
            }
            case DW_CFA_expression: {
                uint32_t reg = getLeb();
                uint32_t len = getLeb();
                std::cout << "DW_CFA_expression(reg=" << reg << ", len=" << len << ")\n";
                _ptr += len; // Skip expression
                break;
            }
            case DW_CFA_offset_extended_sf:
                std::cout << "DW_CFA_offset_extended_sf(reg=" << getLeb() << ", offset=" << getSLeb() << ")\n";
                break;
            case DW_CFA_def_cfa_sf:
                std::cout << "DW_CFA_def_cfa_sf(reg=" << getLeb() << ", offset=" << getSLeb() << ")\n";
                break;
            case DW_CFA_def_cfa_offset_sf:
                std::cout << "DW_CFA_def_cfa_offset_sf(offset=" << getSLeb() << ")\n";
                break;
            case DW_CFA_GNU_args_size:
                std::cout << "DW_CFA_GNU_args_size(size=" << getLeb() << ")\n";
                break;
            default:
                std::cout << "Unknown instruction 0x" << std::hex << (int)op << std::dec << "\n";
                break;
        }
    }
    
    void parseFde(const char* start, uint32_t length, uint32_t cie_offset) {
        std::cout << "  CIE offset: " << cie_offset << "\n";
        
        if (!checkBounds(16)) {
            std::cout << "  Error: Not enough data for FDE\n";
            return;
        }
        
        uint64_t initial_location = *(uint64_t*)_ptr;
        _ptr += 8;
        uint64_t address_range = *(uint64_t*)_ptr;
        _ptr += 8;
        
        std::cout << "  Initial location: 0x" << std::hex << initial_location << std::dec << "\n";
        std::cout << "  Address range: 0x" << std::hex << address_range << std::dec << "\n";
        std::cout << "  End address: 0x" << std::hex << (initial_location + address_range) << std::dec << "\n";
        
        // Parse instructions
        const char* instructions_start = _ptr;
        const char* entry_end = start + length;
        int instruction_count = entry_end - instructions_start;
        
        std::cout << "  Instructions: " << instruction_count << " bytes\n";
        
        if (instruction_count > 0) {
            parseInstructions(entry_end);
        }
    }
};

class ElfParser {
private:
    const char* _base;
    ElfHeader* _header;
    const char* _sections;
    
public:
    ElfParser(const char* base) : _base(base) {
        _header = (ElfHeader*)base;
        _sections = base + _header->e_shoff;
    }
    
    bool validHeader() {
        unsigned char* ident = _header->e_ident;
        return ident[0] == 0x7f && ident[1] == 'E' && ident[2] == 'L' && ident[3] == 'F';
    }
    
    ElfSection* section(int index) {
        return (ElfSection*)(_sections + index * _header->e_shentsize);
    }
    
    const char* at(ElfSection* section) {
        return _base + section->sh_offset;
    }
    
    const char* getSectionName(ElfSection* section) {
        ElfSection* strtab = this->section(_header->e_shstrndx);
        return _base + strtab->sh_offset + section->sh_name;
    }
    
    ElfSection* findSection(const char* name) {
        for (int i = 0; i < _header->e_shnum; i++) {
            ElfSection* section = this->section(i);
            if (strcmp(getSectionName(section), name) == 0) {
                return section;
            }
        }
        return nullptr;
    }
    
    void parseDebugFrame() {
        ElfSection* debug_frame = findSection(".debug_frame");
        if (!debug_frame) {
            std::cout << "No .debug_frame section found\n";
            return;
        }
        
        std::cout << "Found .debug_frame section:\n";
        std::cout << "  Offset: 0x" << std::hex << debug_frame->sh_offset << std::dec << "\n";
        std::cout << "  Size: " << debug_frame->sh_size << " bytes\n\n";
        
        if (debug_frame->sh_size == 0) {
            std::cout << "Empty .debug_frame section\n";
            return;
        }
        
        DebugFrameParser parser(at(debug_frame), debug_frame->sh_size);
        parser.parse();
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <object_file>\n";
        return 1;
    }
    
    const char* filename = argv[1];
    
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return 1;
    }
    
    struct stat st;
    if (fstat(fd, &st) == -1) {
        perror("fstat");
        close(fd);
        return 1;
    }
    
    size_t length = st.st_size;
    if (length < sizeof(ElfHeader)) {
        std::cout << "File too small to be a valid ELF file\n";
        close(fd);
        return 1;
    }
    
    void* addr = mmap(nullptr, length, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    
    if (addr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    
    ElfParser parser((const char*)addr);
    if (!parser.validHeader()) {
        std::cout << "Invalid ELF file\n";
        munmap(addr, length);
        return 1;
    }
    
    std::cout << "Parsing ELF file: " << filename << "\n\n";
    parser.parseDebugFrame();
    
    munmap(addr, length);
    return 0;
}