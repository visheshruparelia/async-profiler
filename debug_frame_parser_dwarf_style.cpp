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

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

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

// Register constants (simplified)
enum {
    DW_REG_SP = 7,
    DW_REG_FP = 6,
    DW_REG_PC = 16,
};

// Frame constants
const int EMPTY_FRAME_SIZE = 8;
const int DW_SAME_FP = -1;

class DebugFrameParser {
private:
    const char* _data;
    const char* _ptr;
    const char* _end;
    u32 _code_align;
    int _data_align;
    
    bool checkBounds(size_t bytes) {
        return _ptr + bytes <= _end;
    }
    
    u32 get32() {
        if (!checkBounds(4)) return 0;
        u32 value = *(u32*)_ptr;
        _ptr += 4;
        return value;
    }
    
    u64 get64() {
        if (!checkBounds(8)) return 0;
        u64 value = *(u64*)_ptr;
        _ptr += 8;
        return value;
    }
    
    u16 get16() {
        if (!checkBounds(2)) return 0;
        u16 value = *(u16*)_ptr;
        _ptr += 2;
        return value;
    }
    
    u8 get8() {
        if (!checkBounds(1)) return 0;
        return *_ptr++;
    }
    
    u32 getLeb() {
        u32 result = 0;
        int shift = 0;
        u8 byte;
        do {
            byte = get8();
            result |= (byte & 0x7f) << shift;
            shift += 7;
        } while (byte & 0x80);
        return result;
    }
    
    int getSLeb() {
        int result = 0;
        int shift = 0;
        u8 byte;
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
    
    void skipLeb() {
        while (get8() & 0x80);
    }
    
public:
    DebugFrameParser(const char* debug_frame_data, size_t size) 
        : _data(debug_frame_data), _end(debug_frame_data + size), _code_align(1), _data_align(-8) {}
    
    void parse() {
        _ptr = _data;
        int fde_count = 0;
        
        std::cout << "Parsing .debug_frame section:\n\n";
        
        while (true) {
            u32 initial_length = get32();
            u64 length;
            u64 cie_id;
            const char* entry_start;
            
            if (initial_length == 0) {
                std::cout << "End of .debug_frame section\n";
                break;
            }
            
            if (initial_length == 0xffffffff) {
                // 64-bit DWARF format
                length = get64();
                entry_start = _ptr;
                cie_id = get64();
            } else {
                // 32-bit DWARF format  
                length = initial_length;
                entry_start = _ptr;
                cie_id = get32();
            }
            
            if (cie_id == 0xffffffff || cie_id == 0xffffffffull) {
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
    void parseCie(const char* entry_start, u64 length) {
        u8 version = get8();
        std::cout << "  CFI Version: " << (int)version << "\n";
        
        // Augmentation string
        const char* aug_start = _ptr;
        while (*_ptr++) {}
        std::cout << "  Augmentation: \"" << aug_start << "\"\n";
        
        if (version >= 4) {
            u8 address_size = get8();
            u8 segment_size = get8();
            std::cout << "  Address size: " << (int)address_size << "\n";
            std::cout << "  Segment selector size: " << (int)segment_size << "\n";
        }
        
        _code_align = getLeb();
        _data_align = getSLeb();
        
        u32 return_reg;
        if (version >= 3) {
            return_reg = getLeb();
        } else {
            return_reg = get8();
        }
        
        std::cout << "  Code alignment: " << _code_align << "\n";
        std::cout << "  Data alignment: " << _data_align << "\n";
        std::cout << "  Return register: " << return_reg << "\n";
        
        // Skip to end of CIE
        _ptr = entry_start + length;
    }
    
    void parseFde(const char* entry_start, u64 length, u64 cie_offset) {
        std::cout << "  CIE offset: " << cie_offset << "\n";
        
        if (!checkBounds(16)) {
            std::cout << "  Error: Not enough data for FDE\n";
            return;
        }
        
        u64 initial_location = *(u64*)_ptr;
        _ptr += 8;
        u64 address_range = *(u64*)_ptr;
        _ptr += 8;
        
        std::cout << "  Initial location: 0x" << std::hex << initial_location << std::dec << "\n";
        std::cout << "  Address range: 0x" << std::hex << address_range << std::dec << "\n";
        std::cout << "  End address: 0x" << std::hex << (initial_location + address_range) << std::dec << "\n";
        
        // Parse instructions using dwarf.cpp style
        parseInstructions(initial_location, entry_start + length);
    }
    
    void parseInstructions(u64 loc, const char* end) {
        const u32 code_align = _code_align;
        const int data_align = _data_align;

        u32 cfa_reg = DW_REG_SP;
        int cfa_off = EMPTY_FRAME_SIZE;
        int fp_off = DW_SAME_FP;
        int pc_off = -EMPTY_FRAME_SIZE;

        u32 rem_cfa_reg = DW_REG_SP;
        int rem_cfa_off = EMPTY_FRAME_SIZE;
        int rem_fp_off = DW_SAME_FP;
        int rem_pc_off = -EMPTY_FRAME_SIZE;

        std::cout << "  Parsing instructions (dwarf.cpp style):\n";
        int instruction_count = 0;

        while (_ptr < end && instruction_count < 50) { // Limit output
            u8 op = get8();
            std::cout << "    [" << instruction_count++ << "] ";
            
            switch (op >> 6) {
                case 0:
                    switch (op) {
                        case DW_CFA_nop:
                            std::cout << "DW_CFA_nop\n";
                            break;
                        case DW_CFA_set_loc:
                            std::cout << "DW_CFA_set_loc (end parsing)\n";
                            _ptr = end;
                            break;
                        case DW_CFA_advance_loc1: {
                            u8 delta = get8();
                            std::cout << "DW_CFA_advance_loc1(" << (int)delta << ") -> loc += " << (delta * code_align) << "\n";
                            loc += delta * code_align;
                            break;
                        }
                        case DW_CFA_advance_loc2: {
                            u16 delta = get16();
                            std::cout << "DW_CFA_advance_loc2(" << delta << ") -> loc += " << (delta * code_align) << "\n";
                            loc += delta * code_align;
                            break;
                        }
                        case DW_CFA_advance_loc4: {
                            u32 delta = get32();
                            std::cout << "DW_CFA_advance_loc4(" << delta << ") -> loc += " << (delta * code_align) << "\n";
                            loc += delta * code_align;
                            break;
                        }
                        case DW_CFA_offset_extended: {
                            u32 reg = getLeb();
                            u32 offset = getLeb();
                            std::cout << "DW_CFA_offset_extended(reg=" << reg << ", offset=" << offset << ")\n";
                            if (reg == DW_REG_FP) fp_off = offset * data_align;
                            else if (reg == DW_REG_PC) pc_off = offset * data_align;
                            break;
                        }
                        case DW_CFA_restore_extended:
                        case DW_CFA_undefined:
                        case DW_CFA_same_value: {
                            u32 reg = getLeb();
                            std::cout << "DW_CFA_" << (op == DW_CFA_restore_extended ? "restore_extended" : 
                                                      op == DW_CFA_undefined ? "undefined" : "same_value") 
                                     << "(reg=" << reg << ")\n";
                            if (reg == DW_REG_FP) fp_off = DW_SAME_FP;
                            break;
                        }
                        case DW_CFA_register: {
                            u32 reg1 = getLeb();
                            u32 reg2 = getLeb();
                            std::cout << "DW_CFA_register(reg1=" << reg1 << ", reg2=" << reg2 << ")\n";
                            break;
                        }
                        case DW_CFA_remember_state:
                            std::cout << "DW_CFA_remember_state\n";
                            rem_cfa_reg = cfa_reg;
                            rem_cfa_off = cfa_off;
                            rem_fp_off = fp_off;
                            rem_pc_off = pc_off;
                            break;
                        case DW_CFA_restore_state:
                            std::cout << "DW_CFA_restore_state\n";
                            cfa_reg = rem_cfa_reg;
                            cfa_off = rem_cfa_off;
                            fp_off = rem_fp_off;
                            pc_off = rem_pc_off;
                            break;
                        case DW_CFA_def_cfa: {
                            u32 reg = getLeb();
                            u32 offset = getLeb();
                            std::cout << "DW_CFA_def_cfa(reg=" << reg << ", offset=" << offset << ")\n";
                            cfa_reg = reg;
                            cfa_off = offset;
                            break;
                        }
                        case DW_CFA_def_cfa_register: {
                            u32 reg = getLeb();
                            std::cout << "DW_CFA_def_cfa_register(reg=" << reg << ")\n";
                            cfa_reg = reg;
                            break;
                        }
                        case DW_CFA_def_cfa_offset: {
                            u32 offset = getLeb();
                            std::cout << "DW_CFA_def_cfa_offset(offset=" << offset << ")\n";
                            cfa_off = offset;
                            break;
                        }
                        case DW_CFA_def_cfa_expression: {
                            u32 len = getLeb();
                            std::cout << "DW_CFA_def_cfa_expression(len=" << len << ")\n";
                            _ptr += len;
                            break;
                        }
                        case DW_CFA_expression: {
                            u32 reg = getLeb();
                            u32 len = getLeb();
                            std::cout << "DW_CFA_expression(reg=" << reg << ", len=" << len << ")\n";
                            _ptr += len;
                            break;
                        }
                        case DW_CFA_offset_extended_sf: {
                            u32 reg = getLeb();
                            int offset = getSLeb();
                            std::cout << "DW_CFA_offset_extended_sf(reg=" << reg << ", offset=" << offset << ")\n";
                            if (reg == DW_REG_FP) fp_off = offset * data_align;
                            else if (reg == DW_REG_PC) pc_off = offset * data_align;
                            break;
                        }
                        case DW_CFA_def_cfa_sf: {
                            u32 reg = getLeb();
                            int offset = getSLeb();
                            std::cout << "DW_CFA_def_cfa_sf(reg=" << reg << ", offset=" << offset << ")\n";
                            cfa_reg = reg;
                            cfa_off = offset * data_align;
                            break;
                        }
                        case DW_CFA_def_cfa_offset_sf: {
                            int offset = getSLeb();
                            std::cout << "DW_CFA_def_cfa_offset_sf(offset=" << offset << ")\n";
                            cfa_off = offset * data_align;
                            break;
                        }
                        case DW_CFA_val_offset:
                        case DW_CFA_val_offset_sf:
                            skipLeb();
                            skipLeb();
                            std::cout << "DW_CFA_val_offset" << (op == DW_CFA_val_offset_sf ? "_sf" : "") << "\n";
                            break;
                        case DW_CFA_GNU_args_size: {
                            u32 size = getLeb();
                            std::cout << "DW_CFA_GNU_args_size(size=" << size << ")\n";
                            break;
                        }
                        default:
                            std::cout << "Unknown extended instruction 0x" << std::hex << (int)op << std::dec << "\n";
                            break;
                    }
                    break;
                case DW_CFA_advance_loc: {
                    u32 delta = op & 0x3f;
                    std::cout << "DW_CFA_advance_loc(" << delta << ") -> loc += " << (delta * code_align) << "\n";
                    loc += delta * code_align;
                    break;
                }
                case DW_CFA_offset: {
                    u32 reg = op & 0x3f;
                    u32 offset = getLeb();
                    std::cout << "DW_CFA_offset(reg=" << reg << ", offset=" << offset << ")\n";
                    if (reg == DW_REG_FP) fp_off = offset * data_align;
                    else if (reg == DW_REG_PC) pc_off = offset * data_align;
                    break;
                }
                case DW_CFA_restore: {
                    u32 reg = op & 0x3f;
                    std::cout << "DW_CFA_restore(reg=" << reg << ")\n";
                    if (reg == DW_REG_FP) fp_off = DW_SAME_FP;
                    break;
                }
            }
            
            // Print current state
            std::cout << "      State: loc=0x" << std::hex << loc << std::dec 
                     << ", cfa=r" << cfa_reg << "+" << cfa_off 
                     << ", fp_off=" << fp_off << ", pc_off=" << pc_off << "\n";
        }
        
        if (_ptr < end) {
            std::cout << "    ... (" << (end - _ptr) << " more instruction bytes)\n";
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