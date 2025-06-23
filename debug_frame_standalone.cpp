/*
 * Standalone Debug Frame Parser
 * Based on async-profiler's dwarf.cpp
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <elf.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <iomanip>

// Inlined dependencies from arch.h
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#ifdef __LP64__
typedef Elf64_Ehdr ElfHeader;
typedef Elf64_Shdr ElfSection;
#else
typedef Elf32_Ehdr ElfHeader;
typedef Elf32_Shdr ElfSection;
#endif

// Inlined dependencies from dwarf.h
typedef unsigned int instruction_t;

// Constants from dwarf.h
const int DW_REG_PLT = 128;      // denotes special rule for PLT entries
const int DW_REG_INVALID = 255;  // denotes unsupported configuration

const int DW_PC_OFFSET = 1;
const int DW_SAME_FP = 0x80000000;
const int DW_STACK_SLOT = sizeof(void*);

// Architecture-specific constants (x86_64)
#if defined(__x86_64__)
const int DW_REG_FP = 6;
const int DW_REG_SP = 7;
const int DW_REG_PC = 16;
const int EMPTY_FRAME_SIZE = DW_STACK_SLOT;
const int LINKED_FRAME_SIZE = 2 * DW_STACK_SLOT;
#elif defined(__i386__)
const int DW_REG_FP = 5;
const int DW_REG_SP = 4;
const int DW_REG_PC = 8;
const int EMPTY_FRAME_SIZE = DW_STACK_SLOT;
const int LINKED_FRAME_SIZE = 2 * DW_STACK_SLOT;
#elif defined(__aarch64__)
const int DW_REG_FP = 29;
const int DW_REG_SP = 31;
const int DW_REG_PC = 30;
const int EMPTY_FRAME_SIZE = 0;
const int LINKED_FRAME_SIZE = 0;
#else
const int DW_REG_FP = 6;  // Default to x86_64
const int DW_REG_SP = 7;
const int DW_REG_PC = 16;
const int EMPTY_FRAME_SIZE = DW_STACK_SLOT;
const int LINKED_FRAME_SIZE = 2 * DW_STACK_SLOT;
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
    DW_CFA_AARCH64_negate_ra_state = 0x2d,
    DW_CFA_GNU_args_size           = 0x2e,

    DW_CFA_advance_loc             = 0x1,
    DW_CFA_offset                  = 0x2,
    DW_CFA_restore                 = 0x3,
};

enum {
    DW_OP_breg_pc = 0x70 + DW_REG_PC,
    DW_OP_const1u = 0x08,
    DW_OP_const1s = 0x09,
    DW_OP_const2u = 0x0a,
    DW_OP_const2s = 0x0b,
    DW_OP_const4u = 0x0c,
    DW_OP_const4s = 0x0d,
    DW_OP_constu  = 0x10,
    DW_OP_consts  = 0x11,
    DW_OP_minus   = 0x1c,
    DW_OP_plus    = 0x22,
};

struct FrameDesc {
    u32 loc;
    int cfa;
    int fp_off;
    int pc_off;
    
    static FrameDesc empty_frame;
    static FrameDesc default_frame;
};

FrameDesc FrameDesc::empty_frame = {0, DW_REG_SP | EMPTY_FRAME_SIZE << 8, DW_SAME_FP, -EMPTY_FRAME_SIZE};
FrameDesc FrameDesc::default_frame = {0, DW_REG_FP | LINKED_FRAME_SIZE << 8, -LINKED_FRAME_SIZE, -LINKED_FRAME_SIZE + DW_STACK_SLOT};

class DebugFrameParser {
private:
    const char* _name;
    const char* _image_base;
    const char* _ptr;
    u32 _code_align;
    int _data_align;
    
    int _capacity;
    int _count;
    FrameDesc* _table;
    FrameDesc* _prev;
    
    // ELF parsing members
    const char* _file_base;
    ElfHeader* _header;
    const char* _sections;
    
    const char* add(size_t size) {
        const char* ptr = _ptr;
        _ptr = ptr + size;
        return ptr;
    }

    u8 get8() {
        return *_ptr++;
    }

    u16 get16() {
        return *(u16*)add(2);
    }

    u32 get32() {
        return *(u32*)add(4);
    }

    u64 get64() {
        return *(u64*)add(8);
    }
    
    const char* getPtr() {
        const char* ptr = _ptr;
        return ptr + *(int*)add(4);
    }
    
    u32 getLeb() {
        u32 result = 0;
        for (u32 shift = 0; ; shift += 7) {
            u8 b = *_ptr++;
            result |= (b & 0x7f) << shift;
            if ((b & 0x80) == 0) {
                return result;
            }
        }
    }
    
    int getSLeb() {
        int result = 0;
        for (u32 shift = 0; ; shift += 7) {
            u8 b = *_ptr++;
            result |= (b & 0x7f) << shift;
            if ((b & 0x80) == 0) {
                if ((b & 0x40) != 0 && (shift += 7) < 32) {
                    result |= -1 << shift;
                }
                return result;
            }
        }
    }
    
    void skipLeb() {
        while (*_ptr++ & 0x80) {}
    }
    
    void addRecord(u32 loc, u32 cfa_reg, int cfa_off, int fp_off, int pc_off) {
        int cfa = cfa_reg | cfa_off << 8;
        if (_prev == NULL || (_prev->loc == loc && --_count >= 0) ||
                _prev->cfa != cfa || _prev->fp_off != fp_off || _prev->pc_off != pc_off) {
            _prev = addRecordRaw(loc, cfa, fp_off, pc_off);
        }
    }
    
    FrameDesc* addRecordRaw(u32 loc, int cfa, int fp_off, int pc_off) {
        if (_count >= _capacity) {
            _capacity *= 2;
            _table = (FrameDesc*)realloc(_table, _capacity * sizeof(FrameDesc));
        }

        FrameDesc* f = &_table[_count++];
        f->loc = loc;
        f->cfa = cfa;
        f->fp_off = fp_off;
        f->pc_off = pc_off;
        
        // Debug output
        std::cout << "    -> Record: loc=0x" << std::hex << loc << std::dec 
                 << ", cfa=r" << (cfa & 0xff) << "+" << (cfa >> 8)
                 << ", fp_off=" << fp_off << ", pc_off=" << pc_off << "\n";
        
        return f;
    }
    
    void sortTable() {
        // Simple insertion sort since the table is likely mostly sorted
        for (int i = 1; i < _count; i++) {
            FrameDesc temp = _table[i];
            int j = i - 1;
            while (j >= 0 && _table[j].loc > temp.loc) {
                _table[j + 1] = _table[j];
                j--;
            }
            _table[j + 1] = temp;
        }
        std::cout << "  Sorted " << _count << " frame records\n";
    }
    
    int parseExpression() {
        int pc_off = 0;
        int tos = 0;

        u32 len = getLeb();
        const char* end = _ptr + len;

        while (_ptr < end) {
            u8 op = get8();
            switch (op) {
                case DW_OP_breg_pc:
                    pc_off = getSLeb();
                    break;
                case DW_OP_const1u:
                    tos = get8();
                    break;
                case DW_OP_const1s:
                    tos = (signed char)get8();
                    break;
                case DW_OP_const2u:
                    tos = get16();
                    break;
                case DW_OP_const2s:
                    tos = (short)get16();
                    break;
                case DW_OP_const4u:
                case DW_OP_const4s:
                    tos = get32();
                    break;
                case DW_OP_constu:
                    tos = getLeb();
                    break;
                case DW_OP_consts:
                    tos = getSLeb();
                    break;
                case DW_OP_minus:
                    pc_off -= tos;
                    break;
                case DW_OP_plus:
                    pc_off += tos;
                    break;
                default:
                    std::cout << "Unknown DWARF opcode 0x" << std::hex << (int)op << std::dec << " in " << _name << "\n";
                    _ptr = end;
                    return 0;
            }
        }

        return pc_off;
    }
    
public:
    DebugFrameParser(const char* filename) {
        _name = filename;
        _image_base = nullptr;
        _code_align = sizeof(instruction_t);
        _data_align = -(int)sizeof(void*);
        
        _capacity = 128;
        _count = 0;
        _table = (FrameDesc*)malloc(_capacity * sizeof(FrameDesc));
        _prev = nullptr;
        
        if (!loadFile(filename)) {
            std::cout << "Failed to load file: " << filename << "\n";
            return;
        }
        
        parseDebugFrameSection();
    }
    
    ~DebugFrameParser() {
        if (_table) {
            free(_table);
        }
    }
    
    bool loadFile(const char* filename) {
        int fd = open(filename, O_RDONLY);
        if (fd == -1) {
            perror("open");
            return false;
        }
        
        struct stat st;
        if (fstat(fd, &st) == -1) {
            perror("fstat");
            close(fd);
            return false;
        }
        
        size_t length = st.st_size;
        if (length < sizeof(ElfHeader)) {
            std::cout << "File too small to be a valid ELF file\n";
            close(fd);
            return false;
        }
        
        void* addr = mmap(nullptr, length, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        
        if (addr == MAP_FAILED) {
            perror("mmap");
            return false;
        }
        
        _file_base = (const char*)addr;
        _header = (ElfHeader*)addr;
        _sections = _file_base + _header->e_shoff;
        
        // Validate ELF header
        unsigned char* ident = _header->e_ident;
        if (!(ident[0] == 0x7f && ident[1] == 'E' && ident[2] == 'L' && ident[3] == 'F')) {
            std::cout << "Invalid ELF file\n";
            return false;
        }
        
        return true;
    }
    
    ElfSection* section(int index) {
        return (ElfSection*)(_sections + index * _header->e_shentsize);
    }
    
    const char* at(ElfSection* section) {
        return _file_base + section->sh_offset;
    }
    
    const char* getSectionName(ElfSection* section) {
        ElfSection* strtab = this->section(_header->e_shstrndx);
        return _file_base + strtab->sh_offset + section->sh_name;
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
    
    void parseDebugFrameSection() {
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
        
        parseDebugFrame(at(debug_frame));
    }
    
    void parseDebugFrame(const char* debug_frame) {
        ElfSection* debug_frame_section = findSection(".debug_frame");
        const char* section_end = debug_frame + debug_frame_section->sh_size;
        
        _ptr = debug_frame;
        int cie_count = 0;
        int fde_count = 0;
        
        std::cout << "Parsing .debug_frame entries:\n\n";
        
        while (_ptr < section_end) {
            // Check if we have enough bytes for length field
            // if (_ptr + 4 > section_end) {
            //     std::cout << "End of .debug_frame section (insufficient data)\n";
            //     break;
            // }
            
            u32 initial_length = get32();
            u64 length;
            u64 cie_id;
            const char* entry_start;
            
            if (initial_length == 0) {
                std::cout << "End of .debug_frame section (zero length)\n";
                break;
            }
            
            if (initial_length == 0xffffffff) {
                // 64-bit DWARF format
                length = get64();
                entry_start = _ptr;
                cie_id = get64();
                std::cout << "64-bit DWARF format detected\n";
            } else {
                // 32-bit DWARF format  
                length = initial_length;
                entry_start = _ptr;
                cie_id = get32();
            }
            
            if (cie_id == 0xffffffff || cie_id == 0xffffffffull) {
                std::cout << "CIE #" << ++cie_count << " at offset " << (_ptr - debug_frame - 8) << ", length: " << length << "\n";
                parseDebugCie(length, entry_start);
            } else {
                std::cout << "FDE #" << ++fde_count << " at offset " << (_ptr - debug_frame - 8) << ", length: " << length << "\n";
                parseDebugFde(entry_start, length, cie_id);
            }
            
            // Skip to next entry with bounds check
            const char* next_entry = entry_start + length;
            // if (next_entry > section_end) {
            //     std::cout << "Warning: Entry extends beyond section boundary with last _ptr: 0x" << std::hex << _ptr<< std::dec << "\n";
            //     break;
            // }
            _ptr = next_entry;
            std::cout << "\n";
        }
        
        std::cout << "Summary: " << cie_count << " CIEs, " << fde_count << " FDEs\n";
        sortTable();
    }
    
    void parseDebugCie(u64 length, const char* entry_start) {
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
        
        _ptr = entry_start + length;
    }
    
    void parseDebugFde(const char* entry_start, u64 length, u64 cie_offset) {
        std::cout << "  CIE offset: " << cie_offset << "\n";
        
        u64 initial_location = *(u64*)_ptr;
        _ptr += 8;
        u64 address_range = *(u64*)_ptr;
        _ptr += 8;
        
        std::cout << "  Initial location: 0x" << std::hex << initial_location << std::dec << "\n";
        std::cout << "  Address range: 0x" << std::hex << address_range << std::dec << "\n";
        std::cout << "  End address: 0x" << std::hex << (initial_location + address_range) << std::dec << "\n";
        
        std::cout << "  Parsing instructions:\n";
        parseInstructions(initial_location, entry_start + length);
        addRecord(initial_location + address_range, DW_REG_FP, LINKED_FRAME_SIZE, -LINKED_FRAME_SIZE, -LINKED_FRAME_SIZE + DW_STACK_SLOT);
    }
    
    void parseInstructions(u32 loc, const char* end) {
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

        int instruction_count = 0;
        while (_ptr < end && instruction_count < 100) { // Limit for readability
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
                            addRecord(loc, cfa_reg, cfa_off, fp_off, pc_off);
                            u8 delta = get8();
                            loc += delta * code_align;
                            std::cout << "DW_CFA_advance_loc1(" << (int)delta << ") -> loc=0x" << std::hex << loc << std::dec << "\n";
                            break;
                        }
                        case DW_CFA_advance_loc2: {
                            addRecord(loc, cfa_reg, cfa_off, fp_off, pc_off);
                            u16 delta = get16();
                            loc += delta * code_align;
                            std::cout << "DW_CFA_advance_loc2(" << delta << ") -> loc=0x" << std::hex << loc << std::dec << "\n";
                            break;
                        }
                        case DW_CFA_advance_loc4: {
                            addRecord(loc, cfa_reg, cfa_off, fp_off, pc_off);
                            u32 delta = get32();
                            loc += delta * code_align;
                            std::cout << "DW_CFA_advance_loc4(" << delta << ") -> loc=0x" << std::hex << loc << std::dec << "\n";
                            break;
                        }
                        case DW_CFA_offset_extended: {
                            u32 reg = getLeb();
                            u32 offset = getLeb();
                            std::cout << "DW_CFA_offset_extended(reg=" << reg << ", offset=" << offset << ")\n";
                            switch (reg) {
                                case DW_REG_FP: fp_off = offset * data_align; break;
                                case DW_REG_PC: pc_off = offset * data_align; break;
                            }
                            break;
                        }
                        case DW_CFA_restore_extended:
                        case DW_CFA_undefined:
                        case DW_CFA_same_value: {
                            u32 reg = getLeb();
                            std::cout << "DW_CFA_" << (op == DW_CFA_restore_extended ? "restore_extended" : 
                                                      op == DW_CFA_undefined ? "undefined" : "same_value") 
                                     << "(reg=" << reg << ")\n";
                            if (reg == DW_REG_FP) {
                                fp_off = DW_SAME_FP;
                            }
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
                            cfa_reg = len == 11 ? DW_REG_PLT : DW_REG_INVALID;
                            cfa_off = DW_STACK_SLOT;
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
                            switch (reg) {
                                case DW_REG_FP: fp_off = offset * data_align; break;
                                case DW_REG_PC: pc_off = offset * data_align; break;
                            }
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
                        case DW_CFA_val_expression: {
                            u32 reg = getLeb();
                            std::cout << "DW_CFA_val_expression(reg=" << reg << ")\n";
                            if (reg == DW_REG_PC) {
                                int pc_off_expr = parseExpression();
                                if (pc_off_expr != 0) {
                                    fp_off = DW_PC_OFFSET | (pc_off_expr << 1);
                                }
                            } else {
                                _ptr += getLeb();
                            }
                            break;
                        }
#ifdef __aarch64__
                        case DW_CFA_AARCH64_negate_ra_state:
                            std::cout << "DW_CFA_AARCH64_negate_ra_state\n";
                            break;
#endif
                        case DW_CFA_GNU_args_size: {
                            u32 size = getLeb();
                            std::cout << "DW_CFA_GNU_args_size(size=" << size << ")\n";
                            break;
                        }
                        default:
                            std::cout << "Unknown DWARF instruction 0x" << std::hex << (int)op << std::dec << " in " << _name << "\n";
                            return;
                    }
                    break;
                case DW_CFA_advance_loc: {
                    addRecord(loc, cfa_reg, cfa_off, fp_off, pc_off);
                    u32 delta = op & 0x3f;
                    loc += delta * code_align;
                    std::cout << "DW_CFA_advance_loc(" << delta << ") -> loc=0x" << std::hex << loc << std::dec << "\n";
                    break;
                }
                case DW_CFA_offset: {
                    u32 reg = op & 0x3f;
                    u32 offset = getLeb();
                    std::cout << "DW_CFA_offset(reg=" << reg << ", offset=" << offset << ")\n";
                    switch (reg) {
                        case DW_REG_FP: fp_off = offset * data_align; break;
                        case DW_REG_PC: pc_off = offset * data_align; break;
                    }
                    break;
                }
                case DW_CFA_restore: {
                    u32 reg = op & 0x3f;
                    std::cout << "DW_CFA_restore(reg=" << reg << ")\n";
                    if (reg == DW_REG_FP) {
                        fp_off = DW_SAME_FP;
                    }
                    break;
                }
            }
        }
        
        if (_ptr < end) {
            std::cout << "    ... (" << (end - _ptr) << " more instruction bytes)\n";
        }
        
        addRecord(loc, cfa_reg, cfa_off, fp_off, pc_off);
    }
    
    void printFrameTable() {
        std::cout << "\nGenerated Frame Table (" << _count << " entries):\n";
        std::cout << "  Loc      CFA       FP_Off  PC_Off\n";
        std::cout << "  -------- --------- ------- -------\n";
        for (int i = 0; i < _count; i++) {
            FrameDesc* f = &_table[i];
            std::cout << "  " << std::hex << std::setfill('0') << std::setw(8) << f->loc << std::dec
                     << " r" << (f->cfa & 0xff) << "+" << std::setw(3) << (f->cfa >> 8)
                     << "   " << std::setw(6) << f->fp_off
                     << "  " << std::setw(6) << f->pc_off << "\n";
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <object_file>\n";
        return 1;
    }
    
    std::cout << "Debug Frame Parser - Based on async-profiler dwarf.cpp\n";
    std::cout << "Parsing file: " << argv[1] << "\n\n";
    
    DebugFrameParser parser(argv[1]);
    parser.printFrameTable();
    
    return 0;
}