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

    void parse1() {
        _ptr = _data;
        int fde_count = 0;
        
        std::cout << "Parsing .debug_frame section:\n\n";
        
        while (true) {
            u32 initial_length = get32();
            u64 length;
            u64 cie_id;
            const char* entry_start;
            if (initial_length == 0) {
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
                // This is a CIE
                // _ptr = entry_start;
                parseDebugCie(length, entry_start);
            } else {
                // This is an FDE
                _ptr = entry_start;
                parseDebugFde(entry_start, length, cie_id);
            }
        }
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

    void DwarfParser::parseDebugCie(u64 length, const char* entry_start) {
        uint8_t version = get8();
        std::cout << "  Version: " << (int)version << "\n";
        
        // Augmentation string
        while (*_ptr++) {}
        // std::cout << "  Augmentation: \"" << aug_start << "\"\n";
        if (version >= 4) {
            // skip address_size
            get8();
            // skip segment_size
            get8();
        }
        _code_align = getLeb();
        _data_align = getSLeb();
        _ptr = entry_start + length;
    }
    
    void DwarfParser::parseDebugFde(const char* entry_start, u64 length, u64 cie_offset) {
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
        
        parseInstructions(initial_location, entry_start + length);
        addRecord(initial_location + address_range, DW_REG_FP, LINKED_FRAME_SIZE, -LINKED_FRAME_SIZE, -LINKED_FRAME_SIZE + DW_STACK_SLOT);
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