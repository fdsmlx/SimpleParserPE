#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <type_traits>
#include <cstdint>

struct ImportDescriptor {
    uint32_t originalFirstThunk;  // RVA to array of RVA function names (INT)
    uint32_t timeDateStamp;       // Timestamp
    uint32_t forwarderChain;      // Forwarder chain
    uint32_t name;                // RVA to DLL name (string)
    uint32_t firstThunk;          // RVA to array of function addresses (IAT)
};

struct SectionHeader {
    char name[8];
    uint32_t virtualSize;
    uint32_t virtualAdress;
    uint32_t sizeOfRawData;
    uint32_t pointerToRawData;
    uint32_t pointerToRelocations;
    uint32_t pointerToLinenumbers;
    uint16_t numberOfRelocations;
    uint16_t numberOfLinenumbers;
    uint32_t characteristics;
};

struct DataDirectory {
    uint32_t virtualAdress;
    uint32_t size;
};

struct OptionalHeader32 {
    uint16_t magic;
    uint8_t majorLinkerVersion;
    uint8_t minorLinkerVersion;
    uint32_t sizeOfCode;
    uint32_t sizeOfInitializedData;
    uint32_t sizeOfUninitializedData;
    uint32_t adressOfEntryPoint;
    uint32_t baseOfCode;
    uint32_t baseOfData;
    uint32_t imageBase;
    uint32_t sectionAlignment;
    uint32_t fileAlignment;
    uint16_t majorOperatingSystemVersion;
    uint16_t minorOperatingSystemVersion;
    uint16_t majorImageVersion;
    uint16_t minorImageVersion;
    uint16_t majorSubsystemVersion;
    uint16_t minorSubsystemVersion;
    uint32_t win32VersionValue;
    uint32_t sizeOfImage;
    uint32_t sizeOFHeaders;
    uint32_t checkSum;
    uint16_t subsystem;
    uint16_t dllCharacteristics;
    uint32_t sizeOfStackReserve;
    uint32_t sizeOfStackCommit;
    uint32_t sizeOfHeapReserve;
    uint32_t sizeOfHeapCommit;
    uint32_t loaderFlags;
    uint32_t numberOfRvaAndSizes;

    DataDirectory dataDirectory[16]; 
};

struct FileHeader {
    uint16_t machine;
    uint16_t numberOfSections;
    uint32_t timeDateStamp;
    uint32_t pointerToSymbolTable;
    uint32_t numberOfSymbols;
    uint16_t sizeOfOptionalHeader;
    uint16_t characteristics;
};

struct NTHeader {
    uint32_t signature;
};

struct DOSHeader {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};

// Template for different types (uint16, uint32, etc.)
template<typename T>
std::string toHex(const T& num) {
    std::stringstream s;
    s << std::hex << std::uppercase << num;
    return s.str();
}

// Expected exactly 8 bytes
std::string sectionNameToString(const char name[8]) {
    return std::string(name, 8);
}

// File Offset = (RVA - Section.VirtualAddress) + Section.PointerToRawData
uint32_t rvaToFileOffset(uint32_t rva, const std::vector<SectionHeader>& sections) {
    for (const auto& section : sections) {
        if (rva >= section.virtualAdress && rva < section.virtualAdress + section.virtualSize) {
            return (rva - section.virtualAdress) + section.pointerToRawData;
        }
    }
    return 0;
}

std::string readString(std::ifstream& file, uint32_t fileOffset) {
    auto oldPos = file.tellg();

    file.seekg(fileOffset, std::ios::beg);

    std::string result;
    char ch;
    while (file.get(ch) && ch != '\0') {
        result += ch;
    }

    file.seekg(oldPos);

    return result;
}


int main() {
    DOSHeader dos;
    NTHeader ntheader;
    FileHeader fileheader;
    OptionalHeader32 optionalheader;
    std::ifstream file("HxD32.exe", std::ios::binary);
    if (file.is_open()) {    
        file.read(reinterpret_cast<char*>(&dos), sizeof(dos));
        if (dos.e_magic == 0x5A4D) {
            std::cout << "Valid PE file (MZ signature found)" << std::endl;
            std::cout << toHex(dos.e_lfanew) << " Offset NT Header" << std::endl;
            // Jump to offset in e_lfanew (NTHeader)
            file.seekg(dos.e_lfanew, std::ios::beg);
            file.read(reinterpret_cast<char*>(&ntheader.signature), sizeof(ntheader.signature));
            if (ntheader.signature == 0x4550) {
                std::cout << "PE signature verifed!" << std::endl;
                file.read(reinterpret_cast<char*>(&fileheader), sizeof(fileheader));
                std::cout << "======File Header======" << std::endl;
                std::cout << "Number of Sections: " << fileheader.numberOfSections << std::endl;
                std::cout << "Machine: " << toHex(fileheader.machine) << std::endl;
                std::cout << "Characteristics: " << toHex(fileheader.characteristics) << std::endl;
                file.read(reinterpret_cast<char*>(&optionalheader), sizeof(optionalheader));
                std::cout << "======Optional Header32======" << std::endl;
                std::cout << "Entry Point: " << toHex(optionalheader.adressOfEntryPoint) << std::endl;
                std::cout << "Image Base: " << toHex(optionalheader.imageBase) << std::endl;
                std::cout << "Section Alignment: " << toHex(optionalheader.sectionAlignment) << std::endl;
                std::cout << "File Alignment: " << toHex(optionalheader.fileAlignment) << std::endl;
                std::cout << "Size of Image: " << toHex(optionalheader.sizeOfImage) << std::endl;
                std::cout << "Subsystem: " << toHex(optionalheader.subsystem) << std::endl;
                std::cout << "========Import Table========" << std::endl;
                std::cout << "RVA: " << toHex(optionalheader.dataDirectory[1].virtualAdress) << std::endl;
                std::cout << "Size: " << toHex(optionalheader.dataDirectory[1].size) << std::endl;
                std::vector<SectionHeader> sections(fileheader.numberOfSections);
                std::cout << "=======Section Headers=======" << std::endl;
                for (size_t i = 0; i < fileheader.numberOfSections; ++i) {
                    file.read(reinterpret_cast<char*>(&sections[i]), sizeof(SectionHeader));
                    std::cout << "Name: " << sectionNameToString(sections[i].name) << std::endl;
                    std::cout << "Virtual Size: " << toHex(sections[i].virtualSize) << std::endl;
                    std::cout << "Virtual Address: " << toHex(sections[i].virtualAdress) << std::endl;
                    std::cout << "Size of Raw Data: " << toHex(sections[i].sizeOfRawData) << std::endl;
                    std::cout << "Pointer to Raw Data: " << toHex(sections[i].pointerToRawData) << std::endl;
                    std::cout << "Characteristics: " << toHex(sections[i].characteristics) << std::endl;
                    std::cout << "------------------------" << std::endl;
                }

                // Working with Import Table
                uint32_t importRVA = optionalheader.dataDirectory[1].virtualAdress;
                uint32_t importOffset = rvaToFileOffset(importRVA, sections);

                std::cout << "Import Table RVA: 0x" << toHex(importRVA) << std::endl;
                std::cout << "Import Table File Offset: 0x" << toHex(importOffset) << std::endl;

                // Jump to ImportOffset
                file.seekg(importOffset, std::ios::beg);
                std::cout << "======Import Table (DLLs)======" << std::endl;
                while (true) {
                    ImportDescriptor desc;
                    file.read(reinterpret_cast<char*>(&desc), sizeof(desc));

                    if (desc.name == 0) break;

                    // DLL name
                    uint32_t nameOffset = rvaToFileOffset(desc.name, sections);
                    std::string dllName = readString(file, nameOffset);
                    std::cout << dllName << std::endl;

                    // SAVE MAIN LOOP POSITION!
                    auto descPos = file.tellg();

                    // Parse functions
                    uint32_t thunkArrayOffset = rvaToFileOffset(desc.originalFirstThunk, sections);
                    file.seekg(thunkArrayOffset);
                    
                    std::cout << "  Functions:" << std::endl;
                    while (true) {
                        uint32_t thunkData;
                        file.read(reinterpret_cast<char*>(&thunkData), sizeof(thunkData));
                        
                        if (thunkData == 0) break;
                        
                        if (thunkData & 0x80000000) {
                            uint16_t ordinal = thunkData & 0xFFFF;
                            std::cout << "    - Ordinal #" << ordinal << std::endl;
                        } else {
                            uint32_t nameRVA = thunkData;
                            uint32_t nameOffset = rvaToFileOffset(nameRVA, sections);

                            auto thunkPos = file.tellg();  // Position in thunk array

                            file.seekg(nameOffset);
                            uint16_t hint;
                            file.read(reinterpret_cast<char*>(&hint), 2);

                            std::string funcName;
                            char ch;
                            while (file.get(ch) && ch != '\0') {
                                funcName += ch;
                            }

                            std::cout << "    - " << funcName << std::endl;

                            file.seekg(thunkPos);  // Back to thunk array
                        }
                    }

                    // BACK TO IMPORT DESCRIPTORS ARRAY!
                    file.seekg(descPos);
                }
                
            } else {
                std::cout << "Signature PE failed!" << std::endl;
            }
        } else {
            std::cout << "Invalid File" << std::endl;
        }
    } else {
        std::cout << "Cannot open file" << std::endl;
    }
    return 0;
}