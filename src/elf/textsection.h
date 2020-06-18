#ifndef EGALITO_TEXT_SECTION_H
#define EGALITO_TEXT_SECTION_H

#include <vector>
#include <string>
#include "elfmap.h"
#include "symbol.h"
#include "reloc.h"
#include "types.h"

class RelativeInstruction;
class TextFunction;

class TextSection {
private:
    ElfMap *sourceElfMap;
    ElfSection *textSection;
    address_t startAddress;
    address_t endAddress;
    SymbolList *symbols;
    SymbolList *dynSymbols;
    Symbol *entrySymbol;
    RelocList *relalist;
    std::vector<TextFunction *> functionList;

private:
    TextSection();

public:
    TextSection(ElfMap *sourceElfMap);
    ~TextSection();

    address_t getStartAddress() { return startAddress; }
    address_t getEndAddress(){ return endAddress; }

    Symbol *getEntrySymbol() { return entrySymbol; }

    std::vector<TextFunction *> &getFunctionList() { return functionList; }
    TextFunction *searchFunctionByName(std::string name);
    TextFunction *searchFunctionByAddress(address_t addr);

    void reorder(std::vector<std::string> orderList);

private:
    void getUnorderedFunctionList();
    static bool comp(TextFunction *tf1, TextFunction *tf2);
    void sortFunctionList();
    void calcFunctionEndAddress();
    void scanRelativeInstructions();
    
    void updateSymbols();
    void fixRelativeInstructions();
    void patchCALLInstruction(char *elfmap, address_t addr, address_t sym_addr);
    
    void patchRIPInstruction(char *elfmap, address_t addr, std::string &insn,
                                uint32_t oldOffset, uint32_t newOffset);

    void encodeInstruction(std::string insn, unsigned char *bytes, size_t *size);
    
    void fixEntryPoint();
    
    void printHex(const char *content, int length);
};

class TextFunction {
private:
    const char *name;
    address_t startAddress;
    address_t endAddress;
    int offsetChange;
    std::vector<RelativeInstruction *> instructionList;

public:
    TextFunction(const char *name, address_t start, address_t end)
        : name(name), startAddress(start), endAddress(end), offsetChange(0) {}

    const char *getName(void) { return name; }
    address_t getStartAddress(void) { return startAddress; }
    address_t getEndAddress(void){ return endAddress; }
    int &getOffsetChange(void) { return offsetChange; }

    void setStartAddress(address_t addr) { startAddress = addr; }
    void setEndAddress(address_t addr) { endAddress = addr; }
    void setOffsetChange(int offcng) { offsetChange = offcng; }

    void addInstruction(RelativeInstruction *relIns) { instructionList.push_back(relIns); }
    std::vector<RelativeInstruction *> &getInstructionList() { return instructionList; }
};

class RelativeInstruction {
public:
    enum Type {
        CALL,
        RIP 
    };

private:
    address_t instructionAddress;
    std::string instructionAsm;
    int instructionSize;
    Type instructionType;
    uint32_t offset;
    std::string callingFunctionName;

public:
    RelativeInstruction() {}

    address_t getAddress() { return instructionAddress; }
    std::string &getInstructionAsm() { return instructionAsm; }
    int getInstructionSize() { return instructionSize; }
    Type getType() { return instructionType; }
    uint32_t getOffset() { return offset; }
    std::string &getCallingFunctionName() { return callingFunctionName; }
    
    void setAddress(address_t addr) { instructionAddress = addr; }
    void setInstructionAsm(std::string insnAsm) { instructionAsm = insnAsm; }
    void setInstructionSize(int size) { instructionSize = size; }
    void setType(Type type) { instructionType =type; }
    void setOffset(uint32_t off) { offset = off; }
    void setCallingFunctionName(std::string name) { callingFunctionName = name; }
};

#endif
