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
        PLTCALL,
        RIP 
    };

private:
    std::string callingFunctionName;
    address_t instructionAddress;
    uint32_t callOffset;
    Type instructionType;
    std::string mnemonic;
    int instructionSize;
    uint8_t firstByte;

public:
    RelativeInstruction(const char *name, address_t addr, uint32_t offset, Type type)
        : callingFunctionName(name), instructionAddress(addr), callOffset(offset),
            instructionType(type) {}

    Type getType() { return instructionType; }
    std::string &getMnemonic() { return mnemonic; }
    int getInstructionSize() { return instructionSize; }
    uint8_t &getFistByte() { return  firstByte; }
    address_t getAddress() { return instructionAddress; }
    address_t getOffset() { return callOffset; }
    std::string &getCallingFunctionName() { return callingFunctionName; }
    
    void setType(Type type) { instructionType =type; }
    void setMnemonic(std::string nc) { mnemonic = nc; }
    void setInstructionSize(int size) { instructionSize = size; }
    void setFirstByte(uint8_t byte) { firstByte = byte; }
    void setAddress(address_t addr) { instructionAddress = addr; }
    void setOffset(address_t offset) { callOffset = offset; }
    void setCallingFunctionName(std::string name) { callingFunctionName = name; }
};

#endif
