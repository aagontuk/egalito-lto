#ifndef EGALITO_TEXT_SECTION_H
#define EGALITO_TEXT_SECTION_H

#include <vector>
#include <string>
#include "elfmap.h"
#include "symbol.h"
#include "reloc.h"
#include "types.h"

class CallInstruction;
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
    void scanCallInstructions();
    
    void updateSymbols();
    void fixCallInstructions();
    void fixEntryPoint();
    
    void printHex(const char *content, int length);
};

class TextFunction {
private:
    const char *name;
    address_t startAddress;
    address_t endAddress;
    uint32_t offsetChange;
    std::vector<CallInstruction *> callList;

public:
    TextFunction(const char *name, address_t start, address_t end)
        : name(name), startAddress(start), endAddress(end), offsetChange(0) {}

    const char *getName(void) { return name; }
    address_t getStartAddress(void) { return startAddress; }
    address_t getEndAddress(void){ return endAddress; }
    uint32_t &getOffsetChange(void) { return offsetChange; }

    void setStartAddress(address_t addr) { startAddress = addr; }
    void setEndAddress(address_t addr) { endAddress = addr; }
    void setOffsetChange(uint32_t offcng) { offsetChange = offcng; }

    void addCall(CallInstruction *pltCall) { callList.push_back(pltCall); }
    std::vector<CallInstruction *> &getCallList() { return callList; }
};

class CallInstruction {
private:
    std::string callingFunctionName;
    address_t instructionAddress;
    uint32_t callOffset;
    bool isPLTCall;

public:
    CallInstruction(const char *name, address_t addr, uint32_t offset, bool isPlt = false)
        : callingFunctionName(name), instructionAddress(addr), callOffset(offset),
            isPLTCall(isPlt) {}

    std::string &getCallingFunctionName() { return callingFunctionName; }
    address_t getAddress() { return instructionAddress; }
    address_t getOffset() { return callOffset; }
    bool isPltCall() { return isPLTCall; }
    void setCallingFunctionName(std::string name) { callingFunctionName = name; }
    void setAddress(address_t addr) { instructionAddress = addr; }
    void setOffset(address_t offset) { callOffset = offset; }
};

#endif
