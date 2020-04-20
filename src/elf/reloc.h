#ifndef EGALITO_RELOC_H
#define EGALITO_RELOC_H

#include <vector>
#include <map>
#include <string>
#include <elf.h>

#include "types.h"
#include "elf/elfmap.h"
#include "elf/elfxx.h"
#include "elf/riscv-elf.h"

class Symbol;
class SymbolList;

class Reloc {
public:
#ifdef ARCH_ARM
    typedef ElfXX_Half  rel_type_t;
    typedef ElfXX_Half  rel_sym_t;
    typedef ElfXX_Sword rel_addend_t;
#else
    typedef ElfXX_Word   rel_type_t;
    typedef ElfXX_Word   rel_sym_t;
    typedef ElfXX_Sxword rel_addend_t;
#endif
private:
    address_t address;      // source address
    rel_type_t type;        // type
    rel_sym_t symbolIndex;  // target index
    Symbol *symbol;         // target
    rel_addend_t addend;    // for RELA relocs
public:
    Reloc(address_t address, rel_type_t type, rel_sym_t symbolIndex,
        Symbol *symbol, rel_addend_t addend)
        : address(address), type(type), symbolIndex(symbolIndex),
        symbol(symbol), addend(addend) {}

    address_t getAddress() const { return address; }
    rel_type_t getType() const { return type; }
    Symbol *getSymbol() const { return symbol; }
    rel_addend_t getAddend() const { return addend; }

    std::string getSymbolName() const;
};

class RelocSection {
private:
    typedef std::vector<Reloc *> ListType;
    ListType relocList;
    std::string name;
    int infoLink;
public:
    RelocSection(const std::string &name, int infoLink = 0)
        : name(name), infoLink(infoLink) {}

    void add(Reloc *reloc);
    int getInfoLink() const { return infoLink; }

    ListType::iterator begin() { return relocList.begin(); }
    ListType::iterator end() { return relocList.end(); }
};

class RelocList {
private:
    typedef std::vector<Reloc *> ListType;
    ListType relocList;
    typedef std::map<address_t, Reloc *> MapType;
    MapType relocMap;
    typedef std::map<std::string, RelocSection *> SectionListType;
    SectionListType sectionList;
public:
    bool add(Reloc *reloc);

    ListType::iterator begin() { return relocList.begin(); }
    ListType::iterator end() { return relocList.end(); }

    Reloc *find(address_t address);
    Reloc *find(const char *name);

    RelocSection *getSection(const std::string &name);

    static RelocList *buildRelocList(ElfMap *elfmap, SymbolList *symbolList,
        SymbolList *dynamicSymbolList = nullptr);
private:
    RelocSection *makeOrGetSection(const std::string &name, ElfXX_Shdr *s);
};

#endif
