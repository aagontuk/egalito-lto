#ifndef EGALITO_SYMBOL_H
#define EGALITO_SYMBOL_H

#include <cstddef>  // for size_t
#include <map>
#include <vector>
#include <string>
#include "types.h"
#include "elfxx.h"

class ElfMap;
class SharedLib;
class SymbolVersion;

/*class AbstractSymbol {
public:
    const char *getName() const { return name; }
    const SymbolVersion *getVersion() const { return version; }
    address_t getAddress() const { return address; }
    size_t getSize() const { return size; }
};*/

class Symbol {
public:
    enum SymbolType {
        TYPE_FUNC,
        TYPE_IFUNC,
        TYPE_OBJECT,
        TYPE_SECTION,
        TYPE_FILE,
        TYPE_TLS,
        TYPE_NOTYPE,
        TYPE_UNKNOWN
    };
    enum BindingType {
        BIND_LOCAL,
        BIND_GLOBAL,
        BIND_WEAK
    };
private:
    address_t address;
    size_t size;
    const char *name;
    SymbolVersion *version;
    Symbol *aliasFor;
    std::vector<Symbol *> aliasList;
    SymbolType symbolType;
    BindingType bindingType;
    size_t index;
    size_t shndx;
public:
    Symbol(address_t address, size_t size, const char *name,
           SymbolType sym, BindingType bind, size_t index, size_t shndx)
        : address(address), size(size), name(name), version(nullptr),
        aliasFor(nullptr), symbolType(sym), bindingType(bind), index(index),
        shndx(shndx) {}

    address_t getAddress() const { return address; }
    size_t getSize() const { return size; }
    const char *getName() const { return name; }
    const SymbolVersion *getVersion() const { return version; }
    SymbolType getType() const { return symbolType; }
    BindingType getBind() const { return bindingType; }
    Symbol *getAliasFor() const { return aliasFor; }
    size_t getSectionIndex() const { return shndx; }
    size_t getIndex() const { return index; }

    void setName(const char *name) { this->name = name; }
    void setSize(size_t size) { this->size = size; }
    void setAddress(address_t addr) { this->address = addr; }
    void setVersion(SymbolVersion *version) { this->version = version; }
    void setAliasFor(Symbol *aliasFor) { this->aliasFor = aliasFor; }
    void setType(SymbolType type) { this->symbolType = type; }

    void addAlias(Symbol *alias) { aliasList.push_back(alias); }

    const std::vector<Symbol *> &getAliases() const { return aliasList; }

    bool isFunction() const;
    bool isMarker() const;

    void updateElfMap(ElfMap *elfmap, int symtype);

public:
    static unsigned char typeFromInternalToElf(SymbolType type);
    static SymbolType typeFromElfToInternal(unsigned char type);
    static unsigned char bindFromInternalToElf(BindingType bind);
    static BindingType bindFromElfToInternal(unsigned char bind);
};

class SymbolVersion {
private:
    const char *name;
    bool hidden;    // means the default version to use
public:
    SymbolVersion(const char *name, bool hidden)
        : name(name), hidden(hidden) {}
    const char *getName() const { return name; }
    bool isHidden() const { return hidden; }
};

class SymbolVersionList {
private:
    std::vector<ElfXX_Versym> verList;          // indexed by symbolIndex
    std::map<size_t, const char *> nameList;    // indexed by versionIndex
public:
    SymbolVersionList(ElfMap *elfMap);

    const char *getVersionName(size_t symbolIndex) const;
    bool isHidden(size_t symbolIndex) const;

    void dump() const;

private:
    void addVersion(ElfXX_Versym ver)
        { verList.push_back(ver); }
    void addName(size_t i, const char *name)
        { nameList.emplace(i, name); }
    size_t getVersionIndex(size_t symbolIndex) const
        { return verList.at(symbolIndex) & ~0x8000; }
    bool hasVersionInfo() const { return verList.size() > 0; }
};

class SymbolList {
private:
    typedef std::vector<Symbol *> ListType;
    ListType symbolList;
    typedef std::vector<Symbol *> IndexMapType;
    IndexMapType indexMap;
    typedef std::map<std::string, Symbol *> MapType;
    MapType symbolMap;
    std::map<address_t, Symbol *> spaceMap;
    // elfmap this symbol list was built from. this may be a separate symbol elfmap.
    ElfMap *sourceElfMap;
public:
    SymbolList(ElfMap *sourceElfMap = nullptr) : sourceElfMap(sourceElfMap) {}
    virtual ~SymbolList() {}

    bool add(Symbol *symbol, size_t index);
    void addAlias(Symbol *symbol, size_t otherIndex);
    Symbol *get(size_t index);
    Symbol *find(const char *name);
    Symbol *find(address_t address);
    size_t getCount() const { return symbolList.size(); }

    ListType::iterator begin() { return symbolList.begin(); }
    ListType::iterator end() { return symbolList.end(); }

    ElfMap *getSourceElfMap() const { return sourceElfMap; }

    size_t estimateSizeOf(Symbol *symbol);

    virtual void buildMappingList() {}
    virtual Symbol *findMappingBelowOrAt(Symbol *symbol) { return nullptr; }
    virtual Symbol *findMappingAbove(Symbol *symbol) { return nullptr; }

    static SymbolList *buildSymbolList(ElfMap *elfMap, std::string symbolFile);
    static SymbolList *buildSymbolList(ElfMap *elfMap);
    static SymbolList *buildDynamicSymbolList(ElfMap *elfMap);
private:
    static SymbolList *buildAnySymbolList(ElfMap *elfMap,
        const char *sectionName, unsigned sectionType);
    static Symbol *findSizeZero(SymbolList *list, const char *sym);
};

class SymbolListWithMapping : public SymbolList {
private:
    std::vector<Symbol *> sortedMappingList;
public:
    using SymbolList::SymbolList;

    virtual void buildMappingList();
    virtual Symbol *findMappingBelowOrAt(Symbol *symbol);
    virtual Symbol *findMappingAbove(Symbol *symbol);
};

#endif
