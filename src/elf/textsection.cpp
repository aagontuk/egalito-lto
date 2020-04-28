#include <iostream>
#include <string>
#include <cstring>
#include <algorithm>
#include <capstone/capstone.h>
#include "textsection.h"

TextSection::TextSection(ElfMap *sourceElfMap): sourceElfMap(sourceElfMap){
    textSection = sourceElfMap->findSection(".text");

    // Calculate section start and end
    startAddress = textSection->getStartOffset();
    endAddress = textSection->getEndOffset();

    // Create symbol list
    symbols = SymbolList::buildSymbolList(sourceElfMap);
    dynSymbols = SymbolList::buildDynamicSymbolList(sourceElfMap);

    // Find entry symbol
    ElfXX_Ehdr *ehdr = (ElfXX_Ehdr *)(sourceElfMap->getMap());
    entrySymbol = symbols->find(ehdr->e_entry);
    
    std::cout << "Entry Symbol: " << this->getEntrySymbol()->getName() << std::endl;
    std::cout << "Symbol Address: " << std::hex << this->getEntrySymbol()->getAddress() << std::endl;
        
    getUnorderedFunctionList();
    sortFunctionList();
    calcFunctionEndAddress();
    scanCallInstructions();
}

TextSection::~TextSection() {
    for(auto fn : functionList) {
        delete fn; 
    }
}

void TextSection::getUnorderedFunctionList() {
    for(auto s = symbols->begin(); s != symbols->end(); s++){
        if((*s)->getType() == Symbol::TYPE_FUNC){
            if(((*s)->getAddress() >= startAddress) && ((*s)->getAddress() <= endAddress)){
                TextFunction *tfunc = new TextFunction((*s)->getName(), (*s)->getAddress(), 0);
                functionList.push_back(tfunc);
            }
        } 
    }
}

bool TextSection::comp(TextFunction *tf1, TextFunction *tf2) {
    return tf1->getStartAddress() < tf2->getStartAddress();
}


void TextSection::sortFunctionList() {
    sort(functionList.begin(), functionList.end(), comp);
}

void TextSection::calcFunctionEndAddress() {
    auto it = functionList.begin();

    for(; it != functionList.end(); ++it){
        if((it+1) == functionList.end()){
            auto curFunc = *it;
            curFunc->setEndAddress(endAddress);
        }
        else{
            auto curFunc = *it;
            auto nextFunc = *(it + 1);
            curFunc->setEndAddress(nextFunc->getStartAddress() - 1);
        } 
    }
}

void TextSection::scanCallInstructions() {
    ElfSection *pltSection = sourceElfMap->findSection(".plt");
    address_t pltStart = pltSection->getStartOffset();
    address_t pltEnd = pltSection->getEndOffset();

    csh handle;
    cs_insn *insn;
    size_t count;

    if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        throw "capstone open error";

    count = cs_disasm(handle,
               reinterpret_cast<const uint8_t *>(sourceElfMap->getCharmap()) + startAddress,
               endAddress - startAddress, startAddress, 0, &insn);

    if(count > 0) {
        size_t j; 
        
        for(j = 0; j < count; j++) {
            if(std::string(insn[j].mnemonic) == "call") {
                uint32_t *offset = (uint32_t *)(sourceElfMap->getCharmap() + insn[j].address + 1);
                address_t addr = insn[j].address;
                address_t funcAddress = (int)*offset + addr + 5;


                /* Is the call offset pointing to PLT section? */
                if(funcAddress >= pltStart && funcAddress <= pltEnd) {
                    CallInstruction *pltCall = new CallInstruction("plt", addr, *offset, true);
                    if(pltCall) {
                        auto fn = searchFunctionByAddress(addr); 
                        if(fn) fn->addCall(pltCall);
                    }
                }
                else {
                    Symbol *sym = symbols->find(funcAddress);
                    if(sym) {
                        const char *funcName = sym->getName();
                        CallInstruction *normCall = new CallInstruction(funcName, addr, 0);
                        if(normCall) {
                            auto fn = searchFunctionByAddress(addr); 
                            if(fn) fn->addCall(normCall);
                        }

                    }
                }
            }
        }

        cs_free(insn, count);
    }
    else {
        cs_close(&handle);
        throw "failed to disassemble"; 
    }

    cs_close(&handle);
}

TextFunction *TextSection::searchFunctionByName(std::string name){
    for(auto it = functionList.begin(); it != functionList.end(); it++){
        if((*it)->getName() == name){
            return *it; 
        } 
    }

    return nullptr;
}

TextFunction *TextSection::searchFunctionByAddress(address_t addr) {
    for(auto fn : functionList) {
        if(addr >= fn->getStartAddress() && addr <= fn->getEndAddress()) {
            return fn; 
        }
    }

    return nullptr;
}

void TextSection::reorder(std::vector<std::string> orderList) {
    char *elfmap = sourceElfMap->getCharmap();
    char *newTextSection = new char[textSection->getSize()];
    int bytesWritten = 0;
    
    for(auto l : orderList) {
        TextFunction *tf = searchFunctionByName(l);
        int fsize = tf->getEndAddress() - tf->getStartAddress() + 1;
        
        memcpy(newTextSection + bytesWritten, elfmap + tf->getStartAddress(), fsize);

        int offset;
        
        if(!bytesWritten) {
            offset = this->startAddress - tf->getStartAddress();
            tf->setStartAddress(this->startAddress);
            tf->setEndAddress(this->startAddress + fsize - 1);
        }
        else {
            offset = (this->startAddress + bytesWritten) - tf->getStartAddress();
            tf->setStartAddress(this->startAddress + bytesWritten);
            tf->setEndAddress(tf->getStartAddress() + fsize - 1);
        }

        tf->setOffsetChange(offset);

        bytesWritten += fsize;
    }

    sortFunctionList();
    
    memcpy(elfmap + startAddress, newTextSection, bytesWritten);

    updateSymbols();
    fixCallInstructions();
    fixEntryPoint();
    
    delete[] newTextSection;
}

void TextSection::updateSymbols() {
    Symbol *s;
    for(auto f: functionList) {
        s = symbols->find(f->getName());

        if(s && s->getAddress() != f->getStartAddress()){
            s->setAddress(f->getStartAddress());
            s->updateElfMap(sourceElfMap, 0);
        }

        s = dynSymbols->find(f->getName());
        
        if(s && s->getAddress() != f->getStartAddress()){
            s->setAddress(f->getStartAddress());
            s->updateElfMap(sourceElfMap, 1);
        }
    }    
}

void TextSection::fixCallInstructions() {
    char *elfmap = sourceElfMap->getCharmap();

    for(auto fn : functionList) {
        for(auto call : fn->getCallList()) {
            if(call->isPltCall()) {
                int offset = fn->getOffsetChange();
                if(offset) {
                    call->setAddress(call->getAddress() + offset);
                    call->setOffset(call->getOffset() - offset);
                    uint32_t *newOffset = (uint32_t *)(elfmap + call->getAddress() + 1);
                    *newOffset = call->getOffset();
                } 
            }
            else {
                int offset = fn->getOffsetChange();
                if(offset) {
                    call->setAddress(call->getAddress() + offset);
                }

                Symbol *sym = symbols->find(call->getCallingFunctionName().c_str());
                if(sym) {
                    offset = sym->getAddress() - (call->getAddress() + 5);
                    uint32_t *newOffset = (uint32_t *)(elfmap + call->getAddress() + 1);
                    *newOffset = offset;
                }
            }
        } 
    }
}

void TextSection::fixEntryPoint() {
    ElfXX_Ehdr *ehdr = (ElfXX_Ehdr *)(sourceElfMap->getMap());
    ehdr->e_entry = this->getEntrySymbol()->getAddress();
}

void TextSection::printHex(const char *content, int length){
    const unsigned char *ucontent = (const unsigned char *)content;
    for(int i = 0; i < length; i++){
        if(i < (length - 1)){
            std::cout << std::hex << static_cast<int>(ucontent[i]) << " ";
        }
        else{
            std::cout << std::hex << static_cast<int>(ucontent[i]) << std::endl;
        }
    }
}
