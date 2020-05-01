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
    scanRelativeInstructions();
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

void TextSection::scanRelativeInstructions() {
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
            if(std::string(insn[j].mnemonic) == "call" || strstr(insn[j].op_str, "rip")) {
                
                address_t addr = insn[j].address;
                uint8_t firstByte = insn[j].bytes[0];
                
                // Some instruction sizes are wrong
                // Is there any instruction lengh greater than 7?
                int size;
                if(insn[j].size > 7){
                    size = 7; 
                }
                else {
                    size = insn[j].size; 
                }
                
                if(strstr(insn[j].op_str, "rip")) {
                    uint32_t *offset;

                    if(firstByte == 0x48 || firstByte == 0x4c) {
                        
                        offset = (uint32_t *)(sourceElfMap->getCharmap() + 
                            insn[j].address + 3);
                    }
                    else {
                        offset = (uint32_t *)(sourceElfMap->getCharmap() + 
                            insn[j].address + 2);
                    }

                    address_t funcAddress = (int)*offset + addr + size;

                    const char *funcName = "";
                    
                    if(funcAddress <= endAddress) {
                        Symbol *sym = symbols->find(funcAddress);
                        if(sym) {
                            funcName = sym->getName(); 
                        }    
                    }
                    
                    RelativeInstruction *ripInsn = new RelativeInstruction(funcName, addr,
                            *offset, RelativeInstruction::RIP);
                    ripInsn->setInstructionSize(size);
                    ripInsn->setFirstByte(firstByte);

                    if(ripInsn) {
                        auto fn = searchFunctionByAddress(addr); 
                        if(fn) fn->addInstruction(ripInsn);
                    }
                }
                else {
                    uint32_t *offset = (uint32_t *)(sourceElfMap->getCharmap() + 
                            insn[j].address + size - 4);
                    address_t funcAddress = (int)*offset + addr + size;
                    
                    /* Is the call offset pointing to PLT section? */
                    if(funcAddress >= pltStart && funcAddress <= pltEnd) {
                        RelativeInstruction *pltCall = new RelativeInstruction("plt", addr,
                                *offset, RelativeInstruction::PLTCALL);
                        
                        if(pltCall) {
                            auto fn = searchFunctionByAddress(addr); 
                            if(fn) fn->addInstruction(pltCall);
                        }
                    }
                    else {
                        Symbol *sym = symbols->find(funcAddress);
                        if(sym) {
                            const char *funcName = sym->getName();
                            RelativeInstruction *normCall = new RelativeInstruction(funcName,
                                    addr, 0, RelativeInstruction::CALL);
                            if(normCall) {
                                auto fn = searchFunctionByAddress(addr); 
                                if(fn) fn->addInstruction(normCall);
                            }

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

        int offset = 0;
        
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
    fixRelativeInstructions();
    fixEntryPoint();

    // Dump the elf
    sourceElfMap->dumpToFile("reordered_binary");
    
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

void TextSection::fixRelativeInstructions() {
    char *elfmap = sourceElfMap->getCharmap();

    for(auto fn : functionList) {
        for(auto call : fn->getInstructionList()) {
            if(call->getType() == RelativeInstruction::PLTCALL) {
                int offset = fn->getOffsetChange();
                if(offset) {
                    call->setAddress(call->getAddress() + offset);
                    call->setOffset(call->getOffset() - offset);
                    uint32_t *newOffset = (uint32_t *)(elfmap + call->getAddress() + 1);
                    *newOffset = call->getOffset();
                } 
            }
            else if(call->getType() == RelativeInstruction::CALL) {
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
            else {
                int offset = fn->getOffsetChange();
                
                if(offset || call->getCallingFunctionName() != "") {
                    // Old next instruction address
                    address_t oldNextInsAddress = call->getAddress() +
                        call->getInstructionSize();
                    
                    // Adjust address according to offset change
                    call->setAddress(call->getAddress() + offset);
                    
                    // New next instruction address
                    address_t nextInsAddress = call->getAddress() + 
                        call->getInstructionSize();
                    
                    uint8_t firstByte = call->getFistByte();
                    uint32_t *newOffset;
                    
                    if(firstByte == 0x4c || firstByte == 0x48) {
                        newOffset = (uint32_t *)(elfmap + call->getAddress() + 3); 
                    }
                    else {
                        newOffset = (uint32_t *)(elfmap + call->getAddress() + 2); 
                    }
                    
                    if(call->getCallingFunctionName() != "") {
                        Symbol *sym = symbols->find(call->getCallingFunctionName().c_str());
                        
                        if(sym) {
                            *newOffset = sym->getAddress() - nextInsAddress;
                        }
                    }
                    else {
                        *newOffset = *newOffset - offset;
                    }
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
