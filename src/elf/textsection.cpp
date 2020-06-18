#include <iostream>
#include <string>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <capstone/capstone.h>
#include <keystone/keystone.h>
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
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    count = cs_disasm(handle,
               reinterpret_cast<const uint8_t *>(sourceElfMap->getCharmap()) + startAddress,
               endAddress - startAddress, startAddress, 0, &insn);

    if(count > 0) {
        size_t j; 
        
        for(j = 0; j < count; j++) {
            if(std::string(insn[j].mnemonic) == "call" || strstr(insn[j].op_str, "rip")) {
                std::string instruction(insn[j].mnemonic);
                instruction.append(" ");
                instruction.append(insn[j].op_str);

                RelativeInstruction *ripInsn = new RelativeInstruction();
                ripInsn->setAddress(insn[j].address);
                ripInsn->setInstructionAsm(instruction);
                ripInsn->setInstructionSize(insn[j].size);

                // immediate is assumed to be 32 bit this can be a problem in future
                uint32_t offset = 0;
                uint32_t imm = 0;
                address_t target = 0;

                // call instructions can have immediate value or can be relative
                if(std::string(insn[j].mnemonic) == "call") {
                    offset = insn[j].detail->x86.disp;
                    imm = insn[j].detail->x86.operands[0].imm;
                }
                else {
                    offset = insn[j].detail->x86.disp; 
                }

                // relative addressing
                if(offset) {
                    target = insn[j].address + insn[j].size + offset; 
                    ripInsn->setType(RelativeInstruction::RIP);
                    ripInsn->setOffset(offset);
                }
                else {  // direct addressing
                    target = imm; 
                    ripInsn->setType(RelativeInstruction::CALL);
                    ripInsn->setOffset(offset);
                }

                if(target >= pltStart && target <= pltEnd) {
                    ripInsn->setCallingFunctionName("plt");
                    ripInsn->setOffset(target);
                }
                else if(target <= endAddress) {
                    Symbol *sym = symbols->find(target);
                    
                    if(sym) {
                        ripInsn->setCallingFunctionName(sym->getName());
                    }    
                }
                else {
                    ripInsn->setCallingFunctionName(""); 
                }

                auto fn = searchFunctionByAddress(insn[j].address);
                if(fn) {
                    fn->addInstruction(ripInsn);
                }

                std::cout << "addr: " << ripInsn->getAddress() << std::endl;
                std::cout << "insn: " << ripInsn->getInstructionAsm() << std::endl;
                std::cout << "disp: " << offset << std::endl;
                std::cout << "immd: " << imm << std::endl;
                std::cout << "taddr: " << target << std::endl;
                std::cout << "tname: " << ripInsn->getCallingFunctionName() << "\n\n";
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
            std::cout << "func: " << l << std::endl;
            std::cout << std::hex << "oaddr: " << tf->getStartAddress() << std::endl;
            offset = this->startAddress - tf->getStartAddress();
            tf->setStartAddress(this->startAddress);
            tf->setEndAddress(this->startAddress + fsize - 1);
            std::cout << std::hex << "naddr: " << tf->getStartAddress() << std::endl;
            std::cout << std::hex << "ocng: " << offset << std::endl;
        }
        else {
            std::cout << "func: " << l << std::endl;
            std::cout << std::hex << "oaddr: " << tf->getStartAddress() << std::endl;
            offset = (this->startAddress + bytesWritten) - tf->getStartAddress();
            tf->setStartAddress(this->startAddress + bytesWritten);
            tf->setEndAddress(tf->getStartAddress() + fsize - 1);
            std::cout << std::hex << "naddr: " << tf->getStartAddress() << std::endl;
            std::cout << std::hex << "ocng: " << offset << std::endl;
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
        for(auto insn : fn->getInstructionList()) {

            // set new address of the instructions
            insn->setAddress(insn->getAddress() + fn->getOffsetChange());
            
            // CALL instructions that uses fixed address
            if(insn->getType() == RelativeInstruction::CALL) {
                
                // for plt calls offset is the distance from call instruction address to
                // plt entry address
                if(insn->getCallingFunctionName() == "plt") {
                    // patch code
                    patchCALLInstruction(elfmap, insn->getAddress(), insn->getOffset());
                }
                // for the other calls offet is the distance from current instruction to
                // calling symbol address
                else if(insn->getCallingFunctionName() != "plt" &&
                        insn->getCallingFunctionName() != "") {
                
                    Symbol *sym = symbols->find(insn->getCallingFunctionName().c_str());
                    if(sym) {
                       // patch code  
                       patchCALLInstruction(elfmap, insn->getAddress(), sym->getAddress());
                    }
                }  
            }
            // all instructions involving RIP
            else {
                if(insn->getCallingFunctionName() != "") {
                    Symbol *sym = symbols->find(insn->getCallingFunctionName().c_str());
                    if(sym) {
                        // patch code  
                        uint32_t offset = sym->getAddress() - (insn->getAddress()
                                            + insn->getInstructionSize());
                        
                        patchRIPInstruction(elfmap, insn->getAddress(),
                                insn->getInstructionAsm(), insn->getOffset(), offset);
                    }
                }
                else {
                    // patch code
                    uint32_t offset = insn->getOffset() - fn->getOffsetChange();
                    
                    patchRIPInstruction(elfmap, insn->getAddress(),
                            insn->getInstructionAsm(), insn->getOffset(), offset);
                }
            }
        } 
    }
}

void TextSection::patchRIPInstruction(char *elfmap, address_t addr, std::string &insn,
                                        uint32_t oldOffset, uint32_t newOffset) {

    std::stringstream oldOffset_ss;
    std::stringstream newOffset_ss;

    oldOffset_ss << std::hex << oldOffset;
    newOffset_ss << std::hex << newOffset;

    std::string new_insn(insn.replace(insn.find(oldOffset_ss.str()),
                oldOffset_ss.str().length(), newOffset_ss.str()));
    
    unsigned char *bytes;
    size_t size;
   
    bytes = (unsigned char *)malloc(15);
    encodeInstruction(new_insn, bytes, &size);
    memcpy(elfmap + addr, bytes, size);
    free(bytes);
}

void TextSection::patchCALLInstruction(char *elfmap, address_t addr, address_t sym_addr) {
    std::stringstream offset_ss;
    offset_ss << "call " << static_cast<long>(sym_addr) - static_cast<long>(addr);

    unsigned char *bytes;
    size_t size;
    
    bytes = (unsigned char *)malloc(15);
    encodeInstruction(offset_ss.str(), bytes, &size);
    memcpy(elfmap + addr, bytes, size);
    free(bytes);
}

void TextSection::encodeInstruction(std::string insn, unsigned char *bytes, size_t *size) {
    ks_engine *ks; 
    unsigned char *encode;
    size_t count;

    if(ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK) {
        throw "Can't open ksm engine!";
    }

    if(ks_asm(ks, insn.c_str(), 0, &encode, size, &count) != KS_ERR_OK) {
        throw "assembly failed!"; 
    }

    // What is wrong in allocating here?
    // bytes = (unsigned char *)malloc(*size);
    memcpy(bytes, encode, *size);
    
    ks_free(encode);
    ks_close(ks);
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
