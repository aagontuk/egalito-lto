#include <iostream>
#include <cstdio>
#include "disassemble.h"
#include "dump.h"

void ChunkDumper::visit(Function *function) {
    std::cout << "---[" << function->getName() << "]---\n";
    recurse(function);
}

void ChunkDumper::visit(Block *block) {
    std::cout << ".block:\n";
    recurse(block);
}

void ChunkDumper::visit(Instruction *instruction) {
    const char *target = nullptr;
    auto pos = dynamic_cast<RelativePosition *>(instruction->getPosition());
    cs_insn *ins = instruction->getSemantic()->getCapstone();

    std::printf("    ");

    if(!ins) {
        if(auto p = dynamic_cast<ControlFlowInstruction *>(instruction->getSemantic())) {

            auto link = p->getLink();
            auto target = link ? link->getTarget() : nullptr;

            std::printf("0x%08lx <+%lu>:\t%s\t\t0x%lx <%s>\n",
                instruction->getAddress(),
                pos ? pos->getOffset() : 0,
                "(CALL)",
                link ? link->getTargetAddress() : 0,
                target ? target->getName().c_str() : "???");
        }
        else std::printf("...unknown...\n");
        return;
    }

    // !!! we shouldn't need to modify the addr inside a dump function
    // !!! this is just to keep the cs_insn up-to-date
    ins->address = instruction->getAddress();
    if(pos) {
        Disassemble::printInstructionAtOffset(ins, pos->getOffset(), target);
    }
    else {
        Disassemble::printInstruction(ins, target);
    }
}
