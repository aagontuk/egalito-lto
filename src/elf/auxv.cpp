#include <cstring>
#include <iostream>
#include <assert.h>
#include <elf.h>
#include "auxv.h"
#include "elfxx.h"
#include "log/log.h"

static address_t *findAuxiliaryVector(char **argv) {
    address_t *address = reinterpret_cast<address_t *>(argv);

    //address ++;  // skip argc
    while(*address++) {}  // skip argv entries
    while(*address++) {}  // skip envp entries

    return address;
}

void adjustAuxiliaryVector(char **argv, ElfMap *elf, ElfMap *interpreter) {
    if(!elf) return;
    ElfMap *beginning = (interpreter ? interpreter : elf);
    ElfXX_Ehdr *header = (ElfXX_Ehdr *)elf->getCharmap();

    address_t *auxv = findAuxiliaryVector(argv);

    CLOG(0, "fixing auxiliary vector");

    // Loop through all auxiliary vector entries, stopping at the terminating
    // entry of type AT_NULL.
    for(address_t *p = auxv; p[0] != AT_NULL; p += 2) {
        address_t type = p[0];
        address_t *new_value = &p[1];
        switch(type) {
        case AT_BASE:
            *new_value = reinterpret_cast<address_t>(beginning->getCharmap());
            CLOG(1, "    auxv base address: 0x%lx", *new_value);
            break;
        case AT_ENTRY:
            *new_value = beginning->getBaseAddress()
                + beginning->getEntryPoint();
            CLOG(1, "    auxv entry point: 0x%lx", *new_value);
            break;
        case AT_PHDR:
            *new_value = reinterpret_cast<address_t>(elf->getCharmap())
                + header->e_phoff;
            break;
        case AT_PHENT:
            *new_value = header->e_phentsize;
            break;
        case AT_PHNUM:
            *new_value = header->e_phnum;
            break;
#if 0
        case AT_EXECFN:
            static const char *fakeFilename
                = "./hello";
            std::printf("AUXV: old exec filename is [%s]\n",
                reinterpret_cast<char *>(*new_value));
            *new_value = reinterpret_cast<address_t>(fakeFilename);
            std::printf("AUXV: new exec filename is [%s]\n",
                reinterpret_cast<char *>(*new_value));
            break;
#endif
        default:
            break;
        }
    }
}

int removeLoaderFromArgv(void *argv, int remove_count) {
    unsigned long *argc = (unsigned long *)argv - 1;
    //int remove_count = 1;  // number of arguments to remove

    LOG(5, "Original command-line arguments:");
    for(int i = 0; i < (int)*argc; i ++) {
        CLOG(5, "    argv[%d] = \"%s\"%s", i,
            (char *) *(unsigned long *)((char *)argv + i*8),
            i >= remove_count ? "" : "\t[removing]");
    }

#ifdef ARCH_X86_64
    // move argc, overwriting arguments to be erased, and adjust %rsp
    *(argc + remove_count) = (*argc) - remove_count;
    return sizeof(unsigned long) * remove_count;
#elif defined(ARCH_AARCH64) || defined(ARCH_ARM)
    // AARCH64 ABI requires the stack to be 16 Bytes aligned between calls
    address_t *auxv = findAuxiliaryVector((char **)argv);
    address_t *p;
    for(p = auxv; p[0] != AT_NULL; p += 2) { }

    *(argc) = (*argc) - remove_count;
    size_t newSize = (char *)p - (char *)argv - remove_count*8;
    std::memmove(argv, (char *)argv + remove_count*8, newSize);
    *(unsigned long *)((char *)argv + newSize) = 0;
    return 0;
#elif defined(ARCH_RISCV)
    assert(0); // XXX: no idea for now
    return 0;
#endif
}
