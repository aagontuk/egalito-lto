#ifndef EGALITO_LOAD_LOADER_H
#define EGALITO_LOAD_LOADER_H

#include "conductor/setup.h"

class EgalitoLoader {
private:
    ConductorSetup *setup;
    Sandbox *sandbox;
    int argc;
    char **argv;
    char **envp;
    bool fromArchive;
public:
    EgalitoLoader();
    bool parse(const char *filename);
    void *parseOrderFile(const char *executable, const char *orderfile);

    /* these must be called in this order */
    void setupEnvironment(int argc, int remove_count, char *argv[]);
    void generateCode();
    void run();
private:
    void otherPasses();
    void otherPassesAfterMove();
};

#endif
