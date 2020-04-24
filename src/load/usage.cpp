#include <cstdio>
#include "usage.h"

#ifndef GIT_VERSION
    #define GIT_VERSION (unknown)
#endif

#define _STRINGIZE(x) # x
#define _STRINGIZE2(x) _STRINGIZE(x)

void printUsage(const char *exepath) {
    std::fprintf(stderr,
        "This is the Egalito loader version %s\n", _STRINGIZE2(GIT_VERSION));

    std::fprintf(stderr, "\n"
        "Usage: %s [options] -- executable [arguments...]\n"
        "    OR set the executable's program interpreter permanently with\n"
        "       /usr/bin/patchelf --set-interpreter %s executable\n",
        exepath, exepath);

    std::fprintf(stderr, "\n"
        "Options:\n" 
        "   -f, --function-order=FILE\n"
        "       FILE containing function orders of the binary\n");

    std::fprintf(stderr, "\n"
        "Debug options: EGALITO_DEBUG=/dev/null|(some/settings/file)|(setting)\n"
        "    where a setting may be e.g. load, load=2, !load\n"
        "    and a settings file contains one setting/filename per line\n");
}
