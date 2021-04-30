#include "ebpfOptions.h"
#include "midend.h"


EbpfOptions::EbpfOptions() {
        langVersion = CompilerOptions::FrontendVersion::P4_16;
        registerOption("--listMidendPasses", nullptr,
                [this](const char*) {
                    loadIRFromJson = false;
                    listMidendPasses = true;
                    EBPF::MidEnd midend;
                    midend.run(*this, nullptr, outStream);
                    exit(0);
                    return false; },
                "[ebpf back-end] Lists exact name of all midend passes.\n");
        registerOption("--fromJSON", "file",
                [this](const char* arg) { loadIRFromJson = true; file = arg; return true; },
                "Use IR representation from JsonFile dumped previously,"
                "the compilation starts with reduced midEnd.");
        registerOption("--emit-externs", nullptr,
                [this](const char*) { emitExterns = true; return true; },
                "[ebpf back-end] Allow for user-provided implementation of extern functions.");
        registerOption("--trace", nullptr,
                [this](const char*) { emitTraceMessages = true; return true; },
                "Enable tracing of packet flow");
        registerOption("--xdp", nullptr,
                [this](const char*) { generateToXDP = true; return true; },
                "Compile and generate the P4 prog to XDP layer");
}
