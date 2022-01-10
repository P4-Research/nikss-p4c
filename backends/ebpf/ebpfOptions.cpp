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
                "[psa] Compile and generate the P4 prog to XDP layer");
        registerOption("--xdp2tc", "MODE",
                [this](const char* arg) {
                    if (!strcmp(arg, "meta")) {
                        xdp2tcMode = XDP2TC_META;
                    } else if (!strcmp(arg, "head")) {
                        xdp2tcMode = XDP2TC_HEAD;
                    } else if (!strcmp(arg, "cpumap")) {
                        xdp2tcMode = XDP2TC_CPUMAP;
                    }
                    return true;
                },
                "[psa] Select the mode used to pass metadata from XDP to TC.");
        registerOption("--table-caching", nullptr,
                [this](const char *) { enableTableCache = true; return true; },
                "[psa] Enable caching entries for tables with lpm or ternary key");
        registerOption("--max-ternary-masks", "MAX_MASK",
                [this](const char *arg) {
                    unsigned int parsed_val = std::strtoul(arg, nullptr, 0);
                    if (parsed_val >= 2)
                        this->maxTernaryMasks = parsed_val;
                    return true;
                },
                "[psa] Set number of maximum possible masks for ternary key in a single table");
        registerOption("--pipeline-opt", nullptr,
                       [this](const char*) { pipelineOptimization = true; return true; },
                       "Optimize the packet processing by leveraging clever data sharing "
                       "and pipeline awareness.");
}
