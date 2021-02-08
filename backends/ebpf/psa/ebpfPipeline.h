#ifndef P4C_EBPFPIPELINE_H
#define P4C_EBPFPIPELINE_H

#include "backends/ebpf/ebpfProgram.h"

namespace EBPF {

/*
 * EBPFPipeline represents a single eBPF program in the TC/XDP hook.
 * A single pipeline is composed of Parser, Control block and Deparser.
 * EBPFPipeline inherits from EBPFProgram, but extends it with deparser and other PSA-specific objects.
 */
class EBPFPipeline : public EBPFProgram {
 public:
    const cstring name;
    // TODO: add deparser
    //EBPFDeparser* deparser;

    EBPFPipeline(cstring name, const EbpfOptions& options, P4::ReferenceMap* refMap, P4::TypeMap* typeMap) :
                 EBPFProgram(options, nullptr, refMap, typeMap, nullptr), name(name) {
        functionName = name;
    }

    void emit(CodeBuilder* builder);
};

}

#endif //P4C_EBPFPIPELINE_H
