#ifndef P4C_EBPFPIPELINE_H
#define P4C_EBPFPIPELINE_H

#include "backends/ebpf/ebpfProgram.h"

namespace EBPF_PSA {

/*
 * EBPFPipeline represents a single eBPF program in the TC/XDP hook.
 * A single pipeline is composed of Parser, Control block and Deparser.
 * EBPFPipeline inherits from EBPFProgram, but extends it with deparser and other PSA-specific objects.
 */
class EBPFPipeline : public EBPF::EBPFProgram {
 public:
    const cstring name;
    // TODO: add deparser
    //EBPFDeparser* deparser;

    EBPFPipeline(cstring name, const EbpfOptions& options, const IR::ToplevelBlock* toplevel, const IR::P4Program* program,
                 P4::ReferenceMap* refMap, P4::TypeMap* typeMap) :
                 EBPF::EBPFProgram(options, program, refMap, typeMap, toplevel), name(name) {
        functionName = name;
    }

    void emit(EBPF::CodeBuilder* builder);
};

}

#endif //P4C_EBPFPIPELINE_H
