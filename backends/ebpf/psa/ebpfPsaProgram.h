#ifndef P4C_EBPFPSAPROGRAM_H
#define P4C_EBPFPSAPROGRAM_H

#include "backends/bmv2/psa_switch/psaSwitch.h"

#include "backends/ebpf/codeGen.h"
#include "backends/ebpf/ebpfObject.h"
#include "backends/ebpf/ebpfOptions.h"


namespace EBPF_PSA {

class EBPFPsaProgram : public EBPF::EBPFObject {
 public:
    const EbpfOptions& options;
    const IR::P4Program* program;
    BMV2::PsaProgramStructure programStructure;

    EBPFPsaProgram(const EbpfOptions &options, const IR::P4Program* program,
                   P4::ReferenceMap* refMap, P4::TypeMap* typeMap, BMV2::PsaProgramStructure programStructure) :
                   options(options), programStructure(programStructure) {

    }

    virtual bool build();  // return 'true' on success
    virtual void emit(EBPF::CodeBuilder* builder);  // emits C file for eBPF program
};

}

#endif //P4C_EBPFPSAPROGRAM_H
