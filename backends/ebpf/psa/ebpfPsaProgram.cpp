
#include "ebpfPsaProgram.h"

namespace EBPF_PSA {
bool EBPFPsaProgram::build() {
    // TODO: convert from PSA representation to EBPF objects
    return true;
}

void EBPFPsaProgram::emit(EBPF::CodeBuilder *builder) {
    builder->target->emitIncludes(builder);
}

};

