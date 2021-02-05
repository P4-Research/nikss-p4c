#ifndef P4C_EBPFPSAPARSER_H
#define P4C_EBPFPSAPARSER_H

#include "backends/ebpf/ebpfParser.h"

namespace EBPF_PSA {

class EBPFPsaParser : public EBPF::EBPFParser {
 public:

    EBPFPsaParser(const EBPF::EBPFProgram* program, const IR::P4Parser* block,
                  const P4::TypeMap* typeMap) : EBPF::EBPFParser(program, block, typeMap) {

    }

    bool build() override;
};

}

#endif //P4C_EBPFPSAPARSER_H
