#ifndef P4C_EBPFPSAPARSER_H
#define P4C_EBPFPSAPARSER_H

#include "backends/ebpf/ebpfParser.h"

namespace EBPF {

class EBPFPsaParser : public EBPFParser {
 public:

    EBPFPsaParser(const EBPFProgram* program, const IR::P4Parser* block,
                  const P4::TypeMap* typeMap) : EBPFParser(program, block, typeMap) {

    }

    bool build() override;
};

}

#endif //P4C_EBPFPSAPARSER_H
