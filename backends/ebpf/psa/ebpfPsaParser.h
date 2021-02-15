#ifndef BACKENDS_EBPF_PSA_EBPFPSAPARSER_H_
#define BACKENDS_EBPF_PSA_EBPFPSAPARSER_H_

#include "backends/ebpf/ebpfParser.h"

namespace EBPF {

class EBPFPsaParser : public EBPFParser {
 public:
    EBPFPsaParser(const EBPFProgram* program, const IR::P4Parser* block,
                  const P4::TypeMap* typeMap) : EBPFParser(program, block, typeMap) { }

    bool build() override;
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EBPFPSAPARSER_H_ */
