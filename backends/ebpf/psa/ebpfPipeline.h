#ifndef BACKENDS_EBPF_PSA_EBPFPIPELINE_H_
#define BACKENDS_EBPF_PSA_EBPFPIPELINE_H_

#include "backends/ebpf/ebpfProgram.h"
#include "ebpfPsaDeparser.h"

namespace EBPF {

/*
 * EBPFPipeline represents a single eBPF program in the TC/XDP hook.
 * A single pipeline is composed of Parser, Control block and Deparser.
 * EBPFPipeline inherits from EBPFProgram, but extends it with deparser and other PSA-specific objects.
 */
class EBPFPipeline : public EBPFProgram {
 public:
    const cstring name;
    cstring sectionName;
    EBPFPsaDeparser* deparser;

    cstring contextVar, outerHdrOffsetVar, outerHdrLengthVar;
    cstring stdMetadataVar;
    cstring packetTruncatedSizeVar;
    cstring returnCode;
    cstring arrayIndexType = "uint32_t";

    EBPFPipeline(cstring name, const EbpfOptions& options, P4::ReferenceMap* refMap,
                 P4::TypeMap* typeMap) :
                 EBPFProgram(options, nullptr, refMap, typeMap, nullptr),
                             name(name) {
        sectionName = name;
        functionName = name.replace("-", "_") + "_func";
        errorType = "ParserError_t";

        packetStartVar = cstring("pkt");
        offsetVar = cstring("packetOffsetInBits");
        outerHdrOffsetVar = cstring("outHeaderOffset");
        outerHdrLengthVar = cstring("outHeaderLength");
        contextVar = cstring("skb");
        lengthVar = cstring("pkt_len");
        endLabel = cstring("deparser");
        stdMetadataVar = cstring("std_meta");
        packetTruncatedSizeVar = cstring("packetTruncatedSize");
        returnCode = cstring("returnCode");
    }

    void emitHeaderInstances(CodeBuilder *builder) override;
    void emitLocalVariables(CodeBuilder* builder) override;
    void emit(CodeBuilder* builder);
};

}  // namespace EBPF

#endif /* BACKENDS_EBPF_PSA_EBPFPIPELINE_H_ */