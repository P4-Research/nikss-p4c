#ifndef BACKENDS_EBPF_PSA_EBPFPIPELINE_H_
#define BACKENDS_EBPF_PSA_EBPFPIPELINE_H_

#include "ebpfPsaControl.h"
#include "backends/ebpf/ebpfProgram.h"
#include "ebpfPsaDeparser.h"

namespace EBPF {

class EBPFControlPSA;
class EBPFDeparserPSA;

/*
 * EBPFPipeline represents a single eBPF program in the TC/XDP hook.
 * A single pipeline is composed of Parser, Control block and Deparser.
 * EBPFPipeline inherits from EBPFProgram, but extends it with deparser and other PSA-specific objects.
 */
class EBPFPipeline : public EBPFProgram {
 public:
    const cstring name;
    cstring sectionName;
    cstring contextVar;

    EBPFControlPSA* control;
    EBPFDeparserPSA* deparser;

    EBPFPipeline(cstring name, const EbpfOptions& options, P4::ReferenceMap* refMap,
                 P4::TypeMap* typeMap) :
                 EBPFProgram(options, nullptr, refMap, typeMap, nullptr),
                             name(name) {
        sectionName = "classifier/" + name;
        functionName = name.replace("-", "_") + "_func";
        errorType = "ParserError_t";
        packetStartVar = cstring("pkt");
        contextVar = cstring("skb");
        lengthVar = cstring("pkt_len");
        endLabel = cstring("deparser");
    }

    virtual void emitTrafficManager(CodeBuilder *builder) = 0;
    void emitHeaderInstances(CodeBuilder *builder) override;
    void emitLocalVariables(CodeBuilder* builder) override;
    void emitGlobalMetadataInitializer(CodeBuilder *builder);
    virtual void emitPSAControlDataTypes(CodeBuilder* builder) = 0;
    virtual void emit(CodeBuilder* builder);
};

class EBPFIngressPipeline : public EBPFPipeline {
 public:
    cstring processFunctionName;
    unsigned int maxResubmitDepth;

    EBPFIngressPipeline(cstring name, const EbpfOptions& options, P4::ReferenceMap* refMap,
                        P4::TypeMap* typeMap) :
            EBPFPipeline(name, options, refMap, typeMap) {
        processFunctionName = "process";
        // FIXME: hardcded
        maxResubmitDepth = 4;
    }

    void emitTrafficManager(CodeBuilder *builder) override;
    void emit(CodeBuilder *builder) override;
    void emitPSAControlDataTypes(CodeBuilder *builder) override;
};

class EBPFEgressPipeline : public EBPFPipeline {
 public:
    EBPFEgressPipeline(cstring name, const EbpfOptions& options, P4::ReferenceMap* refMap,
                       P4::TypeMap* typeMap) :
            EBPFPipeline(name, options, refMap, typeMap) { }

    void emitTrafficManager(CodeBuilder *builder) override;
    void emitPSAControlDataTypes(CodeBuilder *builder) override;
};

}  // namespace EBPF

#endif /* BACKENDS_EBPF_PSA_EBPFPIPELINE_H_ */
