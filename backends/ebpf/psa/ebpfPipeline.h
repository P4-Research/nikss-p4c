#ifndef BACKENDS_EBPF_PSA_EBPFPIPELINE_H_
#define BACKENDS_EBPF_PSA_EBPFPIPELINE_H_

#include "ebpfPsaControl.h"
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
    cstring contextVar;
    cstring timestampVar;

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
        timestampVar = cstring("tstamp");
    }

    virtual cstring dropReturnCode() {
        // TC is the default hookpoint
        return "TC_ACT_SHOT";
    }
    virtual cstring forwardReturnCode() {
        // TC is the default hookpoint
        return "TC_ACT_OK";
    }
    virtual void emitTrafficManager(CodeBuilder *builder) = 0;
    void emitHeaderInstances(CodeBuilder *builder) override;
    void emitLocalVariables(CodeBuilder* builder) override;
    void emitGlobalMetadataInitializer(CodeBuilder *builder);
    void emitUserMetadataInstance(CodeBuilder *builder);
    virtual void emitPacketLength(CodeBuilder *builder);
    virtual void emitTimestamp(CodeBuilder *builder);
    virtual void emitPSAControlDataTypes(CodeBuilder* builder) = 0;
    virtual void emit(CodeBuilder* builder);
};

class TCIngressPipeline : public EBPFPipeline {
 public:
    cstring processFunctionName;
    unsigned int maxResubmitDepth;

    TCIngressPipeline(cstring name, const EbpfOptions& options, P4::ReferenceMap* refMap,
                        P4::TypeMap* typeMap) :
            EBPFPipeline(name, options, refMap, typeMap) {
        processFunctionName = "process";
        // FIXME: hardcded
        maxResubmitDepth = 4;
    }

    void emitTrafficManager(CodeBuilder *builder) override;
    void emit(CodeBuilder *builder) override;
    void emitPSAControlDataTypes(CodeBuilder *builder) override;
 private:
    void emitTCWorkaroundUsingMeta(CodeBuilder *builder);
    void emitTCWorkaroundUsingHead(CodeBuilder *builder);
    void emitTCWorkaroundUsingCPUMAP(CodeBuilder *builder);
};

class TCEgressPipeline : public EBPFPipeline {
 public:
    TCEgressPipeline(cstring name, const EbpfOptions& options, P4::ReferenceMap* refMap,
                       P4::TypeMap* typeMap) :
            EBPFPipeline(name, options, refMap, typeMap) { }

    void emitTrafficManager(CodeBuilder *builder) override;
    void emitPSAControlDataTypes(CodeBuilder *builder) override;
};

class XDPPipeline : public EBPFPipeline {
 public:
    XDPPipeline(cstring name, const EbpfOptions& options, P4::ReferenceMap* refMap,
    P4::TypeMap* typeMap) : EBPFPipeline(name, options, refMap, typeMap) {
    }

    void emitPacketLength(CodeBuilder *builder) override;
    void emitTimestamp(CodeBuilder *builder) override;
    cstring forwardReturnCode() override {
        return "XDP_PASS";
    }
    cstring dropReturnCode() override {
        return "XDP_DROP";
    }
};

class XDPIngressPipeline : public XDPPipeline {
 public:
    XDPIngressPipeline(cstring name, const EbpfOptions& options, P4::ReferenceMap* refMap,
                    P4::TypeMap* typeMap) :
            XDPPipeline(name, options, refMap, typeMap) {
        sectionName = "xdp_ingress/" + name;
    }

    void emit(CodeBuilder *builder) override;
    void emitTrafficManager(CodeBuilder *builder) override;
    void emitPSAControlDataTypes(CodeBuilder *builder) override;
};

class XDPEgressPipeline : public XDPPipeline {
 public:
    XDPEgressPipeline(cstring name, const EbpfOptions& options, P4::ReferenceMap* refMap,
                        P4::TypeMap* typeMap):
            XDPPipeline(name, options, refMap, typeMap) {
        sectionName = "xdp_devmap/" + name;
    }

    void emit(CodeBuilder *builder) override;
    void emitTrafficManager(CodeBuilder *builder) override;
    void emitPSAControlDataTypes(CodeBuilder *builder) override;
};

class TCTrafficManagerForXDP : public TCIngressPipeline {
 public:
    TCTrafficManagerForXDP(cstring name, const EbpfOptions& options, P4::ReferenceMap* refMap,
                           P4::TypeMap* typeMap) :
            TCIngressPipeline(name, options, refMap, typeMap) {
    }

    void emit(CodeBuilder *builder) override;
};

}  // namespace EBPF

#endif /* BACKENDS_EBPF_PSA_EBPFPIPELINE_H_ */
