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
    cstring timestampVar, ifindexVar;
    cstring priorityVar, packetPathVar, pktInstanceVar;

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
        ifindexVar = cstring("skb->ifindex");
        packetPathVar = cstring("meta->packet_path");
        pktInstanceVar = cstring("meta->instance");
        priorityVar = cstring("skb->priority");
    }

    virtual cstring dropReturnCode() {
        if (sectionName.startsWith("xdp")) {
            return "XDP_DROP";
        }

        // TC is the default hookpoint
        return "TC_ACT_SHOT";
    }
    virtual cstring forwardReturnCode() {
        if (sectionName.startsWith("xdp")) {
            return "XDP_PASS";
        }

        // TC is the default hookpoint
        return "TC_ACT_OK";
    }

    virtual void emitTrafficManager(CodeBuilder *builder) = 0;
    virtual void emitPSAControlDataTypes(CodeBuilder* builder) = 0;
    void emitHeaderInstances(CodeBuilder *builder) override;
    void emitLocalVariables(CodeBuilder* builder) override;
    void emitGlobalMetadataInitializer(CodeBuilder *builder);
    void emitUserMetadataInstance(CodeBuilder *builder);
    virtual void emitPacketLength(CodeBuilder *builder);
    virtual void emitTimestamp(CodeBuilder *builder);
    virtual void emit(CodeBuilder* builder);
    virtual bool shouldEmitTimestamp() {
        if (!control->meters.empty() || control->timestampIsUsed) {
            return true;
        }
        return false;
    }
};

/*
 * EBPFIngressPipeline represents a hook-independent EBPF-based ingress pipeline.
 * It includes common definitions for TC and XDP.
 */
class EBPFIngressPipeline : public EBPFPipeline {
 public:
    EBPFIngressPipeline(cstring name, const EbpfOptions& options, P4::ReferenceMap* refMap,
                        P4::TypeMap* typeMap) : EBPFPipeline(name, options, refMap, typeMap) {}

    void emitPSAControlDataTypes(CodeBuilder* builder) override;
};

class EBPFEgressPipeline : public EBPFPipeline {
 public:
    EBPFEgressPipeline(cstring name, const EbpfOptions& options, P4::ReferenceMap* refMap,
                       P4::TypeMap* typeMap) : EBPFPipeline(name, options, refMap, typeMap) {}

    void emitPSAControlDataTypes(CodeBuilder* builder) override;
};

class TCIngressPipeline : public EBPFIngressPipeline {
 public:
    cstring processFunctionName;
    unsigned int maxResubmitDepth;

    TCIngressPipeline(cstring name, const EbpfOptions& options, P4::ReferenceMap* refMap,
                        P4::TypeMap* typeMap) :
            EBPFIngressPipeline(name, options, refMap, typeMap) {
        processFunctionName = "process";
        // FIXME: hardcded
        maxResubmitDepth = 4;
    }

    void emitTrafficManager(CodeBuilder *builder) override;
    void emit(CodeBuilder *builder) override;
 private:
    void emitTCWorkaroundUsingMeta(CodeBuilder *builder);
    void emitTCWorkaroundUsingHead(CodeBuilder *builder);
    void emitTCWorkaroundUsingCPUMAP(CodeBuilder *builder);
};

class TCEgressPipeline : public EBPFEgressPipeline {
 public:
    TCEgressPipeline(cstring name, const EbpfOptions& options, P4::ReferenceMap* refMap,
                       P4::TypeMap* typeMap) :
            EBPFEgressPipeline(name, options, refMap, typeMap) { }

    void emitTrafficManager(CodeBuilder *builder) override;
};

class XDPIngressPipeline : public EBPFIngressPipeline {
 public:
    XDPIngressPipeline(cstring name, const EbpfOptions& options, P4::ReferenceMap* refMap,
                    P4::TypeMap* typeMap) :
            EBPFIngressPipeline(name, options, refMap, typeMap) {
        sectionName = "xdp_ingress/" + name;
        ifindexVar = cstring("skb->ingress_ifindex");
        packetPathVar = cstring("0");
    }

    void emit(CodeBuilder *builder) override;
    void emitTrafficManager(CodeBuilder *builder) override;
};

class XDPEgressPipeline : public EBPFEgressPipeline {
 public:
    XDPEgressPipeline(cstring name, const EbpfOptions& options, P4::ReferenceMap* refMap,
                        P4::TypeMap* typeMap):
            EBPFEgressPipeline(name, options, refMap, typeMap) {
        sectionName = "xdp_devmap/" + name;
        ifindexVar = cstring("skb->egress_ifindex");
        // we do not support packet path, instance & priority in the XDP egress.
        packetPathVar = cstring("0");
        pktInstanceVar = cstring("0");
        priorityVar = cstring("0");
    }

    void emit(CodeBuilder *builder) override;
    void emitTrafficManager(CodeBuilder *builder) override;
};

class TCTrafficManagerForXDP : public TCIngressPipeline {
    void emitReadXDP2TCMetadataFromHead(CodeBuilder *builder);
    void emitReadXDP2TCMetadataFromCPUMAP(CodeBuilder *builder);

 public:
    TCTrafficManagerForXDP(cstring name, const EbpfOptions& options, P4::ReferenceMap* refMap,
                           P4::TypeMap* typeMap) :
            TCIngressPipeline(name, options, refMap, typeMap) {
    }

    void emit(CodeBuilder *builder) override;
};

}  // namespace EBPF

#endif /* BACKENDS_EBPF_PSA_EBPFPIPELINE_H_ */
