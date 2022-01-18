#ifndef BACKENDS_EBPF_PSA_EBPFPSAARCH_H_
#define BACKENDS_EBPF_PSA_EBPFPSAARCH_H_

#include "backends/bmv2/psa_switch/psaSwitch.h"

#include "backends/ebpf/codeGen.h"
#include "backends/ebpf/ebpfObject.h"
#include "backends/ebpf/ebpfOptions.h"
#include "ebpfPsaParser.h"
#include "xdpHelpProgram.h"
#include "ebpfPipeline.h"

namespace EBPF {

enum pipeline_type {
    TC_INGRESS,
    TC_EGRESS,
    XDP_INGRESS,
    XDP_EGRESS,
    TC_TRAFFIC_MANAGER
};

class PSAArch {
 public:
    static const unsigned MaxClones = 64;
    static const unsigned MaxCloneSessions = 1024;

    const EbpfOptions&     options;
    std::vector<EBPFType*> ebpfTypes;

    EBPFPipeline* ingress;
    EBPFPipeline* egress;

    PSAArch(const EbpfOptions &options, std::vector<EBPFType*> &ebpfTypes,
            EBPFPipeline* ingress, EBPFPipeline* egress)
            : options(options), ebpfTypes(ebpfTypes), ingress(ingress), egress(egress) {}

    virtual void emit(CodeBuilder* builder) const = 0;

    void emitPSAIncludes(CodeBuilder *builder) const;
    virtual void emitPreamble(CodeBuilder* builder) const;
    void emitCommonPreamble(CodeBuilder *builder) const;
    void emitInternalStructures(CodeBuilder* pBuilder) const;
    void emitTypes(CodeBuilder *builder) const;
    void emitGlobalHeadersMetadata(CodeBuilder *builder) const;
    virtual void emitInstances(CodeBuilder *builder) const = 0;
    void emitPacketReplicationTables(CodeBuilder *builder) const;
    void emitPipelineInstances(CodeBuilder *builder) const;
    void emitInitializer(CodeBuilder *builder) const;
    virtual void emitInitializerSection(CodeBuilder *builder) const = 0;
    void emitHelperFunctions(CodeBuilder *builder) const;
};

class PSAArchTC : public PSAArch {
 public:
    XDPHelpProgram* xdp;

    PSAArchTC(const EbpfOptions &options, std::vector<EBPFType*> &ebpfTypes,
              XDPHelpProgram* xdp, EBPFPipeline* tcIngress, EBPFPipeline* tcEgress) :
              PSAArch(options, ebpfTypes, tcIngress, tcEgress), xdp(xdp) { }

    void emit(CodeBuilder* builder) const override;

    void emitInstances(CodeBuilder *builder) const override;
    void emitInitializerSection(CodeBuilder *builder) const override;
};

class PSAArchXDP : public PSAArch {
 public:
    // TC Ingress program used to support packet cloning in the XDP mode.
    EBPFPipeline* tcIngressForXDP;
    // If the XDP mode is used, we need to have TC Egress pipeline to handle cloned packets.
    EBPFPipeline* tcEgressForXDP;
    static const unsigned egressDevmapSize = 256;

    PSAArchXDP(const EbpfOptions &options, std::vector<EBPFType*> &ebpfTypes,
               EBPFPipeline* xdpIngress, EBPFPipeline* xdpEgress,
               EBPFPipeline* tcTrafficManager, EBPFPipeline* tcEgress) :
               PSAArch(options, ebpfTypes, xdpIngress, xdpEgress),
               tcIngressForXDP(tcTrafficManager), tcEgressForXDP(tcEgress) { }

    void emit(CodeBuilder* builder) const override;

    void emitPreamble(CodeBuilder* builder) const override;
    void emitInstances(CodeBuilder *builder) const override;
    void emitInitializerSection(CodeBuilder *builder) const override;

    void emitXDP2TCInternalStructures(CodeBuilder *builder) const;
    void emitDummyProgram(CodeBuilder *builder) const;
};

class ConvertToEbpfPSA : public Transform {
    const EbpfOptions& options;
    BMV2::PsaProgramStructure& structure;
    P4::TypeMap* typemap;
    P4::ReferenceMap* refmap;
    const PSAArch* ebpf_psa_arch;

 public:
    ConvertToEbpfPSA(const EbpfOptions &options,
                     BMV2::PsaProgramStructure &structure,
                     P4::ReferenceMap *refmap, P4::TypeMap *typemap)
                     : options(options), structure(structure), typemap(typemap), refmap(refmap),
                     ebpf_psa_arch(nullptr) {}

    const PSAArch *build(const IR::ToplevelBlock *prog);
    const IR::Node *preorder(IR::ToplevelBlock *p) override;

    void optimizePipeline();

    const PSAArch *getPSAArchForEBPF() { return ebpf_psa_arch; }
};

class ConvertToEbpfPipeline : public Inspector {
    const cstring name;
    const pipeline_type type;
    const EbpfOptions &options;
    const IR::ParserBlock* parserBlock;
    const IR::ControlBlock* controlBlock;
    const IR::ControlBlock* deparserBlock;
    P4::TypeMap* typemap;
    P4::ReferenceMap* refmap;
    EBPFPipeline* pipeline;

 public:
    ConvertToEbpfPipeline(cstring name, pipeline_type type, const EbpfOptions &options,
                          const IR::ParserBlock* parserBlock, const IR::ControlBlock* controlBlock,
                          const IR::ControlBlock* deparserBlock,
                          P4::ReferenceMap *refmap, P4::TypeMap *typemap) :
            name(name), type(type), options(options),
            parserBlock(parserBlock), controlBlock(controlBlock),
            deparserBlock(deparserBlock), typemap(typemap), refmap(refmap),
            pipeline(nullptr) { }

    bool preorder(const IR::PackageBlock *block) override;
    EBPFPipeline *getEbpfPipeline() { return pipeline; }
};

class ConvertToEBPFParserPSA : public Inspector {
    EBPF::EBPFProgram *program;
    pipeline_type type;

    P4::TypeMap *typemap;
    P4::ReferenceMap *refmap;
    EBPF::EBPFPsaParser* parser;

    const EbpfOptions &options;

 public:
    ConvertToEBPFParserPSA(EBPF::EBPFProgram* program, P4::ReferenceMap* refmap,
            P4::TypeMap* typemap, const EbpfOptions &options, pipeline_type type) :
            program(program), type(type), typemap(typemap), refmap(refmap),
            parser(nullptr), options(options) {}

    bool preorder(const IR::ParserBlock *prsr) override;
    EBPF::EBPFParser* getEBPFParser() { return parser; }

    void findValueSets(const IR::ParserBlock *prsr);
};

class ConvertToEBPFControlPSA : public Inspector {
    EBPF::EBPFProgram *program;
    pipeline_type type;
    EBPF::EBPFControlPSA *control;

    const IR::Parameter* parserHeaders;
    P4::TypeMap *typemap;
    P4::ReferenceMap *refmap;

    const EbpfOptions &options;

 public:
    ConvertToEBPFControlPSA(EBPF::EBPFProgram *program, const IR::Parameter* parserHeaders,
                            P4::ReferenceMap *refmap, P4::TypeMap *typemap,
                            const EbpfOptions &options, pipeline_type type)
                            : program(program), type(type), control(nullptr),
                            parserHeaders(parserHeaders),
                            typemap(typemap), refmap(refmap), options(options) {}

    bool preorder(const IR::TableBlock *) override;
    bool preorder(const IR::ControlBlock *) override;
    bool preorder(const IR::Declaration_Variable*) override;
    bool preorder(const IR::AssignmentStatement *a) override;
    bool preorder(const IR::IfStatement *a) override;
    bool preorder(const IR::ExternBlock *) override;

    EBPF::EBPFControlPSA *getEBPFControl() { return control; }
};

class ConvertToEBPFDeparserPSA : public Inspector {
    EBPF::EBPFProgram* program;
    pipeline_type type;

    const IR::Parameter* parserHeaders;
    const IR::Parameter* istd;
    P4::TypeMap* typemap;
    P4::ReferenceMap* refmap;
    P4::P4CoreLibrary& p4lib;
    EBPF::EBPFDeparserPSA* deparser;

    const EbpfOptions &options;

 public:
    ConvertToEBPFDeparserPSA(EBPFProgram* program, const IR::Parameter* parserHeaders,
                             const IR::Parameter* istd,
                             P4::ReferenceMap* refmap, P4::TypeMap* typemap,
                             const EbpfOptions &options, pipeline_type type)
                             : program(program), type(type), parserHeaders(parserHeaders),
                             istd(istd), typemap(typemap), refmap(refmap),
                             p4lib(P4::P4CoreLibrary::instance),
                             deparser(nullptr), options(options) {}

    bool preorder(const IR::ControlBlock *) override;
    bool preorder(const IR::MethodCallExpression* expression) override;
    EBPF::EBPFDeparserPSA *getEBPFDeparser() { return deparser; }
    void findDigests(const IR::P4Control *p4Control);
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EBPFPSAARCH_H_ */
