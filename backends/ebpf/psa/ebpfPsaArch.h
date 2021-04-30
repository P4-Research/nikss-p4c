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
    INGRESS = 0,
    EGRESS = 1,
};

class PSAArch {
 public:
    static const unsigned MaxClones = 64;
    static const unsigned MaxCloneSessions = 1024;

    std::vector<EBPFType*> ebpfTypes;
    XDPHelpProgram*            xdp;
    EBPFPipeline*          tcIngress;
    EBPFPipeline*          tcEgress;

    EBPFPipeline*          xdpIngress;
    EBPFPipeline*          xdpEgress;

    PSAArch(std::vector<EBPFType*> ebpfTypes, XDPHelpProgram* xdp, EBPFPipeline* tcIngress,
            EBPFPipeline* tcEgress) : 
            ebpfTypes(ebpfTypes), xdp(xdp), tcIngress(tcIngress),
            tcEgress(tcEgress) { }

    PSAArch(std::vector<EBPFType*> ebpfTypes, EBPFPipeline* xdpIngress, 
            EBPFPipeline* xdpEgress) : ebpfTypes(ebpfTypes), 
            xdpIngress(xdpIngress), xdpEgress(xdpEgress) { }

    void emit2TC(CodeBuilder* builder) const;  // emits C file for eBPF program - at TC layer
    void emitPreamble2TC(CodeBuilder* builder) const;
    void emitInternalStructures2TC(CodeBuilder* pBuilder) const;
    void emitTypes2TC(CodeBuilder *builder) const;
    void emitInstances2TC(CodeBuilder *builder) const;
    void emitPSAIncludes2TC(CodeBuilder *builder) const;
    void emitHelperFunctions2TC(CodeBuilder *builder) const;
    void emitInitializer2TC(CodeBuilder *p_builder) const;

    void emit2XDP(CodeBuilder* builder) const;
    void emitPreamble2XDP(CodeBuilder* builder) const;
    void emitTypes2XDP(CodeBuilder *builder) const;
    void emitInstances2XDP(CodeBuilder *builder) const;
    void emitPSAIncludes2XDP(CodeBuilder *builder) const;
    void emitInitializer2XDP(CodeBuilder *p_builder) const;
    void emitDummy2XDP(CodeBuilder *builder) const;
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
                     : options(options), structure(structure), typemap(typemap), refmap(refmap) {
    }

    const PSAArch *build(IR::ToplevelBlock *prog);
    const IR::Node *preorder(IR::ToplevelBlock *p) override;
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
            name(name),
            type(type),
            options(options),
            parserBlock(parserBlock), controlBlock(controlBlock),
            deparserBlock(deparserBlock), typemap(typemap), refmap(refmap) { }

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
            P4::TypeMap* typemap, const EbpfOptions &options) : 
            program(program), typemap(typemap), refmap(refmap), options(options) {
        if (program->is<EBPFIngressPipeline>() || program->is<XDPIngressPipeline>()) {
            type = INGRESS;
        } else if (program->is<EBPFEgressPipeline>() || program->is<XDPEgressPipeline>()) {
            type = EGRESS;
        } else {
            BUG("undefined pipeline type, cannot build parser");
        }
    }

    bool preorder(const IR::ParserBlock *prsr) override;
    bool preorder(const IR::ParserState *s) override;
    EBPF::EBPFParser* getEBPFParser() { return parser; }

    void findValueSets(const IR::ParserBlock *prsr);
};

class ConvertToEBPFControlPSA : public Inspector {
    EBPF::EBPFProgram *program;
    pipeline_type type;

    const IR::Parameter* parserHeaders;
    P4::TypeMap *typemap;
    P4::ReferenceMap *refmap;

    EBPF::EBPFControlPSA *control;

 public:
    ConvertToEBPFControlPSA(EBPF::EBPFProgram *program, const IR::Parameter* parserHeaders,
                            P4::ReferenceMap *refmap,
                            P4::TypeMap *typemap) : program(program), parserHeaders(parserHeaders),
                            typemap(typemap), refmap(refmap) {
        if (program->is<EBPFIngressPipeline>() || program->is<XDPIngressPipeline>()) {
            type = INGRESS;
        } else if (program->is<EBPFEgressPipeline>() || program->is<XDPEgressPipeline>()) {
            type = EGRESS;
        } else {
            BUG("undefined pipeline type, cannot build control block");
        }
    }

    bool preorder(const IR::P4Action *) override;
    bool preorder(const IR::TableBlock *) override;
    bool preorder(const IR::ControlBlock *) override;
    bool preorder(const IR::Declaration_Instance*) override;
    bool preorder(const IR::Declaration_Variable*) override;
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
                             const EbpfOptions &options) : program(program),
                                                     parserHeaders(parserHeaders), istd(istd),
                                                     typemap(typemap), refmap(refmap),
                                                     p4lib(P4::P4CoreLibrary::instance),
                                                     options(options) {
        if (program->is<EBPFIngressPipeline>() || program->is<XDPIngressPipeline>()) {
            type = INGRESS;
        } else if (program->is<EBPFEgressPipeline>() || program->is<XDPEgressPipeline>()) {
            type = EGRESS;
        } else {
            BUG("undefined pipeline type, cannot build deparser");
        }
    }

    bool preorder(const IR::ControlBlock *) override;
    bool preorder(const IR::MethodCallExpression* expression) override;
    EBPF::EBPFDeparserPSA *getEBPFPsaDeparser() { return deparser; }
    void findDigests(const IR::P4Control *p4Control);
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EBPFPSAARCH_H_ */
