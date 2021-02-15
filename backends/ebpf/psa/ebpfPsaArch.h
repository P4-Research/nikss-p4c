#ifndef BACKENDS_EBPF_PSA_EBPFPSAARCH_H_
#define BACKENDS_EBPF_PSA_EBPFPSAARCH_H_

#include "backends/bmv2/psa_switch/psaSwitch.h"

#include "backends/ebpf/codeGen.h"
#include "backends/ebpf/ebpfObject.h"
#include "backends/ebpf/ebpfOptions.h"
#include "backends/ebpf/ebpfParser.h"
#include "xdpProgram.h"
#include "ebpfPipeline.h"

namespace EBPF {

class PSAArch {
 public:
    std::vector<EBPFType*> ebpfTypes;

    XDPProgram*            xdp;
    EBPFPipeline*          tcIngress;
    EBPFPipeline*          tcEgress;

    PSAArch(std::vector<EBPFType*> ebpfTypes, XDPProgram* xdp, EBPFPipeline* tcIngress,
            EBPFPipeline* tcEgress) : xdp(xdp), ebpfTypes(ebpfTypes), tcIngress(tcIngress),
            tcEgress(tcEgress) { }

    void emit(CodeBuilder* builder) const;  // emits C file for eBPF program
    void emitPreamble(CodeBuilder *builder) const;
    void emitInternalMetadata(CodeBuilder *pBuilder) const;
    void emitTypes(CodeBuilder *builder) const;
    void emitPSAIncludes(CodeBuilder *builder) const;
};

class ConvertToEbpfPSA : public Transform {
    const EbpfOptions& options;
    BMV2::PsaProgramStructure &structure;
    P4::TypeMap *typemap;
    P4::ReferenceMap *refmap;

    const PSAArch *ebpf_psa_arch;

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
    const EbpfOptions &options;

    const IR::ParserBlock* parserBlock;
    const IR::ControlBlock* controlBlock;
    const IR::ControlBlock* deparserBlock;
    P4::TypeMap *typemap;
    P4::ReferenceMap *refmap;

    EBPFPipeline* pipeline;

 public:
    ConvertToEbpfPipeline(cstring name, const EbpfOptions &options,
            const IR::ParserBlock* parserBlock, const IR::ControlBlock* controlBlock,
            const IR::ControlBlock* deparserBlock,
            P4::ReferenceMap *refmap, P4::TypeMap *typemap) :
            name(name),
            options(options),
            parserBlock(parserBlock), controlBlock(controlBlock),
            deparserBlock(deparserBlock), typemap(typemap), refmap(refmap) { }

    bool preorder(const IR::PackageBlock *block) override;
    EBPFPipeline *getEbpfPipeline() { return pipeline; }
};

class ConvertToEBPFParserPSA : public Inspector {
    EBPF::EBPFProgram *program;
    P4::TypeMap *typemap;
    P4::ReferenceMap *refmap;

    EBPF::EBPFParser* parser;

 public:
    ConvertToEBPFParserPSA(EBPF::EBPFProgram *program, P4::ReferenceMap *refmap,
            P4::TypeMap *typemap) : program(program), typemap(typemap), refmap(refmap) { }

    bool preorder(const IR::ParserBlock *prsr) override;
    bool preorder(const IR::ParserState *s) override;
    EBPF::EBPFParser* getEBPFParser() { return parser; }
};

class ConvertToEBPFControlPSA : public Inspector {
    EBPF::EBPFProgram *program;
    const IR::Parameter* parserHeaders;
    P4::TypeMap *typemap;
    P4::ReferenceMap *refmap;


    EBPF::EBPFControl *control;
 public:
    ConvertToEBPFControlPSA(EBPF::EBPFProgram *program, const IR::Parameter* parserHeaders,
                            P4::ReferenceMap *refmap,
                            P4::TypeMap *typemap) : program(program), parserHeaders(parserHeaders),
                            typemap(typemap), refmap(refmap) { }

    bool preorder(const IR::P4Action *a) override;
    bool preorder(const IR::TableBlock *a) override;
    bool preorder(const IR::ControlBlock *) override;
    // Used to visit Extern declaration
    bool preorder(const IR::Declaration_Instance*) override;
    bool preorder(const IR::ExternBlock *) override;

    EBPF::EBPFControl *getEBPFControl() { return control; }
};

    class ConvertToEBPFDeparserPSA : public Inspector {
        EBPF::EBPFProgram *program;
        const IR::Parameter *parserHeaders;
        P4::TypeMap *typemap;
        P4::ReferenceMap *refmap;
        P4::P4CoreLibrary &p4lib;

        EBPF::EBPFPsaDeparser *deparser;
    public:
        ConvertToEBPFDeparserPSA(EBPF::EBPFProgram *program, const IR::Parameter *parserHeaders,
                                 P4::ReferenceMap *refmap,
                                 P4::TypeMap *typemap) : program(program), parserHeaders(parserHeaders),
                                                         typemap(typemap), refmap(refmap), p4lib(P4::P4CoreLibrary::instance) {
        }

        bool preorder(const IR::ControlBlock *) override;

        bool preorder(const IR::MethodCallExpression *expression) override;

        EBPF::EBPFPsaDeparser *getEBPFPsaDeparser() { return deparser; }
    };

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EBPFPSAARCH_H_ */