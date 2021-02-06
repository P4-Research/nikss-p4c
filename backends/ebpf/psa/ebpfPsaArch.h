#ifndef P4C_EBPFPSAARCH_H
#define P4C_EBPFPSAARCH_H

#include "backends/bmv2/psa_switch/psaSwitch.h"

#include "backends/ebpf/codeGen.h"
#include "backends/ebpf/ebpfObject.h"
#include "backends/ebpf/ebpfOptions.h"
#include "backends/ebpf/ebpfParser.h"
#include "ebpfPipeline.h"


namespace EBPF_PSA {

class PSAArch {
 public:
    EBPF::EBPFProgram*     xdp;
    EBPFPipeline*          tcIngress;
    EBPFPipeline*          tcEgress;

    PSAArch(EBPF::EBPFProgram* xdp, EBPFPipeline* tcIngress, EBPFPipeline* tcEgress) : xdp(xdp),
        tcIngress(tcIngress), tcEgress(tcEgress) { }

    void emit(EBPF::CodeBuilder* builder) const;  // emits C file for eBPF program
};

class ConvertToEbpfPSA : public Transform {

    const EbpfOptions& options;
    const IR::ToplevelBlock* toplevel;
    BMV2::PsaProgramStructure &structure;
    P4::TypeMap *typemap;
    P4::ReferenceMap *refmap;

    const PSAArch *ebpf_psa_arch;

  public:
    ConvertToEbpfPSA(const EbpfOptions &options,
                     const IR::ToplevelBlock* toplevel,
                     BMV2::PsaProgramStructure &structure,
                     P4::ReferenceMap *refmap, P4::TypeMap *typemap)
                     : options(options), toplevel(toplevel), structure(structure), typemap(typemap), refmap(refmap) {

    }

    const PSAArch *build(IR::P4Program *prog);
    const IR::Node *preorder(IR::P4Program *p) override;
    const PSAArch *getPSAArchForEBPF() { return ebpf_psa_arch; }
};

class ConvertToEbpfPipeline : public Inspector {
    const cstring name;
    const EbpfOptions &options;

    const IR::P4Parser* parserBlock;
    const IR::P4Control* controlBlock;
    const IR::P4Control* deparserBlock;
    P4::TypeMap *typemap;
    P4::ReferenceMap *refmap;

    EBPFPipeline* pipeline;

  public:
    ConvertToEbpfPipeline(cstring name, const EbpfOptions &options, const IR::P4Parser* parserBlock, const IR::P4Control* controlBlock,
            const IR::P4Control* deparserBlock,  P4::ReferenceMap *refmap, P4::TypeMap *typemap) : name(name),
            options(options),
            parserBlock(parserBlock), controlBlock(controlBlock),
            deparserBlock(deparserBlock), typemap(typemap), refmap(refmap) {

    }

    EBPFPipeline *build(const IR::P4Program *prog);
    bool preorder(const IR::P4Program *p) override;
    EBPFPipeline *getEbpfPipeline() { return pipeline; }
};

class ConvertToEBPFControlPSA : public Inspector {
    // TODO: compose EBPFPsaControl object
};

class ConvertToEBPFParserPSA : public Inspector {
    // TODO: compose EBPFParserPSA
};

class ConvertToEBPFDeparserPSA : public Inspector {
    // TODO: compose EBPFDeparserPSA
};

}

#endif //P4C_EBPFPSAARCH_H
