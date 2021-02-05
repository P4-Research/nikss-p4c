#include "ebpfPsaArch.h"
#include "ebpfPsaParser.h"

namespace EBPF_PSA {

void PSAArch::emit(EBPF::CodeBuilder *builder) const {
    /**
     * How the structure of a single C program for PSA should look like?
     * 1. Automatically generated comment
     * 2. Includes
     * 3. Macro definitions (it's called "preamble")
     * 4. Headers, structs, types, PSA-specific data types.
     * 5. BPF map definitions.
     * 6. XDP helper program.
     * 7. TC Ingress program.
     * 8. TC Egress program.
     */

    // 1. Automatically generated comment.
    // Note we use inherited function from EBPFProgram.
    xdp->emitGeneratedComment(builder);

    /*
     * 2. Includes.
     */
    builder->target->emitIncludes(builder);

    /*
     * 3. Macro definitions (it's called "preamble")
     */
    //emitPreamble(builder);

    /*
     * 6. XDP helper program.
     */
    // xdpProgram->emit()

    /*
     * 7. XDP helper program.
     */
    // tcIngressProgram->emit()

    /*
     * 8. TC Egress program.
     */
    // tcEgressProgram->emit()
}

const PSAArch * ConvertToEbpfPSA::build(IR::P4Program *prog) {
    // TODO: use converter
    auto xdp = new EBPF::EBPFProgram(options, prog, refmap, typemap, toplevel);

    /*
     * INGRESS
     */
    auto ingressParser = structure.parsers.at("ingress");
    BUG_CHECK(ingressParser != nullptr, "No ingress parser block found");
    auto ingressControl = structure.pipelines.at("ingress");
    BUG_CHECK(ingressControl != nullptr, "No ingress control block found");
    auto ingressDeparser = structure.deparsers.at("ingress");
    BUG_CHECK(ingressDeparser != nullptr, "No ingress deparser block found");

    auto ingress_pipeline_converter =
           new ConvertToEbpfPipeline(options, ingressParser, ingressControl, ingressDeparser, refmap, typemap);
    prog->apply(*ingress_pipeline_converter);
    auto tcIngress = ingress_pipeline_converter->getEbpfPipeline();

    /*
     * EGRESS
     */
    auto egressParser = structure.parsers.at("egress");
    BUG_CHECK(egressParser != nullptr, "No egress parser block found");
    auto egressControl = structure.pipelines.at("egress");
    BUG_CHECK(egressControl != nullptr, "No egress control block found");
    auto egressDeparser = structure.deparsers.at("egress");
    BUG_CHECK(egressDeparser != nullptr, "No egress deparser block found");

    auto egress_pipeline_converter =
            new ConvertToEbpfPipeline(options, egressParser, egressControl, egressDeparser, refmap, typemap);
    prog->apply(*egress_pipeline_converter);
    auto tcEgress = egress_pipeline_converter->getEbpfPipeline();


    return new PSAArch(xdp, tcIngress, tcEgress);
}

const IR::Node * ConvertToEbpfPSA::preorder(IR::P4Program *prog) {
    ebpf_psa_arch = build(prog);
    return prog;
}

// =====================EbpfPipeline=============================
EBPFPipeline * ConvertToEbpfPipeline::build(const IR::P4Program *prog) {
    auto pipeline = new EBPFPipeline(options, nullptr, prog, refmap, typemap);
    pipeline->parser = new EBPFPsaParser(pipeline, parserBlock, typemap);
    pipeline->parser->build();

    // TODO: EBPFControl needs IR::ControlBlock, while we have only IR::P4Control. How to solve this problem?
//    auto cont = decl->to<IR::P4Control>();
//    auto block = new IR::ControlBlock(node->srcInfo, node, instanceType, controlBlock);
//    pipeline->control = new EBPF::EBPFControl()

}

bool ConvertToEbpfPipeline::preorder(const IR::P4Program *prog) {
    pipeline = build(prog);
    return true;
}

};

