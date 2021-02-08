#include "ebpfPsaArch.h"
#include "ebpfPsaParser.h"
#include "ebpfPsaControl.h"
#include "xdpProgram.h"

namespace EBPF {

void PSAArch::emit(CodeBuilder *builder) const {
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
    xdp->emit(builder);

    /*
     * 7. XDP helper program.
     */
    tcIngress->emit(builder);

    /*
     * 8. TC Egress program.
     */
    tcEgress->emit(builder);

    builder->target->emitLicense(builder, xdp->license);
}

const PSAArch * ConvertToEbpfPSA::build(IR::ToplevelBlock *tlb) {
    auto xdp = new XDPProgram(options);

    /*
     * INGRESS
     */
    auto ingress = tlb->getMain()->getParameterValue("ingress")->to<IR::PackageBlock>();
    auto ingressParser = ingress->getParameterValue("ip");
    BUG_CHECK(ingressParser != nullptr, "No ingress parser block found");
    auto ingressControl = ingress->getParameterValue("ig");
    BUG_CHECK(ingressControl != nullptr, "No ingress control block found");
    auto ingressDeparser = ingress->getParameterValue("id");
    BUG_CHECK(ingressDeparser != nullptr, "No ingress deparser block found");

    auto ingress_pipeline_converter =
           new ConvertToEbpfPipeline("tc_ingress", options, ingressParser->to<IR::ParserBlock>(),
                   ingressControl->to<IR::ControlBlock>(), ingressDeparser->to<IR::ControlBlock>(),
                   refmap, typemap);
    ingress->apply(*ingress_pipeline_converter);
    auto tcIngress = ingress_pipeline_converter->getEbpfPipeline();

    /*
     * EGRESS
     */
    auto egress = tlb->getMain()->getParameterValue("egress")->to<IR::PackageBlock>();
    auto egressParser = egress->getParameterValue("ep");
    BUG_CHECK(egressParser != nullptr, "No egress parser block found");
    auto egressControl = egress->getParameterValue("eg");
    BUG_CHECK(egressControl != nullptr, "No egress control block found");
    auto egressDeparser = egress->getParameterValue("ed");
    BUG_CHECK(egressDeparser != nullptr, "No egress deparser block found");

    auto egress_pipeline_converter =
            new ConvertToEbpfPipeline("tc_egress", options, egressParser->to<IR::ParserBlock>(),
                    egressControl->to<IR::ControlBlock>(), egressDeparser->to<IR::ControlBlock>(),
                    refmap, typemap);
    egress->apply(*egress_pipeline_converter);
    auto tcEgress = egress_pipeline_converter->getEbpfPipeline();

    return new PSAArch(xdp, tcIngress, tcEgress);
}

const IR::Node * ConvertToEbpfPSA::preorder(IR::ToplevelBlock *tlb) {
    ebpf_psa_arch = build(tlb);
    return tlb;
}

// =====================EbpfPipeline=============================
// FIXME: probably we shouldn't have ConvertToEbpfPipeline inspector as "block" is not used here.
// We can invoke parser/control/deparser->apply() inside the ConvertToEbpfPSA::build() method.
// If so, EBPFPipeline construct should have the following arguments: EBPFPipeline(name, EBPFParser, EBPFControl, EBPFDeparser).
bool ConvertToEbpfPipeline::preorder(const IR::PackageBlock *block) {
    pipeline = new EBPFPipeline(name, options, refmap, typemap);

    auto parser_converter = new ConvertToEBPFParserPSA(pipeline, refmap, typemap);
    parserBlock->apply(*parser_converter);
    pipeline->parser = parser_converter->getEBPFParser();

    auto control_converter = new ConvertToEBPFControlPSA(pipeline, pipeline->parser->headers, refmap, typemap);
    controlBlock->apply(*control_converter);
    pipeline->control = control_converter->getEBPFControl();
    return true;
}

// =====================EBPFParser=============================
bool ConvertToEBPFParserPSA::preorder(const IR::ParserBlock *prsr) {
    auto pl = prsr->container->type->applyParams;
    parser = new EBPFParser(program, prsr->container, typemap);

    auto it = pl->parameters.begin();
    parser->packet = *it; ++it;
    parser->headers = *it;
    for (auto state : prsr->container->states) {
        auto ps = new EBPFParserState(state, parser);
        parser->states.push_back(ps);
    }

    auto ht = typemap->getType(parser->headers);
    if (ht == nullptr)
        return false;
    parser->headerType = EBPFTypeFactory::instance->create(ht);

    return true;
}

bool ConvertToEBPFParserPSA::preorder(const IR::ParserState *s) {
    return false;
}

// =====================EBPFControl=============================
bool ConvertToEBPFControlPSA::preorder(const IR::ControlBlock *ctrl) {
    control = new EBPFControl(program,
                                    ctrl,
                                    parserHeaders);
    control->hitVariable = refmap->newName("hit");
    auto pl = ctrl->container->type->applyParams;
    auto it = pl->parameters.begin();
    control->headers = *it;

    auto codegen = new ControlBodyTranslator(control);
    codegen->substitute(control->headers, parserHeaders);
    control->codeGen = codegen;

    for (auto a : ctrl->constantValue) {
        auto b = a.second;
        if (b->is<IR::Block>()) {
            this->visit(b->to<IR::Block>());
        }
    }
}

bool ConvertToEBPFControlPSA::preorder(const IR::TableBlock *tblblk) {
    auto tbl = new EBPFTable(program, tblblk, control->codeGen);
    control->tables.emplace(tblblk->container->name, tbl);
}

bool ConvertToEBPFControlPSA::preorder(const IR::P4Action *a) {

}

bool ConvertToEBPFControlPSA::preorder(const IR::Declaration_Instance* instance) {

}

bool ConvertToEBPFControlPSA::preorder(const IR::ExternBlock* instance) {
    if (instance->type->getName().name == "Counter") {
        // FIXME: move to a separate function
        auto node = instance->node;
        if (node->is<IR::Declaration_Instance>()) {
            auto di = node->to<IR::Declaration_Instance>();
            cstring name = EBPFObject::externalName(di);
            auto size = (*di->arguments)[0]->expression->to<IR::Constant>();
            if (!size->fitsInt()) {
                ::error(ErrorType::ERR_OVERLIMIT, "%1%: size too large", size);
                return false;
            }
            auto ctr = new EBPFCounterTable(program, name, control->codeGen, (size_t) size->asInt(), false);
            control->counters.emplace(name, ctr);
        }
    } else {
        ::error(ErrorType::ERR_UNEXPECTED, "Unexpected block %s nested within control",
                instance->toString());
    }
}

};

