#include "ebpfPsaArch.h"
#include "ebpfPsaParser.h"
#include "backends/ebpf/ebpfControl.h"
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
    emitPSAIncludes(builder);

    /*
     * 3. Macro definitions (it's called "preamble")
     */
    emitPreamble(builder);

    /*
     * 4. Headers, structs, types, PSA-specific data types.
     */
    emitInternalMetadata(builder);
    emitTypes(builder);

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

void PSAArch::emitPSAIncludes(CodeBuilder *builder) const {
    builder->appendLine("#include <stdbool.h>");
    builder->appendLine("#include <linux/if_ether.h>");
    builder->appendLine("#include \"psa.h\"");
    builder->newline();
}

void PSAArch::emitInternalMetadata(CodeBuilder *pBuilder) const {
    pBuilder->appendLine("struct internal_metadata {\n"
                         "    __u16 pkt_ether_type;\n"
                         "};");
    pBuilder->newline();
}

void PSAArch::emitTypes(CodeBuilder *builder) const {
    for (auto type : ebpfTypes) {
        type->emit(builder);
    }
}

void PSAArch::emitPreamble(CodeBuilder *builder) const {
    builder->newline();
    builder->appendLine("#define EBPF_MASK(t, w) ((((t)(1)) << (w)) - (t)1)");
    builder->appendLine("#define BYTES(w) ((w) / 8)");
    builder->appendLine(
            "#define write_partial(a, s, v) do "
            "{ u8 mask = EBPF_MASK(u8, s); "
            "*((u8*)a) = ((*((u8*)a)) & ~mask) | (((v) >> (8 - (s))) & mask); "
            "} while (0)");
    builder->appendLine("#define write_byte(base, offset, v) do { "
                        "*(u8*)((base) + (offset)) = (v); "
                        "} while (0)");
    builder->newline();
}

const PSAArch * ConvertToEbpfPSA::build(IR::ToplevelBlock *tlb) {
    auto xdp = new XDPProgram(options);

    /*
     * TYPES
     */
    std::vector<EBPFType*> ebpfTypes;
    for (auto d : tlb->getProgram()->objects) {
        if (d->is<IR::Type>() && !d->is<IR::IContainer>() &&
            !d->is<IR::Type_Extern>() && !d->is<IR::Type_Parser>() &&
            !d->is<IR::Type_Control>() && !d->is<IR::Type_Typedef>() &&
            !d->is<IR::Type_Error>()) {
            if (d->srcInfo.isValid()) {
                auto sourceFile = d->srcInfo.getSourceFile();
                if (sourceFile.endsWith("p4include/psa.p4")) {
                    // do not generate standard PSA types
                    continue;
                }
            }

            auto type = EBPFTypeFactory::instance->create(d->to<IR::Type>());
            if (type == nullptr)
                continue;
            ebpfTypes.push_back(type);
        }
    }

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
           new ConvertToEbpfPipeline("tc-ingress", options, ingressParser->to<IR::ParserBlock>(),
                   ingressControl->to<IR::ControlBlock>(), ingressDeparser->to<IR::ControlBlock>(),
                   refmap, typemap);
    ingress->apply(*ingress_pipeline_converter);
    tlb->getProgram()->apply(*ingress_pipeline_converter);
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
            new ConvertToEbpfPipeline("tc-egress", options, egressParser->to<IR::ParserBlock>(),
                    egressControl->to<IR::ControlBlock>(), egressDeparser->to<IR::ControlBlock>(),
                    refmap, typemap);
    egress->apply(*egress_pipeline_converter);
    tlb->getProgram()->apply(*egress_pipeline_converter);
    auto tcEgress = egress_pipeline_converter->getEbpfPipeline();

    return new PSAArch(ebpfTypes, xdp, tcIngress, tcEgress);
}

const IR::Node * ConvertToEbpfPSA::preorder(IR::ToplevelBlock *tlb) {
    ebpf_psa_arch = build(tlb);
    return tlb;
}

// =====================EbpfPipeline=============================
// FIXME: probably we shouldn't have ConvertToEbpfPipeline inspector as "block" is not used here.
// We can invoke parser/control/deparser->apply() inside the ConvertToEbpfPSA::build() method.
// If so, EBPFPipeline construct should have the following arguments:
// EBPFPipeline(name, EBPFParser, EBPFControl, EBPFDeparser).
bool ConvertToEbpfPipeline::preorder(const IR::PackageBlock *block) {
    pipeline = new EBPFPipeline(name, options, refmap, typemap);

    auto parser_converter = new ConvertToEBPFParserPSA(pipeline, refmap, typemap);
    parserBlock->apply(*parser_converter);
    pipeline->parser = parser_converter->getEBPFParser();

    auto control_converter = new ConvertToEBPFControlPSA(pipeline,
                                                         pipeline->parser->headers,
                                                         refmap, typemap);
    controlBlock->apply(*control_converter);
    pipeline->control = control_converter->getEBPFControl();

    auto deparser_converter = new ConvertToEBPFDeparserPSA(pipeline, pipeline->parser->headers, refmap, typemap);
    deparserBlock->apply(*deparser_converter);
    pipeline->deparser = deparser_converter->getEBPFPsaDeparser();

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
    return true;
}

bool ConvertToEBPFControlPSA::preorder(const IR::TableBlock *tblblk) {
    auto tbl = new EBPFTable(program, tblblk, control->codeGen);
    control->tables.emplace(tblblk->container->name, tbl);
    return true;
}

bool ConvertToEBPFControlPSA::preorder(const IR::P4Action *a) {
    return true;
}

bool ConvertToEBPFControlPSA::preorder(const IR::Declaration_Instance* instance) {
    return true;
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
            auto ctr = new EBPFCounterTable(program, name,
                    control->codeGen, (size_t) size->asInt(), false);
            control->counters.emplace(name, ctr);
        }
    } else {
        ::error(ErrorType::ERR_UNEXPECTED, "Unexpected block %s nested within control",
                instance->toString());
        return false;
    }
    return true;
}


bool ConvertToEBPFDeparserPSA::preorder(const IR::ControlBlock *ctrl) {
    deparser = new EBPFPsaDeparser(program, ctrl->container, parserHeaders);
    bool success = deparser->build();
    if (!success) {
        return false;
    }

    if (ctrl->container->is<IR::P4Control>()) {
        auto p4Control = ctrl->container->to<IR::P4Control>();

        this->visit(p4Control->body);
    }

    return false;
}

bool ConvertToEBPFDeparserPSA::preorder(const IR::MethodCallExpression *expression) {
    auto mi = P4::MethodInstance::resolve(expression,
                                          deparser->program->refMap,
                                          deparser->program->typeMap);
    auto extMethod = mi->to<P4::ExternMethod>();
    if (extMethod != nullptr) {
        auto decl = extMethod->object;
        if (decl == deparser->packet_out) {
            if (extMethod->method->name.name == p4lib.packetOut.emit.name) {
                auto expr = extMethod->expr->arguments->at(0)->expression;
                auto type = deparser->program->typeMap->getType(expr);
                auto ht = type->to<IR::Type_Header>();
                if (ht == nullptr) {
                    ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                            "Cannot emit a non-header type %1%", expr);
                    return false;
                }
                deparser->headersToEmit.push_back(ht);
                auto exprMemb = expr->to<IR::Member>();
                auto headerName = exprMemb->member.name;
                auto headersStructName = exprMemb->expr->to<IR::PathExpression>()->path->name.name;
                deparser->headersExpressions.push_back(headersStructName + "." + headerName);
                return false;
            }
        }
    }
    return false;
}
bool ConvertToEBPFDeparserPSA::preorder(const IR::AssignmentStatement *a) {
    return false;
}

bool ConvertToEBPFDeparserPSA::preorder(const IR::ExitStatement *s) {
    return false;
}

};

}  // namespace EBPF
