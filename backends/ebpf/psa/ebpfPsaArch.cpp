#include "ebpfPsaArch.h"
#include "ebpfPsaParser.h"
#include "ebpfPsaObjects.h"
#include "ebpfPsaControl.h"
#include "ebpfPsaControlTranslators.h"
#include "xdpHelpProgram.h"
#include "externs/ebpfPsaTableImplementation.h"
#include "externs/ebpfPsaCounter.h"
#include "externs/ebpfPsaHashAlgorithm.h"
#include "externs/ebpfPsaRandom.h"
#include "externs/ebpfPsaRegister.h"
#include "externs/ebpfPsaMeter.h"

namespace EBPF {

void PSAArch::emitCommonPreamble(CodeBuilder *builder) const {
    builder->newline();
    builder->appendLine("#define EBPF_MASK(t, w) ((((t)(1)) << (w)) - (t)1)");
    builder->appendLine("#define BYTES(w) ((w) / 8)");
    builder->appendLine(
        "#define write_partial(a, w, s, v) do { *((u8*)a) = ((*((u8*)a)) "
        "& ~(EBPF_MASK(u8, w) << s)) | (v << s) ; } while (0)");
    builder->appendLine("#define write_byte(base, offset, v) do { "
                        "*(u8*)((base) + (offset)) = (v); "
                        "} while (0)");
    builder->target->emitPreamble(builder);
}

void PSAArch::emitPSAIncludes(CodeBuilder *builder) const {
    builder->appendLine("#include <stdbool.h>");
    builder->appendLine("#include <linux/if_ether.h>");
    builder->appendLine("#include \"psa.h\"");
}

/* Generate headers and structs in p4 prog */
void PSAArch::emitTypes(CodeBuilder *builder) const {
    for (auto type : ebpfTypes) {
        type->emit(builder);
    }

    EBPFMeterPSA *meter = getAnyMeter(true, true);
    if (meter != nullptr) {
        meter->emitValueStruct(builder);
    }
}

void PSAArch::emit2TC(CodeBuilder *builder) const {
    /**
     * How the structure of a single C program for PSA should look like?
     * 1. Automatically generated comment
     * 2. Includes
     * 3. Macro definitions (it's called "preamble")
     * 4. Headers, structs, types, PSA-specific data types.
     * 5. BPF map definitions.
     * 6. BPF map initialization
     * 7. XDP helper program.
     * 8. Helper functions
     * 9. TC Ingress program.
     * 10. TC Egress program.
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
    emitPreamble2TC(builder);

    /*
     * 4. Headers, structs, types, PSA-specific data types.
     */
    emitInternalStructures2TC(builder);
    emitTypes(builder);

    /*
     * 5. BPF map definitions.
     */
    emitInstances2TC(builder);

    /*
     * 6. BPF map initialization
     */
    emitInitializer2TC(builder);
    builder->newline();

    /*
     * 7. XDP helper program.
     */
    xdp->emit(builder);

    /*
     * 8. Helper functions for ingress and egress program.
     */
    emitHelperFunctions2TC(builder);

    /*
     * 9. TC Ingress program.
     */
    tcIngress->emit(builder);

    /*
     * 10. TC Egress program.
     */
    tcEgress->emit(builder);

    builder->target->emitLicense(builder, xdp->license);
}

void PSAArch::emitHelperFunctions2TC(CodeBuilder *builder) const {
    EBPFHashAlgorithmTypeFactoryPSA::instance()->emitGlobals(builder);

    cstring forEachFunc ="static __always_inline\n"
                        "int do_for_each(SK_BUFF *skb, void *map, "
                                        "unsigned int max_iter, "
                                        "void (*a)(SK_BUFF *, void *))\n"
                        "{\n"
                        "    elem_t head_idx = {0, 0};\n"
                        "    struct element *elem = bpf_map_lookup_elem(map, &head_idx);\n"
                        "    if (!elem) {\n"
                        "        return -1;\n"
                        "    }\n"
                        "    if (elem->next_id.port == 0 && elem->next_id.instance == 0) {\n"
                        "       %trace_msg_no_elements%"
                        "        return 0;\n"
                        "    }\n"
                        "    elem_t next_id = elem->next_id;\n"
                        "    for (unsigned int i = 0; i < max_iter; i++) {\n"
                        "        struct element *elem = bpf_map_lookup_elem(map, &next_id);\n"
                        "        if (!elem) {\n"
                        "            break;\n"
                        "        }\n"
                        "        a(skb, &elem->entry);\n"
                        "        if (elem->next_id.port == 0 && elem->next_id.instance == 0) {\n"
                        "            break;\n"
                        "        }\n"
                        "        next_id = elem->next_id;\n"
                        "    }\n"
                        "    return 0;\n"
                        "}";
    if (tcIngress->options.emitTraceMessages) {
        forEachFunc = forEachFunc.replace("%trace_msg_no_elements%",
            "        bpf_trace_message(\"do_for_each: No elements found in list\\n\");\n");
    } else {
        forEachFunc = forEachFunc.replace("%trace_msg_no_elements%", "");
    }
    builder->appendLine(forEachFunc);
    builder->newline();

    // Function to perform cloning, common for ingress and egress
    cstring cloneFunction =
            "static __always_inline\n"
            "void do_clone(SK_BUFF *skb, void *data)\n"
            "{\n"
            "    struct clone_session_entry *entry = (struct clone_session_entry *) data;\n"
                "%trace_msg_redirect%"
            "    bpf_clone_redirect(skb, entry->egress_port, 0);\n"
            "}";
    if (tcIngress->options.emitTraceMessages) {
        cloneFunction = cloneFunction.replace(cstring("%trace_msg_redirect%"),
            "    bpf_trace_message(\"do_clone: cloning pkt, egress_port=%d, cos=%d\\n\", "
            "entry->egress_port, entry->class_of_service);\n");
    } else {
        cloneFunction = cloneFunction.replace(cstring("%trace_msg_redirect%"), "");
    }
    builder->appendLine(cloneFunction);
    builder->newline();

    cstring pktClonesFunc =
            "static __always_inline\n"
            "int do_packet_clones(SK_BUFF * skb, void * map, __u32 session_id, "
                "PSA_PacketPath_t new_pkt_path, __u8 caller_id)\n"
            "{\n"
                "%trace_msg_clone_requested%"
            "    struct psa_global_metadata * meta = (struct psa_global_metadata *) skb->cb;\n"
            "    void * inner_map;\n"
            "    inner_map = bpf_map_lookup_elem(map, &session_id);\n"
            "    if (inner_map != NULL) {\n"
            "        PSA_PacketPath_t original_pkt_path = meta->packet_path;\n"
            "        meta->packet_path = new_pkt_path;\n"
            "        if (do_for_each(skb, inner_map, CLONE_MAX_CLONES, &do_clone) < 0) {\n"
                        "%trace_msg_clone_failed%"
            "            return -1;\n"
            "        }\n"
            "        meta->packet_path = original_pkt_path;\n"
            "    } else {\n"
                    "%trace_msg_no_session%"
            "    }\n"
                "%trace_msg_cloning_done%"
            "    return 0;\n"
            " }";
    if (tcIngress->options.emitTraceMessages) {
        pktClonesFunc = pktClonesFunc.replace(cstring("%trace_msg_clone_requested%"),
            "    bpf_trace_message(\"Clone#%d: pkt clone requested, session=%d\\n\", "
            "caller_id, session_id);\n");
        pktClonesFunc = pktClonesFunc.replace(cstring("%trace_msg_clone_failed%"),
            "            bpf_trace_message(\"Clone#%d: failed to clone packet\", caller_id);\n");
        pktClonesFunc = pktClonesFunc.replace(cstring("%trace_msg_no_session%"),
            "        bpf_trace_message(\"Clone#%d: session_id not found, "
            "no clones created\\n\", caller_id);\n");
        pktClonesFunc = pktClonesFunc.replace(cstring("%trace_msg_cloning_done%"),
            "    bpf_trace_message(\"Clone#%d: packet cloning finished\\n\", caller_id);\n");
    } else {
        pktClonesFunc = pktClonesFunc.replace(
                cstring("%trace_msg_clone_requested%"), "");
        pktClonesFunc = pktClonesFunc.replace(cstring("%trace_msg_clone_failed%"),
                                              "");
        pktClonesFunc = pktClonesFunc.replace(cstring("%trace_msg_no_session%"), "");
        pktClonesFunc = pktClonesFunc.replace(cstring("%trace_msg_cloning_done%"), "");
    }

    builder->appendLine(pktClonesFunc);
    builder->newline();

    if (auto meter = getAnyMeter(true, false)) {
        cstring meterExecuteFunc = meter->meterExecuteFunc(tcIngress->options.emitTraceMessages);
        builder->appendLine(meterExecuteFunc);
        builder->newline();
    }
}

void PSAArch::emitInternalStructures2TC(CodeBuilder *pBuilder) const {
    pBuilder->appendLine("struct internal_metadata {\n"
                         "    __u16 pkt_ether_type;\n"
                         "} __attribute__((aligned(4)));");
    pBuilder->newline();

    // emit helper struct for clone sessions
    pBuilder->appendLine("struct list_key_t {\n"
                         "    __u32 port;\n"
                         "    __u16 instance;\n"
                         "};\n"
                         "typedef struct list_key_t elem_t;\n"
                         "\n"
                         "struct element {\n"
                         "    struct clone_session_entry entry;\n"
                         "    elem_t next_id;\n"
                         "} __attribute__((aligned(4)));");
    pBuilder->newline();
}

void PSAArch::emitPreamble2TC(CodeBuilder *builder) const {
    emitCommonPreamble(builder);
    builder->newline();

    builder->appendLine("#define CLONE_MAX_PORTS 64");
    builder->appendLine("#define CLONE_MAX_INSTANCES 1");
    builder->appendLine("#define CLONE_MAX_CLONES (CLONE_MAX_PORTS * CLONE_MAX_INSTANCES)");
    builder->appendLine("#define CLONE_MAX_SESSIONS 1024");
    builder->newline();

    builder->appendLine("#ifndef PSA_PORT_RECIRCULATE\n"
        "#error \"PSA_PORT_RECIRCULATE not specified, "
            "please use -DPSA_PORT_RECIRCULATE=n option to specify index of recirculation "
            "interface (see the result of command 'ip link')\"\n"
        "#endif");
    builder->appendLine("#define P4C_PSA_PORT_RECIRCULATE 0xfffffffa");
    builder->newline();
}

void PSAArch::emitInstances2TC(CodeBuilder *builder) const {
    builder->newline();
    tcIngress->parser->emitTypes(builder);
    tcIngress->control->emitTableTypes(builder);
    tcEgress->parser->emitTypes(builder);
    tcEgress->control->emitTableTypes(builder);
    builder->appendLine("REGISTER_START()");
    if (tcIngress->options.xdp2tcMode == XDP2TC_CPUMAP) {
        builder->target->emitTableDecl(builder, "workaround_cpumap",
                                       TablePerCPUArray, "u32",
                                       "u16", 1);
    }
    builder->target->emitMapInMapDecl(builder, "clone_session_tbl_inner",
            TableHash, "elem_t",
            "struct element", MaxClones, "clone_session_tbl",
            TableArray, "__u32", MaxCloneSessions);
    builder->target->emitMapInMapDecl(builder, "multicast_grp_tbl_inner",
                                      TableHash, "elem_t",
                                      "struct element", MaxClones, "multicast_grp_tbl",
                                      TableArray, "__u32", MaxCloneSessions);

    tcIngress->parser->emitValueSetInstances(builder);
    tcIngress->control->emitTableInstances(builder);
    tcIngress->deparser->emitDigestInstances(builder);

    tcEgress->parser->emitValueSetInstances(builder);
    tcEgress->control->emitTableInstances(builder);

    builder->appendLine("REGISTER_END()");
    builder->newline();
}

void PSAArch::emitInitializer2TC(CodeBuilder *builder) const {
    builder->appendLine("SEC(\"classifier/map-initializer\")");
    builder->appendFormat("int %s()",
                          "map_initializer");
    builder->spc();
    builder->blockStart();
    builder->emitIndent();
    builder->appendFormat("u32 %s = 0;", this->tcIngress->zeroKey.c_str());
    builder->newline();
    tcIngress->control->emitTableInitializers(builder);
    tcEgress->control->emitTableInitializers(builder);
    builder->newline();
    builder->emitIndent();
    builder->appendLine("return 0;");
    builder->blockEnd(true);
}

void PSAArch::emitHelperFunctions2XDP(CodeBuilder *builder) const {
    EBPFHashAlgorithmTypeFactoryPSA::instance()->emitGlobals(builder);

    if (auto meter = getAnyMeter(false, true)) {
        cstring meterExecuteFunc = meter->meterExecuteFunc(
                xdpIngress->options.emitTraceMessages);
        builder->appendLine(meterExecuteFunc);
        builder->newline();
    }
}

void PSAArch::emit2XDP(CodeBuilder *builder) const {
    builder->target->emitIncludes(builder);
    emitPSAIncludes(builder);

    emitPreamble2XDP(builder);

    emitTypes(builder);

    emitInstances2XDP(builder);

    emitHelperFunctions2XDP(builder);

    emitInitializer2XDP(builder);
    xdpIngress->emit(builder);
    xdpEgress->emit(builder);
    builder->newline();

    emitDummy2XDP(builder);

    builder->appendLine("char _license[] SEC(\"license\") = \"GPL\";");
}

void PSAArch::emitPreamble2XDP(CodeBuilder *builder) const {
    emitCommonPreamble(builder);

    builder->newline();
}

void PSAArch::emitInstances2XDP(CodeBuilder *builder) const {
    builder->newline();

    xdpIngress->parser->emitTypes(builder);
    xdpIngress->control->emitTableTypes(builder);
    xdpEgress->parser->emitTypes(builder);
    xdpEgress->control->emitTableTypes(builder);
    builder->newline();

    builder->emitIndent();
    builder->append("struct bpf_map_def SEC(\"maps\") tx_port = ");
    builder->blockStart();
    builder->emitIndent();
    builder->append(".type          = ");
    builder->appendLine("BPF_MAP_TYPE_DEVMAP,");
    builder->emitIndent();
    builder->append(".key_size      = sizeof(int),");
    builder->newline();
    builder->emitIndent();
    builder->appendFormat(".value_size    = sizeof(struct bpf_devmap_val),");
    builder->newline();
    builder->emitIndent();
    builder->appendFormat(".max_entries   = 64,");
    builder->newline();
    builder->blockEnd(false);
    builder->endOfStatement(true);
    builder->newline();

    builder->appendLine("REGISTER_START()");
    xdpIngress->parser->emitValueSetInstances(builder);
    xdpIngress->control->emitTableInstances(builder);
    xdpIngress->deparser->emitDigestInstances(builder);

    xdpEgress->parser->emitValueSetInstances(builder);
    xdpEgress->control->emitTableInstances(builder);

    builder->appendLine("REGISTER_END()");
    builder->newline();
}

void PSAArch::emitInitializer2XDP(CodeBuilder *builder) const {
    builder->appendLine("SEC(\"xdp/map-initializer\")");
    builder->appendFormat("int %s()",
                          "map_initialize");
    builder->spc();
    builder->blockStart();
    builder->emitIndent();
    builder->appendFormat("u32 %s = 0;", this->xdpIngress->zeroKey.c_str());
    builder->newline();
    xdpIngress->control->emitTableInitializers(builder);
    xdpEgress->control->emitTableInitializers(builder);
    builder->newline();
    builder->emitIndent();
    builder->appendLine("return 0;");
    builder->blockEnd(true);
    builder->newline();
}

void PSAArch::emitDummy2XDP(CodeBuilder *builder) const {
    // this is static program, so we can just paste a piece of code.
    builder->appendLine("SEC(\"xdp_redirect_dummy_sec\")");
    builder->append("int xdp_redirect_dummy(struct xdp_md *skb)");
    builder->spc();
    builder->blockStart();
    builder->emitIndent();

    builder->appendLine("return XDP_PASS;");

    builder->blockEnd(true);  // end of function
}

EBPFMeterPSA *PSAArch::getMeter(EBPFPipeline *pipeline) {
    if (pipeline == nullptr) {
        return nullptr;
    }
    if (!pipeline->control->meters.empty()) {
        return pipeline->control->meters.begin()->second;
    }
    auto directMeter = std::find_if(pipeline->control->tables.begin(),
                                    pipeline->control->tables.end(),
                                    [](std::pair<const cstring, EBPFTable*> elem) {
                                        return !elem.second->to<EBPFTablePSA>()->meters.empty();
                                    });
    if (directMeter != pipeline->control->tables.end()) {
        return directMeter->second->to<EBPFTablePSA>()->meters.front().second;
    }
    return nullptr;
}

EBPFMeterPSA *PSAArch::getAnyMeter(bool atTc, bool atXdp) const {
    EBPFMeterPSA *meter;
    if (atTc) {
        meter = getMeter(tcIngress);
        if (meter == nullptr) {
            meter = getMeter(tcEgress);
        }
    }
    if (atXdp) {
        if (meter == nullptr) {
            meter = getMeter(xdpEgress);
        }
        if (meter == nullptr) {
            meter = getMeter(xdpIngress);
        }
    }
    return meter;
}

const PSAArch * ConvertToEbpfPSA::build(IR::ToplevelBlock *tlb) {
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

        // Use special version of error type
        if (d->is<IR::Type_Error>()) {
            auto type = new EBPFErrorTypePSA(d->to<IR::Type_Error>());
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

    if (!options.generateToXDP) {
        auto xdp = new XDPHelpProgram(options);

        auto ingress_pipeline_converter =
            new ConvertToEbpfPipeline("tc-ingress", INGRESS, options,
                ingressParser->to<IR::ParserBlock>(),
                ingressControl->to<IR::ControlBlock>(),
                ingressDeparser->to<IR::ControlBlock>(),
                refmap, typemap);
        ingress->apply(*ingress_pipeline_converter);
        tlb->getProgram()->apply(*ingress_pipeline_converter);
        auto tcIngress = ingress_pipeline_converter->getEbpfPipeline();

        auto egress_pipeline_converter =
            new ConvertToEbpfPipeline("tc-egress", EGRESS, options,
                egressParser->to<IR::ParserBlock>(),
                egressControl->to<IR::ControlBlock>(),
                egressDeparser->to<IR::ControlBlock>(),
                refmap, typemap);
        egress->apply(*egress_pipeline_converter);
        tlb->getProgram()->apply(*egress_pipeline_converter);
        auto tcEgress = egress_pipeline_converter->getEbpfPipeline();

        return new PSAArch(ebpfTypes, xdp, tcIngress, tcEgress);
    } else {
        auto ingress_pipeline_converter =
            new ConvertToEbpfPipeline("xdp-ingress", INGRESS, options,
                ingressParser->to<IR::ParserBlock>(),
                ingressControl->to<IR::ControlBlock>(),
                ingressDeparser->to<IR::ControlBlock>(),
                refmap, typemap);
        ingress->apply(*ingress_pipeline_converter);
        tlb->getProgram()->apply(*ingress_pipeline_converter);
        auto xdpIngress = ingress_pipeline_converter->getEbpfPipeline();
        BUG_CHECK(xdpIngress != nullptr, "Cannot create xdpIngress block.");

        auto egress_pipeline_converter =
            new ConvertToEbpfPipeline("xdp-egress", EGRESS, options,
                egressParser->to<IR::ParserBlock>(),
                egressControl->to<IR::ControlBlock>(),
                egressDeparser->to<IR::ControlBlock>(),
                refmap, typemap);
        egress->apply(*egress_pipeline_converter);
        tlb->getProgram()->apply(*egress_pipeline_converter);
        auto xdpEgress = egress_pipeline_converter->getEbpfPipeline();
        BUG_CHECK(xdpEgress != nullptr, "Cannot create xdpEgress block.");

        return new PSAArch(ebpfTypes, xdpIngress, xdpEgress);
    }
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
    if (!options.generateToXDP) {
        if (type == INGRESS) {
            pipeline = new TCIngressPipeline(name, options, refmap, typemap);
        } else if (type == EGRESS) {
            pipeline = new TCEgressPipeline(name, options, refmap, typemap);
        } else {
            ::error(ErrorType::ERR_INVALID, "unknown type of pipeline");
            return false;
        }
    } else {
        if (type == INGRESS) {
            pipeline = new XDPIngressPipeline(name, options, refmap, typemap);
        } else if (type == EGRESS) {
            pipeline = new XDPEgressPipeline(name, options, refmap, typemap);
        } else {
            ::error(ErrorType::ERR_INVALID, "unknown type of pipeline");
            return false;
        }
    }

    auto parser_converter = new ConvertToEBPFParserPSA(pipeline, refmap, typemap, options);
    parserBlock->apply(*parser_converter);
    pipeline->parser = parser_converter->getEBPFParser();

    auto control_converter = new ConvertToEBPFControlPSA(pipeline,
                                                         pipeline->parser->headers,
                                                         refmap, typemap, options);
    controlBlock->apply(*control_converter);
    pipeline->control = control_converter->getEBPFControl();


    auto deparser_converter = new ConvertToEBPFDeparserPSA(
            pipeline,
            pipeline->parser->headers, pipeline->control->outputStandardMetadata,
            refmap, typemap, options);
    deparserBlock->apply(*deparser_converter);
    pipeline->deparser = deparser_converter->getEBPFPsaDeparser();

    return true;
}

// =====================EBPFParser=============================
bool ConvertToEBPFParserPSA::preorder(const IR::ParserBlock *prsr) {
    auto pl = prsr->container->type->applyParams;
    parser = new EBPFPsaParser(program, prsr->container, typemap);

    auto it = pl->parameters.begin();
    parser->packet = *it; ++it;
    parser->headers = *it;
    auto resubmit_meta = *(it + 3);

    for (auto state : prsr->container->states) {
        auto ps = new EBPFParserState(state, parser);
        parser->states.push_back(ps);
    }

    auto ht = typemap->getType(parser->headers);
    if (ht == nullptr)
        return false;
    parser->headerType = EBPFTypeFactory::instance->create(ht);

    parser->visitor->asPointerVariables.insert(resubmit_meta->name.name);
    if (!options.generateToXDP && this->type == INGRESS) {
        parser->visitor->asPointerVariables.insert(parser->headers->name.name);
    }

    findValueSets(prsr);

    return true;
}

bool ConvertToEBPFParserPSA::preorder(const IR::ParserState *s) {
    return false;
}

void ConvertToEBPFParserPSA::findValueSets(const IR::ParserBlock *prsr) {
    for (auto decl : prsr->container->parserLocals) {
        if (decl->is<IR::P4ValueSet>()) {
            cstring extName = EBPFObject::externalName(decl);
            auto pvs = new EBPFValueSetPSA(program, decl->to<IR::P4ValueSet>(),
                                           extName, parser->visitor);
            parser->valueSets.emplace(decl->name.name, pvs);
        }
    }
}
// =====================EBPFControl=============================
bool ConvertToEBPFControlPSA::preorder(const IR::ControlBlock *ctrl) {
    control = new EBPFControlPSA(program,
                                 ctrl,
                                 parserHeaders);
    program->control = control;
    program->to<EBPFPipeline>()->control = control;
    control->hitVariable = refmap->newName("hit");
    auto pl = ctrl->container->type->applyParams;
    auto it = pl->parameters.begin();
    control->headers = *it; ++it;
    control->user_metadata = *it; ++it;
    control->inputStandardMetadata = *it; ++it;
    control->outputStandardMetadata = *it;

    auto codegen = new ControlBodyTranslatorPSA(control);
    codegen->substitute(control->headers, parserHeaders);
    codegen->asPointerVariables.insert(control->outputStandardMetadata->name.name);
    if (this->type == INGRESS) {
        codegen->asPointerVariables.insert(control->headers->name.name);
    }
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
    // use HASH_MAP as default type
    TableKind tableKind = TableHash;

    bool isTernaryTable = false;
    // If any key field is LPM we will generate an LPM table
    auto keyGenerator = tblblk->container->getKey();
    if (keyGenerator != nullptr) {
        for (auto it : keyGenerator->keyElements) {
            auto mtdecl = refmap->getDeclaration(it->matchType->path, true);
            auto matchType = mtdecl->getNode()->to<IR::Declaration_ID>();
            if (matchType->name.name != P4::P4CoreLibrary::instance.exactMatch.name &&
                matchType->name.name != P4::P4CoreLibrary::instance.lpmMatch.name &&
                matchType->name.name != P4::P4CoreLibrary::instance.ternaryMatch.name &&
                matchType->name.name != "selector")
                ::error(ErrorType::ERR_UNSUPPORTED,
                        "Match of type %1% not supported", it->matchType);

            if (matchType->name.name == P4::P4CoreLibrary::instance.lpmMatch.name) {
                if (tableKind == TableLPMTrie) {
                    ::error(ErrorType::ERR_UNSUPPORTED,
                            "%1%: only one LPM field allowed", it->matchType);
                    return false;
                }
                if (isTernaryTable) {
                    // if at least one field is ternary, the whole table should be ternary
                    continue;
                }
                tableKind = TableLPMTrie;
            } else if (matchType->name.name == P4::P4CoreLibrary::instance.ternaryMatch.name) {
                isTernaryTable = true;
            }
        }
    }

    // use 1024 by default
    size_t size = 1024;
    auto sizeProperty = tblblk->container->properties->getProperty(
            tblblk->container->properties->sizePropertyName);
    if (sizeProperty != nullptr) {
        auto expr = sizeProperty->value->to<IR::ExpressionValue>()->expression;
        size = expr->to<IR::Constant>()->asInt();
    }

    cstring name = EBPFObject::externalName(tblblk->container);

    EBPFTablePSA *table;
    if (isTernaryTable) {
        table = new EBPFTernaryTablePSA(program, tblblk, control->codeGen, name, size);
    } else {
        table = new EBPFTablePSA(program, tblblk, control->codeGen, name, size);
    }

    control->tables.emplace(tblblk->container->name, table);
    return true;
}

bool ConvertToEBPFControlPSA::preorder(const IR::P4Action *a) {
    return true;
}

bool ConvertToEBPFControlPSA::preorder(const IR::Declaration_Instance* instance) {
    return true;
}

bool ConvertToEBPFControlPSA::preorder(const IR::Declaration_Variable* decl) {
    if (decl->type->is<IR::Type_Name>() &&
            decl->type->to<IR::Type_Name>()->path->name.name == "psa_ingress_output_metadata_t") {
        control->codeGen->asPointerVariables.insert(decl->name.name);
    }

    return true;
}

bool ConvertToEBPFControlPSA::preorder(const IR::ExternBlock* instance) {
    auto di = instance->node->to<IR::Declaration_Instance>();
    if (di == nullptr)
        return false;
    cstring name = EBPFObject::externalName(di);
    cstring typeName = instance->type->getName().name;

    if (typeName == "ActionProfile") {
        auto ap = new EBPFActionProfilePSA(program, control->codeGen, di);
        control->tables.emplace(di->name.name, ap);
    } else if (typeName == "ActionSelector") {
        auto ap = new EBPFActionSelectorPSA(program, control->codeGen, di);
        control->tables.emplace(di->name.name, ap);
    } else if (typeName == "Counter") {
        auto ctr = new EBPFCounterPSA(program, di, name, control->codeGen);
        control->counters.emplace(name, ctr);
    } else if (typeName == "DirectCounter") {
        return false;
    } else if (typeName == "Hash") {
        auto hash = new EBPFHashPSA(program, di, name);
        control->hashes.emplace(name, hash);
    } else if (typeName == "Meter") {
        if (options.arch != "psa") {
            BUG("Meters are supported only in PSA architecture");
        }
        auto met = new EBPFMeterPSA(program, name, di, control->codeGen);
        control->meters.emplace(name, met);
    } else if (typeName == "DirectMeter") {
        return false;
    } else if (instance->type->getName().name == "Random") {
        auto rand = new EBPFRandomPSA(di);
        control->randGenerators.emplace(name, rand);
    } else if (typeName == "Register") {
        auto reg = new EBPFRegisterPSA(program, name, di, control->codeGen);
        control->registers.emplace(name, reg);
    } else {
        ::error(ErrorType::ERR_UNEXPECTED, "Unexpected block %s nested within control",
                instance->toString());
    }

    return false;
}

// =====================EBPFDeparser=============================
bool ConvertToEBPFDeparserPSA::preorder(const IR::ControlBlock *ctrl) {
    // if type is INGRESS create IngressDeparser, otherwise create EgressDeparser
    // constructor of ConvertToEBPFDeparserPSA ensures that no other type can be set.
    if (!options.generateToXDP) {
        type == INGRESS ?
            deparser = new TCIngressDeparserPSA(program, ctrl, parserHeaders, istd) :
            deparser = new TCEgressDeparserPSA(program, ctrl, parserHeaders, istd);
    } else {
        type == INGRESS ?
            deparser = new XDPIngressDeparserPSA(program, ctrl, parserHeaders, istd) :
            deparser = new XDPEgressDeparserPSA(program, ctrl, parserHeaders, istd);
    }

    auto codegen = new DeparserBodyTranslator(deparser);
    if (this->type == INGRESS) {
        codegen->asPointerVariables.insert(parserHeaders->name.name);
    }

    deparser->codeGen = codegen;
    if (!deparser->build()) {
        BUG("failed to build deparser");
    }

    if (ctrl->container->is<IR::P4Control>()) {
        auto p4Control = ctrl->container->to<IR::P4Control>();
        findDigests(p4Control);
        this->visit(p4Control->body);
    }

    return false;
}
void ConvertToEBPFDeparserPSA::findDigests(const IR::P4Control *p4Control) {
    // Digests are only at ingress
    if (type == INGRESS) {
        for (auto decl : p4Control->controlLocals) {
            if (decl->is<IR::Declaration_Instance>()) {
                auto di = decl->to<IR::Declaration_Instance>();
                if (di->type->is<IR::Type_Specialized>()) {
                    auto typeSpec = di->type->to<IR::Type_Specialized>();
                    auto baseType = typeSpec->baseType;
                    auto typeName = baseType->to<IR::Type_Name>();
                    auto digest = typeName->path->name.name;
                    if (digest == "Digest") {
                        auto messageArg = typeSpec->arguments->front();
                        auto messageType = typemap->getType(messageArg);
                        deparser->digests.emplace(di->name.name, messageType);
                    }
                }
            }
        }
    }
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
                auto headersStructName = deparser->parserHeaders->name.name;
                if (!options.generateToXDP) {
                    cstring op = this->type == INGRESS ? "->" : ".";
                    deparser->headersExpressions.push_back(headersStructName + op + headerName);
                } else {
                    deparser->headersExpressions.push_back(headersStructName + "." + headerName);
                }

                return false;
            }
        }
    }
    return false;
}

}  // namespace EBPF

