#include "ebpfPsaMeter.h"
#include "backends/ebpf/psa/ebpfPipeline.h"

namespace EBPF {

EBPFMeterPSA::EBPFMeterPSA(const EBPFProgram *program,
                           cstring instanceName, const IR::Declaration_Instance* di,
                           CodeGenInspector *codeGen) : EBPFTablePSA(program,
                                                                     codeGen,
                                                                     instanceName) {
    CHECK_NULL(di);
    if (!di->type->is<IR::Type_Specialized>()) {
        ::error(ErrorType::ERR_MODEL, "Missing specialization: %1%", di);
        return;
    }
    auto ts = di->type->to<IR::Type_Specialized>();

    this->keyArg = ts->arguments->at(0);
    this->keyType = EBPFTypeFactory::instance->create(keyArg);

    this->valueTypeName = "meter_value";
    this->valueType = createValueType();

    auto declaredSize = di->arguments->at(0)->expression->to<IR::Constant>();
    if (!declaredSize->fitsUint()) {
        ::error(ErrorType::ERR_OVERLIMIT, "%1%: size too large", declaredSize);
        return;
    }
    size = declaredSize->asUnsigned();

    auto typeExpr = di->arguments->at(1)->expression->to<IR::Constant>();
    this->type = toType(typeExpr->asInt());
}

EBPFMeterPSA::MeterType EBPFMeterPSA::toType(const int typeCode) {
    if (typeCode == 0) {
        return PACKETS;
    } else if (typeCode == 1) {
        return BYTES;
    } else {
        BUG("Unknown meter type %1%", typeCode);
    }
}

EBPFType *EBPFMeterPSA::createValueType() {
    auto vec = IR::IndexedVector<IR::StructField>();
    auto bits_32 = new IR::Type_Bits(32, false);
    auto bits_64 = new IR::Type_Bits(64, false);
    vec.push_back(new IR::StructField(IR::ID("pir"), bits_32));
    vec.push_back(new IR::StructField(IR::ID("cir"), bits_32));
    vec.push_back(new IR::StructField(IR::ID("pbs"), bits_32));
    vec.push_back(new IR::StructField(IR::ID("cbs"), bits_32));
    vec.push_back(new IR::StructField(IR::ID("timestamp"), bits_64));
    vec.push_back(new IR::StructField(IR::ID("pbs_left"), bits_32));
    vec.push_back(new IR::StructField(IR::ID("cbs_left"), bits_32));
    auto valueMeterName = program->refMap->newName("value_meter");
    auto valueStructType = new IR::Type_Struct(IR::ID(valueMeterName), vec);
    return EBPFTypeFactory::instance->create(valueStructType);
}

void EBPFMeterPSA::emitKeyType(CodeBuilder* builder) {
    builder->emitIndent();
    builder->append("typedef ");
    this->keyType->declare(builder, keyTypeName, false);
    builder->endOfStatement(true);
}

void EBPFMeterPSA::emitValueType(CodeBuilder* builder) {
    builder->emitIndent();
    this->valueType->emit(builder);
    builder->append("typedef ");
    this->valueType->declare(builder, valueTypeName, false);
    builder->endOfStatement(true);
}

void EBPFMeterPSA::emitInstance(CodeBuilder *builder) {
    builder->target->emitTableDecl(builder, instanceName, TableHash,
                                   this->keyTypeName,
                                   this->valueTypeName, size);
}

void EBPFMeterPSA::emitExecute(CodeBuilder* builder, const P4::ExternMethod* method) {
    if (method->expr->arguments->size() == 2) {
        ::warning("Color-Aware mode is not supported");
    }
    auto pipeline = dynamic_cast<const EBPFPipeline *>(program);
    if (pipeline == nullptr) {
        ::error(ErrorType::ERR_INVALID, "Meter used outside of pipeline %1%", method->expr);
        return;
    }

    auto indexArgExpr = method->expr->arguments->at(0)->expression->to<IR::PathExpression>();
    // TODO packet len at XDP
    if (type == BYTES) {
        auto packetLen = Util::printf_format("%s->len", pipeline->contextVar.c_str());
        builder->appendFormat("meter_execute_bytes(&%s, &%s, &%s)", instanceName, packetLen,
                              indexArgExpr->path->name.name);
    } else {
        builder->appendFormat("meter_execute_packets(&%s, &%s)", instanceName,
                              indexArgExpr->path->name.name);
    }
}

cstring EBPFMeterPSA::meterExecuteFunc(bool trace) {
    cstring meterExecuteFunc = "static __always_inline\n"
                               "int enough_tokens(u32 *tokens, u32 *packet_len, u32 *bs, "
                               "u32 *bs_left, u32 *ir, u64 *delta_t, u32 *factor) {\n"
                               "\n"
                               "    *tokens = *bs_left + (*delta_t * *ir) / *factor;\n"
                               "\n"
                               "    if (*tokens > *bs) {\n"
                               "        *tokens = *bs;\n"
                               "    }\n"
                               "\n"
                               "    if (*packet_len > *tokens) {\n"
                               "%trace_msg_no_enough_tokens%"
                               "        return 0; // No\n"
                               "    }\n"
                               "\n"
                               "%trace_msg_enough_tokens%"
                               "    return 1; // Yes, enough tokens\n"
                               "}\n"
                               "\n"
                               "static __always_inline\n"
                               "enum PSA_MeterColor_t meter_execute(meter_value *value, "
                               "u32 *packet_len, u32 *factor) {\n"
                               "%trace_msg_meter_execute%"
                               "    u64 time_ns = bpf_ktime_get_ns();\n"
                               "    u64 delta_t = time_ns - value->timestamp;\n"
                               "    u32 tokens_pbs = 0;\n"
                               "    if (enough_tokens(&tokens_pbs, packet_len, &value->pbs, "
                               "&value->pbs_left, &value->pir, &delta_t, factor)) {\n"
                               "        u32 tokens_cbs = 0;\n"
                               "        if (enough_tokens(&tokens_cbs, packet_len, &value->cbs, "
                               "&value->cbs_left, &value->cir, &delta_t, factor)) {\n"
                               "            value->timestamp = value->timestamp + delta_t;\n"
                               "            value->pbs_left = tokens_pbs - *packet_len;\n"
                               "            value->cbs_left = tokens_cbs - *packet_len;\n"
                               "%trace_msg_meter_green%"
                               "            return GREEN;\n"
                               "        } else {\n"
                               "            value->timestamp = value->timestamp + delta_t;\n"
                               "            value->pbs_left = tokens_pbs - *packet_len;\n"
                               "%trace_msg_meter_yellow%"
                               "            return YELLOW;\n"
                               "        }\n"
                               "    } else {\n"
                               "%trace_msg_meter_red%"
                               "        return RED;\n"
                               "    }\n"
                               "}\n"
                               "\n"
                               "static __always_inline\n"
                               "enum PSA_MeterColor_t meter_execute_bytes_value(meter_value *value,"
                               "u32 *packet_len) {\n"
                               "    u32 factor = 8000000;\n"
                               "    if (value != NULL) {\n"
                               "        return meter_execute(value, packet_len, &factor);\n"
                               "    } else {\n"
                               "%trace_msg_meter_no_value%"
                               "        return RED;\n"
                               "    }\n"
                               "}\n"
                               "\n"
                               "static __always_inline\n"
                               "enum PSA_MeterColor_t meter_execute_bytes(void *map, "
                               "u32 *packet_len, void *key) {\n"
                               "    meter_value *value = BPF_MAP_LOOKUP_ELEM(*map, key);\n"
                               "    return meter_execute_bytes_value(value, packet_len);\n"
                               "}\n"
                               "\n"
                               "static __always_inline\n"
                               "enum PSA_MeterColor_t meter_execute_packets_value("
                               "meter_value *value) {\n"
                               "    u32 len = 1;\n"
                               "    u32 factor = 1000000000;\n"
                               "    if (value != NULL) {\n"
                               "        return meter_execute(value, &len, &factor);\n"
                               "    } else {\n"
                               "%trace_msg_meter_no_value%"
                               "        return RED;\n"
                               "    }\n"
                               "}\n"
                               "\n"
                               "static __always_inline\n"
                               "enum PSA_MeterColor_t meter_execute_packets(void *map, "
                               "void *key) {\n"
                               "    meter_value *value = BPF_MAP_LOOKUP_ELEM(*map, key);\n"
                               "    return meter_execute_packets_value(value);\n"
                               "}";

    if (trace) {
        meterExecuteFunc = meterExecuteFunc
                .replace(cstring("%trace_msg_no_enough_tokens%"),
                         "        bpf_trace_message(\""
                         "Meter: No enough tokens\");\n");
        meterExecuteFunc = meterExecuteFunc
                .replace(cstring("%trace_msg_enough_tokens%"),
                         "        bpf_trace_message(\""
                         "Meter: Enough tokens\");\n");
        meterExecuteFunc = meterExecuteFunc
                .replace(cstring("%trace_msg_meter_execute%"),
                         "    bpf_trace_message(\""
                         "Meter: execute\");\n");
        meterExecuteFunc = meterExecuteFunc
                .replace(cstring("%trace_msg_meter_green%"),
                         "                bpf_trace_message(\""
                         "Meter: GREEN\");\n");
        meterExecuteFunc = meterExecuteFunc
                .replace(cstring("%trace_msg_meter_yellow%"),
                         "                bpf_trace_message(\""
                         "Meter: YELLOW\");\n");
        meterExecuteFunc = meterExecuteFunc
                .replace(cstring("%trace_msg_meter_red%"),
                         "        bpf_trace_message(\""
                         "Meter: RED\");\n");
        meterExecuteFunc = meterExecuteFunc
                .replace(cstring("%trace_msg_meter_no_value%"),
                         "        bpf_trace_message(\""
                         "Meter: No meter value!\");\n");
    } else {
        meterExecuteFunc = meterExecuteFunc.replace(cstring("%trace_msg_no_enough_tokens%"),
                                                    "");
        meterExecuteFunc = meterExecuteFunc.replace(cstring("%trace_msg_enough_tokens%"),
                                                    "");
        meterExecuteFunc = meterExecuteFunc.replace(cstring("%trace_msg_meter_execute%"),
                                                    "");
        meterExecuteFunc = meterExecuteFunc.replace(cstring("%trace_msg_meter_green%"),
                                                    "");
        meterExecuteFunc = meterExecuteFunc.replace(cstring("%trace_msg_meter_yellow%"),
                                                    "");
        meterExecuteFunc = meterExecuteFunc.replace(cstring("%trace_msg_meter_red%"),
                                                    "");
        meterExecuteFunc = meterExecuteFunc.replace(cstring("%trace_msg_meter_no_value%"),
                                                    "");
    }

    return meterExecuteFunc;
}

}  // namespace EBPF
