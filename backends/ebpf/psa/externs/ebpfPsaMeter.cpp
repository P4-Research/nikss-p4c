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
    auto bits_64 = new IR::Type_Bits(64, false);
    auto spinLock = new IR::Type_Struct(IR::ID("bpf_spin_lock"));
    vec.push_back(new IR::StructField(IR::ID("pir_period"), bits_64));
    vec.push_back(new IR::StructField(IR::ID("pir_unit_per_period"), bits_64));
    vec.push_back(new IR::StructField(IR::ID("cir_period"), bits_64));
    vec.push_back(new IR::StructField(IR::ID("cir_unit_per_period"), bits_64));
    vec.push_back(new IR::StructField(IR::ID("pbs"), bits_64));
    vec.push_back(new IR::StructField(IR::ID("cbs"), bits_64));
    vec.push_back(new IR::StructField(IR::ID("pbs_left"), bits_64));
    vec.push_back(new IR::StructField(IR::ID("cbs_left"), bits_64));
    vec.push_back(new IR::StructField(IR::ID("time_p"), bits_64));
    vec.push_back(new IR::StructField(IR::ID("time_c"), bits_64));
    vec.push_back(new IR::StructField(IR::ID("lock"), spinLock));
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
    builder->target->emitTableDeclSpinlock(builder, instanceName, TableHash,
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
    if (type == BYTES) {
        builder->appendFormat("meter_execute_bytes(&%s, &%s, &%s, &%s)", instanceName,
                              pipeline->lengthVar.c_str(),
                              indexArgExpr->path->name.name, pipeline->timestampVar.c_str());
    } else {
        builder->appendFormat("meter_execute_packets(&%s, &%s, &%s)", instanceName,
                              indexArgExpr->path->name.name, pipeline->timestampVar.c_str());
    }
}

cstring EBPFMeterPSA::meterExecuteFunc(bool trace) {
    cstring meterExecuteFunc = "static __always_inline\n"
                               "enum PSA_MeterColor_t meter_execute(meter_value *value, "
                               "u32 *packet_len, u64 *time_ns) {\n"
                               "    if (value != NULL) {\n"
                               "        u64 delta_p, delta_c;\n"
                               "        u64 n_periods_p, n_periods_c, tokens_pbs, tokens_cbs;\n"
                               "        bpf_spin_lock(&value->lock);\n"
                               "        delta_p = *time_ns - value->time_p;\n"
                               "        delta_c = *time_ns - value->time_c;\n"
                               "\n"
                               "        n_periods_p = delta_p / value->pir_period;\n"
                               "        n_periods_c = delta_c / value->cir_period;\n"
                               "\n"
                               "        value->time_p += n_periods_p * value->pir_period;\n"
                               "        value->time_c += n_periods_c * value->cir_period;\n"
                               "\n"
                               "        tokens_pbs = value->pbs_left + "
                               "n_periods_p * value->pir_unit_per_period;\n"
                               "        if (tokens_pbs > value->pbs) {\n"
                               "            tokens_pbs = value->pbs;\n"
                               "        }\n"
                               "        tokens_cbs = value->cbs_left + "
                               "n_periods_c * value->cir_unit_per_period;\n"
                               "        if (tokens_cbs > value->cbs) {\n"
                               "            tokens_cbs = value->cbs;\n"
                               "        }\n"
                               "\n"
                               "        if (*packet_len > tokens_pbs) {\n"
                               "            value->pbs_left = tokens_pbs;\n"
                               "            value->cbs_left = tokens_cbs;\n"
                               "            bpf_spin_unlock(&value->lock);\n"
                                            "%trace_msg_meter_red%"
                               "            return RED;\n"
                               "        }\n"
                               "\n"
                               "        if (*packet_len > tokens_cbs) {\n"
                               "            value->pbs_left = tokens_pbs - *packet_len;\n"
                               "            value->cbs_left = tokens_cbs;\n"
                               "            bpf_spin_unlock(&value->lock);\n"
                                            "%trace_msg_meter_yellow%"
                               "            return YELLOW;\n"
                               "        }\n"
                               "\n"
                               "        value->pbs_left = tokens_pbs - *packet_len;\n"
                               "        value->cbs_left = tokens_cbs - *packet_len;\n"
                               "        bpf_spin_unlock(&value->lock);\n"
                                        "%trace_msg_meter_green%"
                               "        return GREEN;\n"
                               "    } else {\n"
                               "        // From P4Runtime spec. No value - return default GREEN.\n"
                                        "%trace_msg_meter_no_value%"
                               "        return GREEN;\n"
                               "    }\n"
                               "}\n"
                               "\n"
                               "static __always_inline\n"
                               "enum PSA_MeterColor_t meter_execute_bytes_value("
                               "meter_value *value, u32 *packet_len, u64 *time_ns) {\n"
                                    "%trace_msg_meter_execute_bytes%"
                               "    return meter_execute(value, packet_len, time_ns);\n"
                               "}\n"
                               "\n"
                               "static __always_inline\n"
                               "enum PSA_MeterColor_t meter_execute_bytes("
                               "void *map, u32 *packet_len, void *key, u64 *time_ns) {\n"
                               "    meter_value *value = BPF_MAP_LOOKUP_ELEM(*map, key);\n"
                               "    return meter_execute_bytes_value(value, packet_len, time_ns);\n"
                               "}\n"
                               "\n"
                               "static __always_inline\n"
                               "enum PSA_MeterColor_t meter_execute_packets_value("
                               "meter_value *value, u64 *time_ns) {\n"
                                    "%trace_msg_meter_execute_packets%"
                               "    u32 len = 1;\n"
                               "    return meter_execute(value, &len, time_ns);\n"
                               "}\n"
                               "\n"
                               "static __always_inline\n"
                               "enum PSA_MeterColor_t meter_execute_packets(void *map, "
                               "void *key, u64 *time_ns) {\n"
                               "    meter_value *value = BPF_MAP_LOOKUP_ELEM(*map, key);\n"
                               "    return meter_execute_packets_value(value, time_ns);\n"
                               "}\n";

    if (trace) {
        meterExecuteFunc = meterExecuteFunc
                .replace(cstring("%trace_msg_meter_green%"),
                         "        bpf_trace_message(\""
                         "Meter: GREEN\\n\");\n");
        meterExecuteFunc = meterExecuteFunc
                .replace(cstring("%trace_msg_meter_yellow%"),
                         "            bpf_trace_message(\""
                         "Meter: YELLOW\\n\");\n");
        meterExecuteFunc = meterExecuteFunc
                .replace(cstring("%trace_msg_meter_red%"),
                         "            bpf_trace_message(\""
                         "Meter: RED\\n\");\n");
        meterExecuteFunc = meterExecuteFunc
                .replace(cstring("%trace_msg_meter_no_value%"),
                         "        bpf_trace_message(\"Meter: No meter value! "
                         "Returning default GREEN\\n\");\n");
        meterExecuteFunc = meterExecuteFunc
                .replace(cstring("%trace_msg_meter_execute_bytes%"),
                         "    bpf_trace_message(\"Meter: execute BYTES\\n\");\n");
        meterExecuteFunc = meterExecuteFunc
                .replace(cstring("%trace_msg_meter_execute_packets%"),
                         "    bpf_trace_message(\"Meter: execute PACKETS\\n\");\n");
    } else {
        meterExecuteFunc = meterExecuteFunc.replace(cstring("%trace_msg_meter_green%"),
                                                    "");
        meterExecuteFunc = meterExecuteFunc.replace(cstring("%trace_msg_meter_yellow%"),
                                                    "");
        meterExecuteFunc = meterExecuteFunc.replace(cstring("%trace_msg_meter_red%"),
                                                    "");
        meterExecuteFunc = meterExecuteFunc.replace(cstring("%trace_msg_meter_no_value%"),
                                                    "");
        meterExecuteFunc = meterExecuteFunc.replace(cstring("%trace_msg_meter_execute_bytes%"),
                                                    "");
        meterExecuteFunc = meterExecuteFunc.replace(cstring("%trace_msg_meter_execute_packets%"),
                                                    "");
    }

    return meterExecuteFunc;
}

}  // namespace EBPF
