#include "ebpfPsaMeter.h"
#include "backends/ebpf/psa/ebpfPipeline.h"

namespace EBPF {

EBPFMeterPSA::EBPFMeterPSA(const EBPFProgram *program,
                           cstring instanceName, const IR::Declaration_Instance* di,
                           CodeGenInspector *codeGen) : EBPFTablePSA(program,
                                                                     codeGen,
                                                                     instanceName) {
    CHECK_NULL(di);
    auto typeName = di->type->toString();
    if (typeName == "DirectMeter") {
        isDirect = true;
    } else if (typeName.startsWith("Meter")) {
        isDirect = false;
        auto ts = di->type->to<IR::Type_Specialized>();
        this->keyArg = ts->arguments->at(0);
        this->keyType = EBPFTypeFactory::instance->create(keyArg);

        auto declaredSize = di->arguments->at(0)->expression->to<IR::Constant>();
        if (!declaredSize->fitsUint()) {
            ::error(ErrorType::ERR_OVERLIMIT, "%1%: size too large", declaredSize);
            return;
        }
        size = declaredSize->asUnsigned();
    } else {
        ::error(ErrorType::ERR_INVALID, "Not known Meter type: %1%", di);
        return;
    }

    auto typeExpr = di->arguments->at(isDirect ? 0 : 1)->expression->to<IR::Constant>();
    this->type = toType(typeExpr->asInt());
}

EBPFType * EBPFMeterPSA::getBaseValueType() const {
    IR::IndexedVector<IR::StructField> vec = getValueFields();
    auto valueStructType = new IR::Type_Struct(
            IR::ID(getBaseStructName()), vec);
    return EBPFTypeFactory::instance->create(valueStructType);
}

EBPFType * EBPFMeterPSA::getIndirectValueType() const {
    auto vec = IR::IndexedVector<IR::StructField>();

    auto baseValue = new IR::Type_Struct(IR::ID(getBaseStructName()));
    vec.push_back(new IR::StructField(IR::ID(indirectValueField), baseValue));

    IR::Type_Struct *spinLock = createSpinlockStruct();
    vec.push_back(new IR::StructField(IR::ID(spinlockField), spinLock));

    auto valueType = new IR::Type_Struct(
            IR::ID(getIndirectStructName()), vec);
    auto meterType = EBPFTypeFactory::instance->create(valueType);

    return meterType;
}

cstring EBPFMeterPSA::getBaseStructName() const {
    static cstring valueBaseStructName;

    if (valueBaseStructName.isNullOrEmpty()) {
        valueBaseStructName = program->refMap->newName("meter_value");
    }

    return valueBaseStructName;
}

cstring EBPFMeterPSA::getIndirectStructName() const {
    static cstring valueIndirectStructName;

    if (valueIndirectStructName.isNullOrEmpty()) {
        valueIndirectStructName = program->refMap->newName("indirect_meter");
    }

    return valueIndirectStructName;
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

IR::IndexedVector<IR::StructField> EBPFMeterPSA::getValueFields() {
    auto vec = IR::IndexedVector<IR::StructField>();
    auto bits_64 = new IR::Type_Bits(64, false);
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
    return vec;
}

IR::Type_Struct *EBPFMeterPSA::createSpinlockStruct() {
    auto spinLock = new IR::Type_Struct(IR::ID("bpf_spin_lock"));
    return spinLock;
}

void EBPFMeterPSA::emitSpinLockField(CodeBuilder* builder) {
    auto spinlockStruct = createSpinlockStruct();
    auto spinlockType = EBPFTypeFactory::instance->create(spinlockStruct);
    builder->emitIndent();
    spinlockType->declare(builder, spinlockField, false);
    builder->endOfStatement(true);
}

void EBPFMeterPSA::emitKeyType(CodeBuilder* builder) {
    builder->emitIndent();
    builder->append("typedef ");
    this->keyType->declare(builder, keyTypeName, false);
    builder->endOfStatement(true);
}

void EBPFMeterPSA::emitValueStruct(CodeBuilder* builder) {
    builder->emitIndent();
    getBaseValueType()->emit(builder);
}
void EBPFMeterPSA::emitValueType(CodeBuilder* builder) {
    if (isDirect) {
        builder->emitIndent();
        getBaseValueType()->declare(builder, instanceName, false);
        builder->endOfStatement(true);
    } else {
        getIndirectValueType()->emit(builder);
    }
}

void EBPFMeterPSA::emitInstance(CodeBuilder *builder) {
    if (!isDirect) {
        builder->target->emitTableDeclSpinlock(builder, instanceName, TableHash,
                                               this->keyTypeName,
                                               "struct " + getIndirectStructName(), size);
    } else {
        ::error(ErrorType::ERR_UNEXPECTED, "Direct meter belongs to table "
                                           "and cannot have own instance");
    }
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

    cstring index = getIndexString(method);

    if (type == BYTES) {
        builder->appendFormat("meter_execute_bytes(&%s, &%s, %s, &%s)", instanceName,
                              pipeline->lengthVar.c_str(),
                              index, pipeline->timestampVar.c_str());
    } else {
        builder->appendFormat("meter_execute_packets(&%s, %s, &%s)", instanceName,
                              index, pipeline->timestampVar.c_str());
    }
}

cstring EBPFMeterPSA::getIndexString(const P4::ExternMethod *method) const {
    if (method->expr->arguments->at(0)->expression->is<IR::PathExpression>()) {
        auto indexArgExpr = method->expr->arguments->at(0)->expression->to<IR::PathExpression>();
        return "&" + indexArgExpr->path->name.name;
    } else if (method->expr->arguments->at(0)->expression->is<IR::Constant>()) {
        auto indexArgExpr = method->expr->arguments->at(0)->expression->to<IR::Constant>();
        return Util::printf_format("&(u32){%s}", Util::toString(indexArgExpr->value, 0, false));
    } else {
        ::error(ErrorType::ERR_INVALID, "Invalid meter index expression %1%",
                method->expr->arguments->at(0)->expression);
        return cstring::empty;
    }
}

void EBPFMeterPSA::emitDirectExecute(CodeBuilder *builder,
                                     const P4::ExternMethod *method,
                                     cstring valuePtr) {
    auto pipeline = dynamic_cast<const EBPFPipeline *>(program);
    if (pipeline == nullptr) {
        ::error(ErrorType::ERR_INVALID, "Meter used outside of pipeline %1%", method->expr);
        return;
    }

    cstring lockVar = valuePtr + "->" + spinlockField;
    cstring valueMeter = valuePtr + "->" + instanceName;
    if (type == BYTES) {
        builder->appendFormat("meter_execute_bytes_value(&%s, &%s, &%s, &%s)",
                              valueMeter,
                              lockVar,
                              pipeline->lengthVar.c_str(),
                              pipeline->timestampVar.c_str());
    } else {
        builder->appendFormat("meter_execute_packets_value(&%s, &%s, &%s)",
                              valueMeter,
                              lockVar,
                              pipeline->timestampVar.c_str());
    }
}

cstring EBPFMeterPSA::meterExecuteFunc(bool trace) {
    cstring meterExecuteFunc = "static __always_inline\n"
                               "enum PSA_MeterColor_t meter_execute(%meter_struct% *value, "
                               "void *lock, "
                               "u32 *packet_len, u64 *time_ns) {\n"
                               "    if (value != NULL && value->pir_period != 0) {\n"
                               "        u64 delta_p, delta_c;\n"
                               "        u64 n_periods_p, n_periods_c, tokens_pbs, tokens_cbs;\n"
                               "        bpf_spin_lock(lock);\n"
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
                               "            bpf_spin_unlock(lock);\n"
                                            "%trace_msg_meter_red%"
                               "            return RED;\n"
                               "        }\n"
                               "\n"
                               "        if (*packet_len > tokens_cbs) {\n"
                               "            value->pbs_left = tokens_pbs - *packet_len;\n"
                               "            value->cbs_left = tokens_cbs;\n"
                               "            bpf_spin_unlock(lock);\n"
                                            "%trace_msg_meter_yellow%"
                               "            return YELLOW;\n"
                               "        }\n"
                               "\n"
                               "        value->pbs_left = tokens_pbs - *packet_len;\n"
                               "        value->cbs_left = tokens_cbs - *packet_len;\n"
                               "        bpf_spin_unlock(lock);\n"
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
                               "void *value, void *lock, u32 *packet_len, "
                               "u64 *time_ns) {\n"
                                    "%trace_msg_meter_execute_bytes%"
                               "    return meter_execute(value, lock, packet_len, time_ns);\n"
                               "}\n"
                               "\n"
                               "static __always_inline\n"
                               "enum PSA_MeterColor_t meter_execute_bytes("
                               "void *map, u32 *packet_len, void *key, u64 *time_ns) {\n"
                               "    %meter_struct% *value = BPF_MAP_LOOKUP_ELEM(*map, key);\n"
                               "    return meter_execute_bytes_value(value, ((void *)value) + "
                               "sizeof(%meter_struct%), "
                               "packet_len, time_ns);\n"
                               "}\n"
                               "\n"
                               "static __always_inline\n"
                               "enum PSA_MeterColor_t meter_execute_packets_value("
                               "void *value, void *lock, u64 *time_ns) {\n"
                                    "%trace_msg_meter_execute_packets%"
                               "    u32 len = 1;\n"
                               "    return meter_execute(value, lock, &len, time_ns);\n"
                               "}\n"
                               "\n"
                               "static __always_inline\n"
                               "enum PSA_MeterColor_t meter_execute_packets(void *map, "
                               "void *key, u64 *time_ns) {\n"
                               "    %meter_struct% *value = BPF_MAP_LOOKUP_ELEM(*map, key);\n"
                               "    return meter_execute_packets_value(value, ((void *)value) + "
                               "sizeof(%meter_struct%), "
                               "time_ns);\n"
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

    meterExecuteFunc = meterExecuteFunc.replace(cstring("%meter_struct%"),
                                                cstring("struct ") + getBaseStructName());

    return meterExecuteFunc;
}

}  // namespace EBPF
