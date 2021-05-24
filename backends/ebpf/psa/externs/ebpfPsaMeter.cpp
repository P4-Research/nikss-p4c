#include "ebpfPsaMeter.h"
#include "backends/ebpf/psa/ebpfPipeline.h"
#include "backends/ebpf/psa/ebpfPsaControlTranslators.h"

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
    auto valueStructType = new IR::Type_Struct(IR::ID(this->valueTypeName), vec);
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
    builder->append("typedef ");
    this->valueType->emit(builder);
}

void EBPFMeterPSA::emitInstance(CodeBuilder *builder) {
    builder->target->emitTableDecl(builder, instanceName, TableArray,
                                   this->keyTypeName,
                                   this->valueTypeName, size);
}

void EBPFMeterPSA::emitExecute(CodeBuilder* builder, const P4::ExternMethod* method) {
    auto indexArgExpr = method->expr->arguments->at(0)->expression->to<IR::PathExpression>();
    // TODO check skb->len
    if (type == BYTES) {
        builder->appendFormat("meter_execute_bytes(&%s, &%s, &%s)", instanceName, "skb->len", indexArgExpr->path->name.name);
    } else {
        builder->appendFormat("meter_execute_packets(&%s, &%s)", instanceName, indexArgExpr->path->name.name);
    }
}

}  // namespace EBPF