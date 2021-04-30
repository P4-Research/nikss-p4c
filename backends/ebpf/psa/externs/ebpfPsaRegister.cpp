#include "ebpfPsaRegister.h"

namespace EBPF {

EBPFRegisterPSA::EBPFRegisterPSA(const EBPFProgram *program,
                                 cstring instanceName, const IR::Declaration_Instance* di,
                                 CodeGenInspector *codeGen) : EBPFTableBase(program,
                                                                            instanceName,
                                                                            codeGen) {
    CHECK_NULL(di);
    if (!di->type->is<IR::Type_Specialized>()) {
        ::error(ErrorType::ERR_MODEL, "Missing specialization: %1%", di);
        return;
    }
    auto ts = di->type->to<IR::Type_Specialized>();

    this->keyArg = ts->arguments->at(1);
    this->valueArg = ts->arguments->at(0);
    this->keyType = EBPFTypeFactory::instance->create(keyArg);
    this->valueType = EBPFTypeFactory::instance->create(valueArg);

    if (keyArg->is<IR::Type_Bits>()) {
        unsigned keyWidth = keyArg->width_bits();
        // For keys <= 32 bit register is based on array map,
        // otherwise we use hash map
        arrayMapBased = (keyWidth <= 32);
    }

    auto declaredSize = di->arguments->at(0)->expression->to<IR::Constant>();
    if (!declaredSize->fitsUint()) {
        ::error(ErrorType::ERR_OVERLIMIT, "%1%: size too large", declaredSize);
        return;
    }
    size = declaredSize->asUnsigned();

    if (di->arguments->size() == 2) {
        this->initialValue = di->arguments->at(1)->expression->to<IR::Constant>();
    }
}

void EBPFRegisterPSA::emitTypes(CodeBuilder* builder) {
    emitKeyType(builder);
    emitValueType(builder);
}

void EBPFRegisterPSA::emitKeyType(CodeBuilder* builder) {
    builder->emitIndent();
    builder->append("typedef ");
    this->keyType->declare(builder, keyTypeName, false);
    builder->endOfStatement(true);
}

void EBPFRegisterPSA::emitValueType(CodeBuilder* builder) {
    builder->emitIndent();
    builder->append("typedef ");
    this->valueType->declare(builder, valueTypeName, false);
    builder->endOfStatement(true);
}

void EBPFRegisterPSA::emitInitializer(CodeBuilder* builder) {
    if (arrayMapBased && this->initialValue != nullptr) {
        auto ret = program->refMap->newName("ret");
        cstring keyName = program->refMap->newName("key");
        cstring valueName = program->refMap->newName("value");

        builder->emitIndent();
        builder->appendFormat("%s %s", keyTypeName.c_str(), keyName.c_str());
        builder->endOfStatement(true);

        builder->emitIndent();
        builder->appendFormat("%s %s = ", valueTypeName.c_str(), valueName.c_str());
        //TODO nie inicjalizuj jak zero
        builder->append(this->initialValue->value.str());
        builder->endOfStatement(true);

        builder->emitIndent();
        builder->appendFormat("for (size_t index = 0; index < %u; index++) ", this->size);
        builder->blockStart();
        builder->emitIndent();
        builder->appendFormat("%s = index", keyName.c_str());
        builder->endOfStatement(true);
        builder->emitIndent();
        builder->appendFormat("int %s = ", ret.c_str());
        builder->target->emitTableUpdate(builder, instanceName,
                                         keyName, valueName);
        builder->newline();

        builder->emitIndent();
        builder->appendFormat("if (%s) ", ret.c_str());
        builder->blockStart();
        cstring msgStr = Util::printf_format(
                "Map initializer: Error while map (%s) update, code: %s", instanceName, "%d");
        builder->target->emitTraceMessage(builder, msgStr,
                                          1, ret.c_str());

        builder->blockEnd(true);

        builder->blockEnd(true);
    }
}

void EBPFRegisterPSA::emitInstance(CodeBuilder *builder) {
    builder->target->emitTableDecl(builder, instanceName, TableHash,
                                   this->keyTypeName,
                                   this->valueTypeName, size);
}

void EBPFRegisterPSA::emitRegisterRead(CodeBuilder* builder, const P4::ExternMethod* method,
                                       ControlBodyTranslatorPSA* translator, const IR::Expression* leftExpression) {
    auto indexArg = method->expr->arguments->at(0)->expression->to<IR::PathExpression>();
    cstring indexParamStr = translator->getIndexActionParam(indexArg);
    BUG_CHECK(!indexParamStr.isNullOrEmpty(), "Index param cannot be empty");
    BUG_CHECK(leftExpression != nullptr, "Register read must be with left assigment");

    cstring valueName = program->refMap->newName("value");
    cstring msgStr, varStr;

    auto pipeline = dynamic_cast<const EBPFPipeline *>(program);
    if (pipeline == nullptr) {
        ::error(ErrorType::ERR_UNSUPPORTED, "Register used outside of pipeline %1%", method->expr);
        return;
    }

    builder->emitIndent();
    this->valueType->declare(builder, valueName, true);
    builder->endOfStatement(true);

    msgStr = Util::printf_format("Register: reading %s",
                                 instanceName.c_str());
    builder->target->emitTraceMessage(builder, msgStr.c_str());

    builder->emitIndent();
    builder->target->emitTableLookup(builder, dataMapName, indexParamStr, valueName);
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->appendFormat("if (%s != NULL) ", valueName.c_str());
    builder->blockStart();
    builder->emitIndent();
    codeGen->visit(leftExpression);
    builder->appendFormat(" = *%s", valueName);
    builder->endOfStatement(true);
    builder->target->emitTraceMessage(builder, "Register: Entry found!");
    builder->blockEnd(false);
    builder->appendFormat(" else ");
    builder->blockStart();
    builder->emitIndent();

    codeGen->visit(leftExpression);
    builder->append(" = ");
    if (this->initialValue != nullptr) {
        builder->append(this->initialValue->value.str());
    } else {
        builder->append("(");
        this->valueType->declare(builder, cstring::empty, false);
        builder->append(")");
        this->valueType->emitInitializer(builder);
    }
    builder->endOfStatement(true);

    builder->target->emitTraceMessage(builder, "Register: Entry not found, using default value");
    builder->blockEnd(true);
}

void EBPFRegisterPSA::emitRegisterWrite(CodeBuilder* builder, const P4::ExternMethod* method,
                                        ControlBodyTranslatorPSA* translator) {
    auto indexArgExpr = method->expr->arguments->at(0)->expression->to<IR::PathExpression>();
    cstring indexParamStr = translator->getIndexActionParam(indexArgExpr);
    auto valueArgExpr = method->expr->arguments->at(1)->expression->to<IR::PathExpression>();
    cstring valueParamStr = translator->getValueActionParam(valueArgExpr);
    BUG_CHECK(!indexParamStr.isNullOrEmpty(), "Index param cannot be empty");
    BUG_CHECK(!valueParamStr.isNullOrEmpty(), "Value param cannot be empty");

    cstring msgStr, varStr;

    auto pipeline = dynamic_cast<const EBPFPipeline *>(program);
    if (pipeline == nullptr) {
        ::error(ErrorType::ERR_UNSUPPORTED, "Register used outside of pipeline %1%", method->expr);
        return;
    }

    msgStr = Util::printf_format("Register: writing %s",
                                 instanceName.c_str());
    builder->target->emitTraceMessage(builder, msgStr.c_str());

    builder->emitIndent();
    auto ret = program->refMap->newName("ret");
    builder->appendFormat("int %s = ", ret.c_str());
    builder->target->emitTableUpdate(builder, instanceName, indexParamStr, valueParamStr);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("if (%s) ", ret.c_str());
    builder->blockStart();
    msgStr = Util::printf_format(
            "Register: Error while map (%s) update, code: %s", instanceName, "%d");
    builder->target->emitTraceMessage(builder, msgStr,
                                      1, ret.c_str());

    builder->blockEnd(true);
}

}  // namespace EBPF
