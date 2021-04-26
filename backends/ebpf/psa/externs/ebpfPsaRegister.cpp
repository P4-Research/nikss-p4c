#include "ebpfPsaRegister.h"

namespace EBPF {

EBPFRegisterPSA::EBPFRegisterPSA(const EBPFProgram *program,
                                 cstring instanceName, const IR::Declaration_Instance* di,
                                 CodeGenInspector *codeGen) : EBPFTableBase(program,
                                                                            instanceName,
                                                                            codeGen) {

    auto ts = di->type->to<IR::Type_Specialized>();

    auto kT = EBPFTypeFactory::instance->create(ts->arguments->at(0));;
    auto vT = EBPFTypeFactory::instance->create(ts->arguments->at(1));

    this->keyType = kT;
    this->valueType = vT;

    auto declaredSize = di->arguments->at(0)->expression->to<IR::Constant>();
    if (!declaredSize->fitsInt()) {
        ::error(ErrorType::ERR_OVERLIMIT, "%1%: size too large", declaredSize);
        return;
    }
    size = declaredSize->asUnsigned();
}

void EBPFRegisterPSA::emitTypes(CodeBuilder* builder) {
    emitKeyType(builder);
    emitValueType(builder);
}

void EBPFRegisterPSA::emitKeyType(CodeBuilder* builder) {
    builder->emitIndent();
    builder->append("typedef ");
    this->keyType->emit(builder);
    builder->appendFormat(" %s", keyTypeName.c_str());
    builder->endOfStatement(true);
}

void EBPFRegisterPSA::emitValueType(CodeBuilder* builder) {
    builder->emitIndent();
    builder->append("typedef ");
    this->valueType->emit(builder);
    builder->appendFormat(" %s", valueTypeName.c_str());
    builder->endOfStatement(true);
}

void EBPFRegisterPSA::emitInstance(CodeBuilder *builder) {
    builder->target->emitTableDecl(builder, instanceName, TableArray,
                                   this->keyTypeName,
                                   this->valueTypeName, size);
}

void EBPFRegisterPSA::emitRegisterRead(CodeBuilder* builder, const P4::ExternMethod* method,
                      cstring indexParamStr, const IR::Expression* leftExpression) {
    cstring keyName = program->refMap->newName("key");
    cstring valueName = program->refMap->newName("value");
    cstring msgStr, varStr;

    auto pipeline = dynamic_cast<const EBPFPipeline *>(program);
    if (pipeline == nullptr) {
        ::error(ErrorType::ERR_UNSUPPORTED, "Register used outside of pipeline %1%", method->expr);
        return;
    }

    builder->emitIndent();
    builder->appendFormat("%s *%s = NULL", valueTypeName.c_str(), valueName.c_str());
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->appendFormat("%s %s = ", keyTypeName.c_str(), keyName.c_str());

    auto expression = method->expr;
    if (!indexParamStr.isNullOrEmpty()) {
        builder->append(indexParamStr);
    } else {
        auto index = expression->arguments->at(0);
        codeGen->visit(index);
    }
    builder->endOfStatement(true);

    msgStr = Util::printf_format("Register: reading %s, id=%%u, packets=1, bytes=%%u",
                                 instanceName.c_str());
    varStr = Util::printf_format("%s->len", pipeline->contextVar.c_str());
    builder->target->emitTraceMessage(builder, msgStr.c_str(), 2, keyName.c_str(), varStr.c_str());

    builder->emitIndent();
    builder->target->emitTableLookup(builder, dataMapName, keyName, valueName);
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->appendFormat("if (%s != NULL) ", valueName.c_str());
    builder->blockStart();
    builder->emitIndent();
    codeGen->visit(leftExpression);
    builder->appendFormat(" = *%s", valueName);
    builder->endOfStatement(true);
    builder->blockEnd(false);
    builder->appendFormat(" else ");
    builder->blockStart();
    builder->target->emitTraceMessage(builder, "Register: Entry not found, aborting");
    builder->emitIndent();
    builder->appendFormat("return %s", builder->target->abortReturnCode().c_str());
    builder->endOfStatement(true);
    builder->blockEnd(true);
}

void EBPFRegisterPSA::emitRegisterWrite(CodeBuilder* builder, const P4::ExternMethod* method,
                                        cstring indexParamStr, cstring valueParamStr) {
    cstring keyName = program->refMap->newName("key");
//    cstring valueName = program->refMap->newName("value");
    cstring msgStr, varStr;

    auto pipeline = dynamic_cast<const EBPFPipeline *>(program);
    if (pipeline == nullptr) {
        ::error(ErrorType::ERR_UNSUPPORTED, "Register used outside of pipeline %1%", method->expr);
        return;
    }

//    builder->emitIndent();
//    builder->appendFormat("%s *%s", valueTypeName.c_str(), valueName.c_str());
//    builder->endOfStatement(true);

    builder->emitIndent();
    builder->appendFormat("%s %s = ", keyTypeName.c_str(), keyName.c_str());

    auto expression = method->expr;
    if (!indexParamStr.isNullOrEmpty()) {
        builder->append(indexParamStr);
    } else {
        auto index = expression->arguments->at(0);
        codeGen->visit(index);
    }
    builder->endOfStatement(true);

    msgStr = Util::printf_format("Register: writing %s, id=%%u, packets=1, bytes=%%u",
                                 instanceName.c_str());
    varStr = Util::printf_format("%s->len", pipeline->contextVar.c_str());
    builder->target->emitTraceMessage(builder, msgStr.c_str(), 2, keyName.c_str(), varStr.c_str());

    if (auto valueExpr = expression->arguments->at(1)->expression->to<IR::PathExpression>()) {
        builder->emitIndent();
        builder->target->emitTableUpdate(builder, dataMapName, keyName, valueExpr->path->name.name);
//        builder->endOfStatement(true);
    } else {
        ::error(ErrorType::ERR_INVALID,
                "Wrong register value argument",
                expression->arguments->at(1)->expression->toString());
    }
}

void EBPFRegisterPSA::emitMethodInvocation(CodeBuilder* builder, const P4::ExternMethod* method,
                                           cstring indexParamStr, cstring valueParamStr) {
    builder->emitIndent();
    builder->blockStart();
    if (method->method->type->name == "read") {

//        return;
    } else if (method->method->type->name == "write") {

//        return;
    } else {
        ::error(ErrorType::ERR_UNSUPPORTED, "Unexpected method %1%", method->expr);
//        return;
    }
    builder->blockEnd(true);
}

} // namespace EBPF