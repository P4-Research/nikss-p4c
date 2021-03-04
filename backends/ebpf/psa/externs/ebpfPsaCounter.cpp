#include "ebpfPsaCounter.h"
#include "backends/ebpf/psa/ebpfPipeline.h"

namespace EBPF {

EBPFCounterPSA::EBPFCounterPSA(const EBPFProgram* program, const IR::ExternBlock* block,
               cstring name, CodeGenInspector* codeGen) :
               EBPFCounterTable(program, block, name, codeGen, false) {
    if (!block->node->is<IR::Declaration_Instance>()) {
        ::error(ErrorType::ERR_EXPRESSION, "Not a declaration instance: %1%", block);
        return;
    }
    if (!block->instanceType->is<IR::Type_SpecializedCanonical>()) {
        ::error(ErrorType::ERR_MODEL, "Missing specialization: %1%", block);
        return;
    }

    auto di = block->node->to<IR::Declaration_Instance>();
    auto ts = block->instanceType->to<IR::Type_SpecializedCanonical>();

    // Direct counter has one specializtion argument, dataplane width,
    // which also is at first position
    if (ts->arguments->size() != 2) {
        ::error(ErrorType::ERR_MODEL, "Expected 2 specialization types: %1%", ts);
        return;
    }

    // check dataplane counter width
    auto dpwtype = ts->arguments->at(0);
    if (!dpwtype->is<IR::Type_Bits>()) {
        ::error(ErrorType::ERR_UNSUPPORTED, "Must be bit or int type: %1%", ts);
        return;
    }
    dataplaneWidthType = EBPFTypeFactory::instance->create(dpwtype);
    unsigned dataplaneWidth = dpwtype->width_bits();
    if (dataplaneWidth > 64) {
        ::error(ErrorType::ERR_UNSUPPORTED,
                "Counters dataplane width up to 64 bits are supported: %1%", ts);
        return;
    }
    if (dataplaneWidth < 8 || (dataplaneWidth & (dataplaneWidth - 1)) != 0) {
        ::warning(ErrorType::WARN_UNSUPPORTED, "Counter dataplane width will be extended to "
                  "nearest type (8, 16, 32 or 64 bits): %1%", ts);
    }

    // check index type
    auto istype = ts->arguments->at(1);
    if (!dpwtype->is<IR::Type_Bits>()) {
        ::error(ErrorType::ERR_UNSUPPORTED, "Must be bit or int type: %1%", ts);
        return;
    }
    unsigned indexWidth = istype->width_bits();
    if (indexWidth != 32) {
        // ARRAY_MAP can have only 32 bits key, so assume this and warn user
        ::warning(ErrorType::WARN_UNSUPPORTED,
                  "Only 32-bits keys are supported, changed to 32 bits: %1%", ts);
        indexWidth = 32;
    }
    indexWidthType = EBPFTypeFactory::instance->create(istype);

    auto declaredSize = (*di->arguments)[0]->expression->to<IR::Constant>();
    if (!declaredSize->fitsInt()) {
        ::error(ErrorType::ERR_OVERLIMIT, "%1%: size too large", declaredSize);
        return;
    }
    size = declaredSize->asUnsigned();

    // TODO: add more advance logic to decide whether used map will be HASH_MAP or ARRAY_MAP
    isHash = false;
    type = toCounterType((*di->arguments)[1]->expression->to<IR::Constant>()->asInt());
}

EBPFCounterPSA::CounterType EBPFCounterPSA::toCounterType(const int type) {
    // TODO: make use of something similar to EBPFModel to avoid hardcoded values
    if (type == 0)
        return CounterType::PACKETS;
    else if (type == 1)
        return CounterType::BYTES;
    else if (type == 2)
        return CounterType::PACKETS_AND_BYTES;

    BUG("Unknown counter type %1%", type);
}

void EBPFCounterPSA::emitTypes(CodeBuilder* builder) {
    emitKeyType(builder);
    emitValueType(builder);
}

void EBPFCounterPSA::emitKeyType(CodeBuilder* builder) {
    builder->emitIndent();
    builder->append("typedef ");
    indexWidthType->emit(builder);
    builder->appendFormat(" %s", keyTypeName.c_str());
    builder->endOfStatement(true);
}

void EBPFCounterPSA::emitValueType(CodeBuilder* builder) {
    builder->emitIndent();
    builder->appendLine("typedef struct ");
    builder->blockStart();
    if (type == CounterType::BYTES || type == CounterType::PACKETS_AND_BYTES) {
        builder->emitIndent();
        dataplaneWidthType->emit(builder);
        builder->append(" bytes");
        builder->endOfStatement(true);
    }
    if (type == CounterType::PACKETS || type == CounterType::PACKETS_AND_BYTES) {
        builder->emitIndent();
        dataplaneWidthType->emit(builder);
        builder->append(" packets");
        builder->endOfStatement(true);
    }

    builder->blockEnd(false);
    builder->appendFormat(" %s", valueTypeName.c_str());
    builder->endOfStatement(true);
}

void EBPFCounterPSA::emitMethodInvocation(CodeBuilder* builder, const P4::ExternMethod* method) {
    if (method->method->name.name != "count") {
        ::error(ErrorType::ERR_UNSUPPORTED, "Unexpected method %1%", method->expr);
        return;
    }
    BUG_CHECK(method->expr->arguments->size() == 1,
              "Expected just 1 argument for %1%", method->expr);

    builder->blockStart();
    this->emitCount(builder, method->expr);
    builder->blockEnd(false);
}

void EBPFCounterPSA::emitCount(CodeBuilder* builder,
                               const IR::MethodCallExpression *expression) {
    cstring keyName = program->refMap->newName("key");
    cstring valueName = program->refMap->newName("value");
    cstring msgStr, varStr;

    auto pipeline = dynamic_cast<const EBPFPipeline *>(program);
    if (pipeline == nullptr) {
        ::error(ErrorType::ERR_UNSUPPORTED, "Counter used outside of pipeline %1%", expression);
        return;
    }

    builder->emitIndent();
    builder->appendFormat("%s *%s", valueTypeName.c_str(), valueName.c_str());
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->appendFormat("%s %s = ", keyTypeName.c_str(), keyName.c_str());
    auto index = expression->arguments->at(0);
    codeGen->visit(index);
    builder->endOfStatement(true);

    msgStr = Util::printf_format("Counter: updating %s, id=%%u, packets=1, bytes=%%u",
                                 instanceName.c_str());
    varStr = Util::printf_format("%s->len", pipeline->contextVar.c_str());
    builder->target->emitTraceMessage(builder, msgStr.c_str(), 2, keyName.c_str(), varStr.c_str());

    builder->emitIndent();
    builder->target->emitTableLookup(builder, dataMapName, keyName, valueName);
    builder->endOfStatement(true);

    emitCounterUpdate(builder, valueName, true, pipeline->contextVar, keyName);

    msgStr = Util::printf_format("Counter: %s updated", instanceName.c_str());
    builder->target->emitTraceMessage(builder, msgStr.c_str());
}

void EBPFCounterPSA::emitCounterUpdate(CodeBuilder* builder, const cstring target,
                                       bool targetIsPtr, const cstring contextVar,
                                       const cstring keyName) {
    cstring targetWAccess, varStr;
    cstring initValueName = program->refMap->newName("init_val");

    if (targetIsPtr)
        targetWAccess = target + "->";
    else
        targetWAccess = target + ".";

    if (targetIsPtr) {
        builder->emitIndent();
        builder->appendFormat("if (%s != NULL) ", target.c_str());
        builder->blockStart();
    }

    if (type == CounterType::BYTES || type == CounterType::PACKETS_AND_BYTES) {
        builder->emitIndent();
        builder->appendFormat("__sync_fetch_and_add(&(%sbytes), %s->len)",
                              targetWAccess.c_str(), contextVar.c_str());
        builder->endOfStatement(true);

        varStr = Util::printf_format("%sbytes", targetWAccess.c_str());
        builder->target->emitTraceMessage(builder, "Counter: now bytes=%u", 1, varStr.c_str());
    }
    if (type == CounterType::PACKETS || type == CounterType::PACKETS_AND_BYTES) {
        builder->emitIndent();
        builder->appendFormat("__sync_fetch_and_add(&(%spackets), 1)", targetWAccess.c_str());
        builder->endOfStatement(true);

        varStr = Util::printf_format("%spackets", targetWAccess.c_str());
        builder->target->emitTraceMessage(builder, "Counter: now packets=%u", 1, varStr.c_str());
    }

    // do not create instance when we are sure it exists, e.g. target is not a pointer
    if (targetIsPtr) {
        builder->blockEnd(false);
        builder->append(" else ");
        builder->blockStart();

        if (isHash) {
            builder->target->emitTraceMessage(builder,
                                              "Counter: data not found, adding new instance");
            builder->emitIndent();
            builder->appendFormat("%s %s = ", valueTypeName.c_str(), target.c_str());
            emitCounterInitializer(builder, contextVar);
            builder->endOfStatement(true);

            builder->emitIndent();
            builder->target->emitTableUpdate(builder, dataMapName, keyName, initValueName);
            builder->newline();
        } else {
            builder->target->emitTraceMessage(builder, "Counter: instance not found");
        }

        builder->blockEnd(true);
    }
}

void EBPFCounterPSA::emitCounterInitializer(CodeBuilder* builder, const cstring contextVar) {
    builder->blockStart();
    if (type == CounterType::BYTES || type == CounterType::PACKETS_AND_BYTES) {
        builder->emitIndent();
        builder->appendFormat(".bytes = %s->len,", contextVar.c_str());
        builder->newline();
    }
    if (type == CounterType::PACKETS || type == CounterType::PACKETS_AND_BYTES) {
        builder->emitIndent();
        builder->appendFormat(".packets = 1,");
        builder->newline();
    }
    builder->blockEnd(false);
}

}
