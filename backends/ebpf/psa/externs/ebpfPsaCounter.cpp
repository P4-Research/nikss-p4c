#include "ebpfPsaCounter.h"
#include "backends/ebpf/psa/ebpfPipeline.h"

namespace EBPF {

EBPFCounterPSA::EBPFCounterPSA(const EBPFProgram* program, const IR::ExternBlock* block,
               cstring name, CodeGenInspector* codeGen) :
               EBPFCounterTable(program, block, name, codeGen) {
    BUG("Not implemented");
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
    builder->emitIndent();
    builder->appendFormat("typedef %s %s",
                          EBPFModel::instance.counterIndexType.c_str(), keyTypeName.c_str());
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->appendLine("typedef struct ");
    builder->blockStart();
    if (type == CounterType::BYTES || type == CounterType::PACKETS_AND_BYTES) {
        builder->emitIndent();
        builder->appendFormat("%s bytes", EBPFModel::instance.counterValueType.c_str());
        builder->endOfStatement(true);
    }
    if (type == CounterType::PACKETS || type == CounterType::PACKETS_AND_BYTES) {
        builder->emitIndent();
        builder->appendFormat("%s packets", EBPFModel::instance.counterValueType.c_str());
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

    this->emitCount(builder, method->expr);
}

void EBPFCounterPSA::emitCount(CodeBuilder* builder,
                               const IR::MethodCallExpression *expression) {
    cstring keyName = program->refMap->newName("key");
    cstring valueName = program->refMap->newName("value");
    cstring initValueName = program->refMap->newName("init_val");
    cstring msgStr, varStr;

    auto pipeline = dynamic_cast<const EBPFPipeline *>(program);
    if (pipeline == nullptr) {
        ::error(ErrorType::ERR_UNSUPPORTED, "Counter used outside of pipeline %1%", expression);
        return;
    }

    builder->blockStart();

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

    builder->emitIndent();
    builder->appendFormat("if (%s != NULL) ", valueName.c_str());
    builder->blockStart();
    if (type == CounterType::BYTES || type == CounterType::PACKETS_AND_BYTES) {
        builder->emitIndent();
        builder->appendFormat("__sync_fetch_and_add(&(%s->bytes), %s->len)",
                              valueName.c_str(), pipeline->contextVar.c_str());
        builder->endOfStatement(true);

        varStr = Util::printf_format("%s->bytes", valueName.c_str());
        builder->target->emitTraceMessage(builder, "Counter: now bytes=%u", 1, varStr.c_str());
    }
    if (type == CounterType::PACKETS || type == CounterType::PACKETS_AND_BYTES) {
        builder->emitIndent();
        builder->appendFormat("__sync_fetch_and_add(&(%s->packets), 1)", valueName.c_str());
        builder->endOfStatement(true);

        varStr = Util::printf_format("%s->packets", valueName.c_str());
        builder->target->emitTraceMessage(builder, "Counter: now packets=%u", 1, varStr.c_str());
    }

    builder->blockEnd(false);
    builder->append(" else ");
    builder->blockStart();

    builder->target->emitTraceMessage(builder, "Counter: data not found, adding new instance");

    builder->emitIndent();
    builder->appendFormat("%s %s = ", valueTypeName.c_str(), initValueName.c_str());
    builder->blockStart();
    if (type == CounterType::BYTES || type == CounterType::PACKETS_AND_BYTES) {
        builder->emitIndent();
        builder->appendFormat(".bytes = %s->len,", pipeline->contextVar.c_str());
        builder->newline();
    }
    if (type == CounterType::PACKETS || type == CounterType::PACKETS_AND_BYTES) {
        builder->emitIndent();
        builder->appendFormat(".packets = 1,");
        builder->newline();
    }
    builder->blockEnd(false);
    builder->endOfStatement(true);

    builder->emitIndent();
    builder->target->emitTableUpdate(builder, dataMapName, keyName, initValueName);
    builder->newline();

    builder->blockEnd(true);

    msgStr = Util::printf_format("Counter: %s updated", instanceName.c_str());
    builder->target->emitTraceMessage(builder, msgStr.c_str());

    builder->blockEnd(false);
}

}
