#ifndef BACKENDS_EBPF_PSA_EBPFPSACOUNTER_H_
#define BACKENDS_EBPF_PSA_EBPFPSACOUNTER_H_

#include "backends/ebpf/ebpfTable.h"

namespace EBPF {

class EBPFCounterPSA : public EBPFCounterTable {
 protected:
    EBPFType* dataplaneWidthType;
    EBPFType* indexWidthType;

 public:
    enum CounterType {
        PACKETS,
        BYTES,
        PACKETS_AND_BYTES
    };
    CounterType type;

    EBPFCounterPSA(const EBPFProgram* program, const IR::ExternBlock* block,
                     cstring name, CodeGenInspector* codeGen);

    static CounterType toCounterType(int type);

    void emitTypes(CodeBuilder* builder) override;
    virtual void emitKeyType(CodeBuilder* builder);
    virtual void emitValueType(CodeBuilder* builder);

    void emitMethodInvocation(CodeBuilder* builder, const P4::ExternMethod* method) override;
    virtual void emitCount(CodeBuilder* builder, const IR::MethodCallExpression *expression);
    virtual void emitCounterUpdate(CodeBuilder* builder, cstring target, bool targetIsPtr,
                                   cstring contextVar, cstring keyName);
    virtual void emitCounterInitializer(CodeBuilder* builder, cstring contextVar);
};

}

#endif //BACKENDS_EBPF_PSA_EBPFPSACOUNTER_H_
