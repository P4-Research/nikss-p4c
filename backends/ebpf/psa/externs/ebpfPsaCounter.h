#ifndef BACKENDS_EBPF_PSA_EBPFPSACOUNTER_H_
#define BACKENDS_EBPF_PSA_EBPFPSACOUNTER_H_

#include "backends/ebpf/ebpfTable.h"

namespace EBPF {

class EBPFCounterPSA : public EBPFCounterTable {
 protected:
 public:
    enum CounterType {
        PACKETS,
        BYTES,
        PACKETS_AND_BYTES
    };
    CounterType type;

    EBPFCounterPSA(const EBPFProgram* program, const IR::ExternBlock* block,
                     cstring name, CodeGenInspector* codeGen);
    EBPFCounterPSA(const EBPFProgram* program, cstring name, CodeGenInspector* codeGen,
                     size_t size, CounterType cntrType) :
                     EBPFCounterTable(program, name, codeGen, size, false), type(cntrType) {}

    static CounterType toCounterType(const int type);

    void emitTypes(CodeBuilder* builder) override;
    void emitMethodInvocation(CodeBuilder* builder, const P4::ExternMethod* method) override;

    virtual void emitCount(CodeBuilder* builder, const IR::MethodCallExpression *expression);
};

}

#endif //BACKENDS_EBPF_PSA_EBPFPSACOUNTER_H_
