#ifndef BACKENDS_EBPF_PSA_EXTERNS_EBPFPSAMETERS_H_
#define BACKENDS_EBPF_PSA_EXTERNS_EBPFPSAMETERS_H_

#include "backends/ebpf/psa/ebpfPsaObjects.h"

namespace EBPF {

class EBPFMeterPSA : public EBPFTablePSA {
 private:
    EBPFType *createValueType() ;

 protected:
    size_t size{};
    const IR::Constant *initialValue = nullptr;
    const IR::Type *keyArg{};
    const IR::Type *valueArg{};
    EBPFType *keyType{};
    EBPFType *valueType{};
    bool arrayMapBased = false;

 public:
    enum MeterType {
        PACKETS,
        BYTES
    };
    MeterType type;

    EBPFMeterPSA(const EBPFProgram* program, cstring instanceName,
                 const IR::Declaration_Instance* di,
                 CodeGenInspector* codeGen);

    void emitKeyType(CodeBuilder* builder);
    void emitValueType(CodeBuilder* builder);

    void emitInstance(CodeBuilder* builder);

    void emitExecute(CodeBuilder* builder, const P4::ExternMethod* method);
};

}  // namespace EBPF

#endif  // BACKENDS_EBPF_PSA_EXTERNS_EBPFPSAMETERS_H_
