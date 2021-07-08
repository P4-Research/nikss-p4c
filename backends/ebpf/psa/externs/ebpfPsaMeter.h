#ifndef BACKENDS_EBPF_PSA_EXTERNS_EBPFPSAMETER_H_
#define BACKENDS_EBPF_PSA_EXTERNS_EBPFPSAMETER_H_

#include "backends/ebpf/psa/ebpfPsaObjects.h"

namespace EBPF {

class EBPFMeterPSA : public EBPFTablePSA {
 private:
    static IR::IndexedVector<IR::StructField> getValueFields() ;
    static IR::Type_Struct *createSpinlockStruct() ;
    EBPFType *createBaseValueType() const;
    EBPFType *createIndirectValueType() const;
    cstring valueBaseStructName;
    cstring valueIndirectStructName;

    const cstring indirectValueField = "value";
    const cstring spinlockField = "lock";

 protected:
    size_t size{};
    const IR::Type *keyArg{};
    EBPFType *keyType{};
    EBPFType *valueIndirectType{};
    EBPFType *valueBaseType{};
    bool isDirect;

 public:
    enum MeterType {
        PACKETS,
        BYTES
    };
    MeterType type;

    EBPFMeterPSA(const EBPFProgram* program, cstring instanceName,
                 const IR::Declaration_Instance* di,
                 CodeGenInspector* codeGen);

    static MeterType toType(const int typeCode);

    void emitKeyType(CodeBuilder* builder) override;
    void emitValueStruct(CodeBuilder* builder);
    void emitValueType(CodeBuilder* builder) override;
    void emitSpinLockField(CodeBuilder* builder);
    void emitInstance(CodeBuilder* builder) override;
    void emitExecute(CodeBuilder* builder, const P4::ExternMethod* method);
    void emitDirectExecute(CodeBuilder* builder, const P4::ExternMethod* method,
                           cstring valuePtr);

    cstring meterExecuteFunc(bool trace);
};

}  // namespace EBPF

#endif  // BACKENDS_EBPF_PSA_EXTERNS_EBPFPSAMETER_H_
