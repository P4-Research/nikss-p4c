#ifndef BACKENDS_EBPF_PSA_EXTERNS_EBPFPSATABLEIMPLEMENTATION_H_
#define BACKENDS_EBPF_PSA_EXTERNS_EBPFPSATABLEIMPLEMENTATION_H_

#include "backends/ebpf/ebpfTable.h"
#include "backends/ebpf/psa/ebpfPsaObjects.h"

namespace EBPF {

class EBPFTableImplementationPSA : public EBPFTablePSA {
 public:
    EBPFTableImplementationPSA(const EBPFProgram* program, CodeGenInspector* codeGen,
                               const IR::Declaration_Instance* decl);

    void emitTypes(CodeBuilder* builder) override;
    void emitInitializer(CodeBuilder *builder) override;
    void emitReferenceEntry(CodeBuilder *builder);

    virtual void registerTable(const EBPFTablePSA * instance);

    virtual void applyImplementation(CodeBuilder* builder, cstring tableValueName,
                                     cstring actionRunVariable) = 0;

 protected:
    const IR::Declaration_Instance* declaration;
    cstring referenceName;

    void verifyTableActionList(const EBPFTablePSA * instance);
    void verifyTableNoDefaultAction(const EBPFTablePSA * instance);
    void verifyTableNoDirectObjects(const EBPFTablePSA * instance);
    void verifyTableNoEntries(const EBPFTablePSA * instance);
};

class EBPFActionProfilePSA : public EBPFTableImplementationPSA {
 public:
    EBPFActionProfilePSA(const EBPFProgram* program, CodeGenInspector* codeGen,
                         const IR::Declaration_Instance* decl);

    void emitInstance(CodeBuilder *builder) override;
    void applyImplementation(CodeBuilder* builder, cstring tableValueName,
                             cstring actionRunVariable) override;
};

}  // namespace EBPF

#endif  // BACKENDS_EBPF_PSA_EXTERNS_EBPFPSATABLEIMPLEMENTATION_H_
