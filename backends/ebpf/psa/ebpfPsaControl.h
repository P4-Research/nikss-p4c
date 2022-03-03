#ifndef BACKENDS_EBPF_PSA_EBPFPSACONTROL_H_
#define BACKENDS_EBPF_PSA_EBPFPSACONTROL_H_

#include "ebpfPsaTable.h"
#include "backends/ebpf/ebpfControl.h"

namespace EBPF {

class EBPFControlPSA;

class ControlBodyTranslatorPSA : public ControlBodyTranslator {
 public:
    explicit ControlBodyTranslatorPSA(const EBPFControlPSA* control);

    bool preorder(const IR::Member* expression) override;
    bool preorder(const IR::AssignmentStatement* a) override;

    void processMethod(const P4::ExternMethod* method) override;

    virtual cstring getIndexActionParam(const IR::PathExpression *indexExpr);
    virtual cstring getValueActionParam(const IR::PathExpression *valueExpr);
};

class ActionTranslationVisitorPSA : public ActionTranslationVisitor,
                                    public ControlBodyTranslatorPSA {
 private:
    cstring getActionParamStr(const IR::Expression *expression) const override;

 protected:
    const EBPFTablePSA* table;

 public:
    ActionTranslationVisitorPSA(cstring valueName, const EBPFProgram* program,
                                const EBPFTablePSA* table);
    bool preorder(const IR::PathExpression* pe) override;

    void processMethod(const P4::ExternMethod* method) override;

    void processApply(const P4::ApplyMethod* method) override;

    bool isActionParameter(const IR::Expression *expression) const;
    cstring getIndexActionParam(const IR::PathExpression *indexExpr) override;
    cstring getValueActionParam(const IR::PathExpression *valueExpr) override;
};

class EBPFControlPSA : public EBPFControl {
 public:
    bool timestampIsUsed = false;
    // FIXME: this should not be part of EBPFControlPSA object.
    // It should be moved to ConvertToEBPFPsaControl.
    const IR::P4Control* p4Control;

    const IR::Parameter* user_metadata;
    const IR::Parameter* inputStandardMetadata;
    const IR::Parameter* outputStandardMetadata;

    EBPFControlPSA(const EBPFProgram* program, const IR::ControlBlock* control,
                   const IR::Parameter* parserHeaders) :
        EBPFControl(program, control, parserHeaders), p4Control(control->container) {}

    bool build() override;
    void emit(CodeBuilder* builder) override;
    void emitTableTypes(CodeBuilder* builder) override;
    void emitTableInstances(CodeBuilder* builder) override;
    void emitTableInitializers(CodeBuilder* builder) override;
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EBPFPSACONTROL_H_ */
