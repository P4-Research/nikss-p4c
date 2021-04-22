#ifndef BACKENDS_EBPF_PSA_EBPFPSACONTROLTRANSLATORS_H_
#define BACKENDS_EBPF_PSA_EBPFPSACONTROLTRANSLATORS_H_

#include "backends/ebpf/ebpfControl.h"
#include "backends/ebpf/ebpfTable.h"
#include "ebpfPsaControl.h"
#include "ebpfPipeline.h"

namespace EBPF {

class EBPFTablePSA;
class EBPFControlPSA;
class EBPFPipeline;

class ControlBodyTranslatorPSA : public ControlBodyTranslator {
 public:
    explicit ControlBodyTranslatorPSA(const EBPFControlPSA* control) :
            CodeGenInspector(control->program->refMap, control->program->typeMap),
            ControlBodyTranslator(control) {}

    bool preorder(const IR::Member* expression) override;

    void processMethod(const P4::ExternMethod* method) override;
};

class ActionTranslationVisitorPSA : public ActionTranslationVisitor,
                                    public ControlBodyTranslatorPSA {
 protected:
    const EBPFTablePSA* table;

 public:
    ActionTranslationVisitorPSA(cstring valueName, const EBPFPipeline* program,
                                const EBPFTablePSA* table):
            CodeGenInspector(program->refMap, program->typeMap),
            ActionTranslationVisitor(valueName, program),
            ControlBodyTranslatorPSA(program->control),
            table(table) {}

    bool preorder(const IR::MethodCallExpression* expression) override;
    bool preorder(const IR::PathExpression* pe) override
    { return ActionTranslationVisitor::preorder(pe); }

    void processMethod(const P4::ExternMethod* method) override;
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EBPFPSACONTROLTRANSLATORS_H_ */
