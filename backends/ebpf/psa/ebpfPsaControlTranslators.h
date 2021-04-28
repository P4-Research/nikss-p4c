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
    explicit ControlBodyTranslatorPSA(const EBPFControlPSA* control);

    bool preorder(const IR::Member* expression) override;
    bool preorder(const IR::AssignmentStatement* s) override;

    void processMethod(const P4::ExternMethod* method) override;
};

class ActionTranslationVisitorPSA : public ActionTranslationVisitor,
                                    public ControlBodyTranslatorPSA {
 protected:
    const EBPFTablePSA* table;

 public:
    ActionTranslationVisitorPSA(cstring valueName, const EBPFPipeline* program,
                                const EBPFTablePSA* table);

    bool preorder(const IR::PathExpression* pe) override;

    void processMethod(const P4::ExternMethod* method) override;
    void processApply(const P4::ApplyMethod* method) override;
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EBPFPSACONTROLTRANSLATORS_H_ */
