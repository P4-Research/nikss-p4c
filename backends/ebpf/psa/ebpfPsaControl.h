#ifndef BACKENDS_EBPF_PSA_EBPFPSACONTROL_H_
#define BACKENDS_EBPF_PSA_EBPFPSACONTROL_H_

#include "ebpfPsaObjects.h"
#include "backends/ebpf/ebpfControl.h"
#include "backends/ebpf/psa/externs/ebpfPsaChecksum.h"
#include "backends/ebpf/psa/externs/ebpfPsaRandom.h"
#include "backends/ebpf/psa/externs/ebpfPsaRegister.h"
#include "backends/ebpf/psa/externs/ebpfPsaMeter.h"

namespace EBPF {

class EBPFControlPSA : public EBPFControl {
 public:
    // FIXME: this should not be part of EBPFControlPSA object.
    // It should be moved to ConvertToEBPFPsaControl.
    const IR::P4Control* p4Control;

    const IR::Parameter* user_metadata;
    const IR::Parameter* inputStandardMetadata;
    const IR::Parameter* outputStandardMetadata;

    std::map<cstring, EBPFHashPSA*> hashes;
    std::map<cstring, EBPFRandomPSA*> randGenerators;
    std::map<cstring, EBPFRegisterPSA*>  registers;
    std::map<cstring, EBPFMeterPSA*>  meters;
//    std::map<cstring, EBPFTablePSA*>  tables;

    EBPFControlPSA(const EBPFProgram* program, const IR::ControlBlock* control,
                   const IR::Parameter* parserHeaders) :
        EBPFControl(program, control, parserHeaders), p4Control(control->container) {}

    bool build() override;
    void emit(CodeBuilder* builder) override;
    void emitTableTypes(CodeBuilder* builder) override;
    void emitTableInstances(CodeBuilder* builder) override;
    void emitTableInitializers(CodeBuilder* builder) override;

    EBPFHashPSA* getHash(cstring name) const {
        auto result = ::get(hashes, name);
        BUG_CHECK(result != nullptr, "No hash named %1%", name);
        return result; }

    EBPFRegisterPSA* getRegister(cstring name) const {
        auto result = ::get(registers, name);
        BUG_CHECK(result != nullptr, "No register named %1%", name);
        return result; }

    EBPFRandomPSA* getRandGenerator(cstring name) const {
        auto result = ::get(randGenerators, name);
        BUG_CHECK(result != nullptr, "No random generator named %1%", name);
        return result;
    }

    EBPFMeterPSA* getMeter(cstring name) const {
        auto result = ::get(meters, name);
        BUG_CHECK(result != nullptr, "No meter named %1%", name);
        return result;
    }
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EBPFPSACONTROL_H_ */
