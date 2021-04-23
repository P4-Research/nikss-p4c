#ifndef BACKENDS_EBPF_PSA_EBPFPSAOBJECTS_H_
#define BACKENDS_EBPF_PSA_EBPFPSAOBJECTS_H_

#include "frontends/p4/methodInstance.h"
#include "backends/ebpf/ebpfTable.h"
#include "backends/ebpf/psa/externs/ebpfPsaCounter.h"

namespace EBPF {

class EBPFTablePSA : public EBPFTable {
 protected:
    ActionTranslationVisitor*
        createActionTranslationVisitor(cstring valueName,
                                       const EBPFProgram* program) const override;
    void initDirectCounters();

 private:
    void emitTableValue(CodeBuilder* builder, const IR::MethodCallExpression* actionMce,
                        cstring valueName);
    void emitDefaultActionInitializer(CodeBuilder *builder);
    void emitConstEntriesInitializer(CodeBuilder *builder);
    void emitMapUpdateTraceMsg(CodeBuilder *builder, cstring mapName,
                               cstring returnCode) const;

 public:
    cstring name;
    size_t size;
    std::vector<std::pair<cstring, EBPFCounterPSA *>> counters;

    EBPFTablePSA(const EBPFProgram* program, const IR::TableBlock* table,
                 CodeGenInspector* codeGen, cstring name, size_t size);

    void emitInstance(CodeBuilder* builder) override;
    void emitInitializer(CodeBuilder* builder) override;
    void emitDirectTypes(CodeBuilder* builder) override;

    EBPFCounterPSA* getCounter(cstring name) const {
        auto result = std::find_if(counters.begin(), counters.end(),
            [name](std::pair<cstring, EBPFCounterPSA *> elem)->bool {
                return name == elem.first;
            });
        if (result != counters.end())
            return result->second;
        return nullptr;
    }
};

class EBPFTernaryTablePSA : public EBPFTablePSA {
 public:
    EBPFTernaryTablePSA(const EBPFProgram* program, const IR::TableBlock* table,
                 CodeGenInspector* codeGen, cstring name, size_t size) :
            EBPFTablePSA(program, table, codeGen, name, size) { }

    void emitInstance(CodeBuilder* builder) override;
    void emitKeyType(CodeBuilder* builder) override;
    void emitLookup(CodeBuilder* builder, cstring key, cstring value) override;
    bool isMatchTypeSupported(const IR::Declaration_ID* matchType) override {
        return EBPFTablePSA::isMatchTypeSupported(matchType) ||
               matchType->name.name == P4::P4CoreLibrary::instance.ternaryMatch.name;
    }
};

class EBPFValueSetPSA : public EBPFTableBase {
 protected:
    size_t size;
    const IR::P4ValueSet* pvs;
    std::vector<std::pair<cstring, const IR::Type*>> fieldNames;
    cstring keyVarName;

 public:
    EBPFValueSetPSA(const EBPFProgram* program, const IR::P4ValueSet* p4vs, cstring instanceName,
                    CodeGenInspector* codeGen);

    void emitTypes(CodeBuilder* builder);
    void emitInstance(CodeBuilder* builder);
    void emitKeyInitializer(CodeBuilder* builder, const IR::SelectExpression* expression,
                            cstring varName);
    void emitLookup(CodeBuilder* builder);
};

}  // namespace EBPF

#endif /* BACKENDS_EBPF_PSA_EBPFPSAOBJECTS_H_ */
