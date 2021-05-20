#ifndef BACKENDS_EBPF_PSA_EBPFPSAOBJECTS_H_
#define BACKENDS_EBPF_PSA_EBPFPSAOBJECTS_H_

#include "frontends/p4/methodInstance.h"
#include "backends/ebpf/ebpfTable.h"
#include "backends/ebpf/psa/externs/ebpfPsaCounter.h"

namespace EBPF {

class EBPFTableImplementationPSA;

class EBPFTablePSA : public EBPFTable {
 protected:
    ActionTranslationVisitor*
        createActionTranslationVisitor(cstring valueName,
                                       const EBPFProgram* program) const override;
    void initDirectCounters();
    void initDirectMeters();
    void initImplementations();

    template<class F>
    void forEachPropertyEntry(cstring propertyName, F func) {
        auto counterProperty = table->container->properties->getProperty(propertyName);
        if (counterProperty == nullptr)
            return;
        if (counterProperty->value->is<IR::ExpressionValue>()) {
            auto ev = counterProperty->value->to<IR::ExpressionValue>();
            if (ev->expression->is<IR::PathExpression>()) {
                func(ev->expression->to<IR::PathExpression>());
            } else if (ev->expression->is<IR::ListExpression>()) {
                auto le = ev->expression->to<IR::ListExpression>();
                for (auto c : le->components) {
                    func(c->to<IR::PathExpression>());
                }
            } else {
                ::error(ErrorType::ERR_UNSUPPORTED,
                        "Unsupported list type: %1%", counterProperty->value);
            }
        } else {
            ::error(ErrorType::ERR_UNKNOWN,
                    "Unknown property expression type: %1%", counterProperty->value);
        }
    }

    bool hasImplementation() const;

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
    std::vector<cstring> meters;  // TODO: implement, now needed for ActionProfile

    std::vector<EBPFTableImplementationPSA *> implementations;

    EBPFTablePSA(const EBPFProgram* program, const IR::TableBlock* table,
                 CodeGenInspector* codeGen, cstring name, size_t size);
    EBPFTablePSA(const EBPFProgram* program, CodeGenInspector* codeGen, cstring name);

    void emitInstance(CodeBuilder* builder) override;
    void emitValueActionIDNames(CodeBuilder* builder) override;
    void emitValueStructStructure(CodeBuilder* builder) override;
    void emitAction(CodeBuilder* builder, cstring valueName, cstring actionRunVariable) override;
    void emitInitializer(CodeBuilder* builder) override;
    void emitDirectTypes(CodeBuilder* builder) override;
    void emitLookupDefault(CodeBuilder* builder, cstring key, cstring value) override;
    bool dropOnNoMatchingEntryFound() const override;
    bool singleActionRun() const override;

    EBPFCounterPSA* getCounter(cstring name) const {
        auto result = std::find_if(counters.begin(), counters.end(),
            [name](std::pair<cstring, EBPFCounterPSA *> elem)->bool {
                return name == elem.first;
            });
        if (result != counters.end())
            return result->second;
        return nullptr;
    }

    bool isMatchTypeSupported(const IR::Declaration_ID* matchType) override {
        return EBPFTable::isMatchTypeSupported(matchType) ||
               matchType->name.name == "selector";
    }
};

class EBPFTernaryTablePSA : public EBPFTablePSA {
 public:
    EBPFTernaryTablePSA(const EBPFProgram* program, const IR::TableBlock* table,
                 CodeGenInspector* codeGen, cstring name, size_t size) :
            EBPFTablePSA(program, table, codeGen, name, size) { }

    void emitInstance(CodeBuilder* builder) override;
    void emitKeyType(CodeBuilder* builder) override;
    void emitValueType(CodeBuilder* builder) override;
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
