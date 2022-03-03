#ifndef BACKENDS_EBPF_PSA_EBPFPSATABLE_H_
#define BACKENDS_EBPF_PSA_EBPFPSATABLE_H_

#include "frontends/p4/methodInstance.h"
#include "backends/ebpf/ebpfTable.h"
#include "backends/ebpf/psa/externs/ebpfPsaCounter.h"

namespace EBPF {

class EBPFTableImplementationPSA;
class EBPFMeterPSA;

class EBPFTablePSA : public EBPFTable {
 private:
    void emitTableDecl(CodeBuilder *builder,
                       cstring tblName,
                       TableKind kind,
                       cstring keyTypeName,
                       cstring valueTypeName,
                       size_t size) const;

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
    virtual void emitConstEntriesInitializer(CodeBuilder *builder);
    void emitMapUpdateTraceMsg(CodeBuilder *builder, cstring mapName,
                               cstring returnCode) const;

    bool tableCacheEnabled = false;
    cstring cacheValueTypeName;
    cstring cacheKeyTypeName;
    cstring cacheTableName;
    void tryEnableTableCache();
    void createCacheTypeNames(bool isCacheKeyType, bool isCacheValueType);

 public:
    cstring name;
    size_t size;
    std::vector<std::pair<cstring, EBPFCounterPSA *>> counters;
    std::vector<std::pair<cstring, EBPFMeterPSA *>> meters;

    std::vector<EBPFTableImplementationPSA *> implementations;

    EBPFTablePSA(const EBPFProgram* program, const IR::TableBlock* table,
                 CodeGenInspector* codeGen, cstring name, size_t size);
    EBPFTablePSA(const EBPFProgram* program, CodeGenInspector* codeGen, cstring name);

    void emitInstance(CodeBuilder* builder) override;
    void emitTypes(CodeBuilder* builder) override;
    void emitValueActionIDNames(CodeBuilder* builder) override;
    void emitValueStructStructure(CodeBuilder* builder) override;
    void emitAction(CodeBuilder* builder, cstring valueName, cstring actionRunVariable) override;
    void emitInitializer(CodeBuilder* builder) override;
    void emitDirectTypes(CodeBuilder* builder) override;
    void emitLookup(CodeBuilder* builder, cstring key, cstring value) override;
    void emitLookupDefault(CodeBuilder* builder, cstring key, cstring value) override;
    bool dropOnNoMatchingEntryFound() const override;
    bool singleActionRun() const override;

    virtual void emitCacheTypes(CodeBuilder* builder);
    void emitCacheInstance(CodeBuilder* builder);
    virtual void emitCacheLookup(CodeBuilder* builder, cstring key, cstring value);
    void emitCacheUpdate(CodeBuilder* builder, cstring key, cstring value) override;
    bool cacheEnabled() override { return tableCacheEnabled; }

    EBPFCounterPSA* getCounter(cstring name) const {
        auto result = std::find_if(counters.begin(), counters.end(),
            [name](std::pair<cstring, EBPFCounterPSA *> elem)->bool {
                return name == elem.first;
            });
        if (result != counters.end())
            return result->second;
        return nullptr;
    }

    EBPFMeterPSA* getMeter(cstring name) const {
        auto result = std::find_if(meters.begin(), meters.end(),
            [name](std::pair<cstring, EBPFMeterPSA *> elem)->bool {
               return name == elem.first;
            });
        if (result != meters.end())
            return result->second;
        return nullptr;
    }

    bool isMatchTypeSupported(const IR::Declaration_ID* matchType) override {
        return EBPFTable::isMatchTypeSupported(matchType) ||
               matchType->name.name == "selector";
    }
};

class EBPFTernaryTablePSA : public EBPFTablePSA {
 private:
    std::vector<std::vector<const IR::Entry*>> getConstEntriesGroupedByPrefix();
    bool hasConstEntries();
    const cstring addPrefixFunctionName = "add_prefix_and_entries";
    const cstring tuplesMapName = name + "_tuples_map";
    const cstring prefixesMapName = name + "_prefixes";

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
    static cstring addPrefixFunc(bool trace);

 protected:
    void emitConstEntriesInitializer(CodeBuilder *builder) override;
    void validateKeys() const override;
    void emitValueMask(CodeBuilder *builder, cstring valueMask,
                       cstring nextMask, int tupleId) const;
    void emitKeyMasks(CodeBuilder *builder,
                      std::vector<std::vector<const IR::Entry *>> &entriesList,
                      std::vector<cstring> &keyMasksNames);
    void emitKeysAndValues(CodeBuilder *builder,
                           std::vector<const IR::Entry *> &samePrefixEntries,
                           std::vector<cstring> &keyNames,
                           std::vector<cstring> &valueNames);
};

}  // namespace EBPF

#endif /* BACKENDS_EBPF_PSA_EBPFPSATABLE_H_ */
