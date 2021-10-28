#ifndef BACKENDS_EBPF_PSA_EXTERNS_EBPFPSATABLEIMPLEMENTATION_H_
#define BACKENDS_EBPF_PSA_EXTERNS_EBPFPSATABLEIMPLEMENTATION_H_

#include "backends/ebpf/ebpfTable.h"
#include "backends/ebpf/psa/ebpfPsaObjects.h"
#include "backends/ebpf/psa/externs/ebpfPsaHashAlgorithm.h"

namespace EBPF {

class EBPFTableImplementationPSA : public EBPFTablePSA {
 public:
    EBPFTableImplementationPSA(const EBPFProgram* program, CodeGenInspector* codeGen,
                               const IR::Declaration_Instance* decl);

    void emitTypes(CodeBuilder* builder) override;
    void emitInitializer(CodeBuilder *builder) override;
    virtual void emitReferenceEntry(CodeBuilder *builder);

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

    unsigned getUintFromExpression(const IR::Expression * expr, unsigned defaultValue);
};

class EBPFActionProfilePSA : public EBPFTableImplementationPSA {
 public:
    EBPFActionProfilePSA(const EBPFProgram* program, CodeGenInspector* codeGen,
                         const IR::Declaration_Instance* decl);

    void emitInstance(CodeBuilder *builder) override;
    void applyImplementation(CodeBuilder* builder, cstring tableValueName,
                             cstring actionRunVariable) override;
};

class EBPFActionSelectorPSA : public EBPFTableImplementationPSA {
 public:
    EBPFActionSelectorPSA(const EBPFProgram* program, CodeGenInspector* codeGen,
                          const IR::Declaration_Instance* decl);

    void emitInitializer(CodeBuilder *builder) override;
    void emitInstance(CodeBuilder *builder) override;
    void emitReferenceEntry(CodeBuilder *builder) override;

    void applyImplementation(CodeBuilder* builder, cstring tableValueName,
                             cstring actionRunVariable) override;

    void registerTable(const EBPFTablePSA * instance) override;

    void emitCacheTypes(CodeBuilder* builder) override;
    void emitCacheVariables(CodeBuilder* builder);
    void emitCacheLookup(CodeBuilder* builder, cstring key, cstring value) override;
    void emitCacheUpdate(CodeBuilder* builder, cstring key, cstring value) override;

 protected:
    typedef std::vector<const IR::KeyElement *> selectorsListType;

    const IR::Property * emptyGroupAction;
    EBPFHashAlgorithmPSA * hashEngine;
    selectorsListType selectors;
    cstring actionsMapName;
    cstring groupsMapName;
    cstring emptyGroupActionMapName;
    size_t groupsMapSize;
    cstring outputHashMask;
    cstring isGroupEntryName;
    cstring groupStateVarName;
    cstring cacheKeyVar;
    cstring cacheDoUpdateVar;

    EBPFHashAlgorithmPSA::argumentsList unpackSelectors();
    selectorsListType getSelectorsFromTable(const EBPFTablePSA * instance);

    void verifyTableSelectorKeySet(const EBPFTablePSA * instance);
    void verifyTableEmptyGroupAction(const EBPFTablePSA * instance);
};

}  // namespace EBPF

#endif  // BACKENDS_EBPF_PSA_EXTERNS_EBPFPSATABLEIMPLEMENTATION_H_
