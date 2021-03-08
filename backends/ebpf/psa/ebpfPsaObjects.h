#ifndef BACKENDS_EBPF_PSA_EBPFPSAOBJECTS_H_
#define BACKENDS_EBPF_PSA_EBPFPSAOBJECTS_H_

#include "backends/ebpf/ebpfTable.h"

namespace EBPF {

class EBPFTablePSA : public EBPFTable {
 public:
    cstring name;
    TableKind tableKind;
    size_t size;

    EBPFTablePSA(const EBPFProgram* program, const IR::TableBlock* table,
                 CodeGenInspector* codeGen, cstring name, TableKind tableKind, size_t size) :
                 EBPFTable(program, table, codeGen), name(name),
                 tableKind(tableKind), size(size) { }

    void emitInstance(CodeBuilder* builder) override;
};

class EBPFTernaryTablePSA : public EBPFTablePSA {

 public:
    EBPFTernaryTablePSA(const EBPFProgram* program, const IR::TableBlock* table,
                 CodeGenInspector* codeGen, cstring name, size_t size) :
            EBPFTablePSA(program, table, codeGen, name, TableTernary, size) { }

    void emitInstance(CodeBuilder* builder) override;
    void emitKeyType(CodeBuilder* builder) override;
    void emitTableLookup(CodeBuilder* builder, cstring key, cstring value) override;
};

}  // namespace EBPF

#endif /* BACKENDS_EBPF_PSA_EBPFPSAOBJECTS_H_ */
