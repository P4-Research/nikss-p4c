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
                 EBPFTable(program, table, codeGen), tableKind(tableKind), name(name), size(size) { }

    void emitInstance(CodeBuilder* builder) override;
};

}  // namespace EBPF

#endif /* BACKENDS_EBPF_PSA_EBPFPSAOBJECTS_H_ */
