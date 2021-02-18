
#include "ebpfPsaObjects.h"

namespace EBPF {

// =====================EBPFTablePSA=============================
void EBPFTablePSA::emitInstance(CodeBuilder *builder) {
    builder->target->emitTableDecl(builder, name, tableKind,
                                   cstring("struct ") + keyTypeName,
                                   cstring("struct ") + valueTypeName, size);
    builder->target->emitTableDecl(builder, defaultActionMapName, TableArray,
                                   program->arrayIndexType,
                                   cstring("struct ") + valueTypeName, 1);
}

}  // namespace EBPF
