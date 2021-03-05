
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

// =====================EBPFTernaryTablePSA=============================
void EBPFTernaryTablePSA::emitInstance(CodeBuilder *builder) {
    builder->target->emitTableDecl(builder, name + "_prefixes", TableTernary,
                                   cstring("struct ") + keyTypeName,
                                   cstring("struct ") + valueTypeName, size);
//    builder->target->emitTableDecl(builder, name + "_tuples_map", TableHash,
//                                   cstring("struct ") + keyTypeName,
//                                   cstring("struct ") + valueTypeName, size);
}

void EBPFTernaryTablePSA::emitKeyType(CodeBuilder *builder) {
    builder->emitIndent();
    builder->appendFormat("struct %s ", keyTypeName.c_str());
    builder->blockStart();

    CodeGenInspector commentGen(program->refMap, program->typeMap);
    commentGen.setBuilder(builder);

    unsigned int structAlignment = 4; // 4 by default
    unsigned int totalSizeOfKeys = 0;
    if (keyGenerator != nullptr) {
        std::vector<std::pair<size_t, const IR::KeyElement*>> ordered;
        unsigned fieldNumber = 0;
        for (auto c : keyGenerator->keyElements) {
            auto type = program->typeMap->getType(c->expression);
            auto ebpfType = EBPFTypeFactory::instance->create(type);
            cstring fieldName = cstring("field") + Util::toString(fieldNumber);
            if (!ebpfType->is<IHasWidth>()) {
                ::error(ErrorType::ERR_TYPE_ERROR,
                        "%1%: illegal type %2% for key field", c, type);
                return;
            }
            unsigned width = ebpfType->to<IHasWidth>()->widthInBits();
            if (ebpfType->to<EBPFScalarType>()->alignment() > structAlignment) {
                structAlignment = 8;
            }

            totalSizeOfKeys += ebpfType->to<EBPFScalarType>()->bytesRequired();
            ordered.emplace_back(width, c);
            keyTypes.emplace(c, ebpfType);
            keyFieldNames.emplace(c, fieldName);
            fieldNumber++;
        }

        // Use this to order elements by size
        std::stable_sort(ordered.begin(), ordered.end(),
                [] (std::pair<size_t, const IR::KeyElement*> p1,
                    std::pair<size_t, const IR::KeyElement*> p2) {
            return p1.first <= p2.first;
        });

        // Emit key in decreasing order size - this way there will be no gaps
        for (auto it = ordered.rbegin(); it != ordered.rend(); ++it) {
            auto c = it->second;

            auto ebpfType = ::get(keyTypes, c);
            builder->emitIndent();
            cstring fieldName = ::get(keyFieldNames, c);
            ebpfType->declare(builder, fieldName, false);
            builder->append("; /* ");
            c->expression->apply(commentGen);
            builder->append(" */");
            builder->newline();
        }
    }

    builder->blockEnd(false);
    builder->appendFormat(" __attribute__((aligned(%d)))", structAlignment);
    builder->endOfStatement(true);

    // generate mask key
    builder->emitIndent();
    builder->appendFormat("struct %s_mask ", keyTypeName.c_str());
    builder->blockStart();

    builder->emitIndent();
    builder->appendFormat("__u8 mask[%d];", totalSizeOfKeys);
    builder->newline();

    builder->blockEnd(false);
    builder->appendFormat(" __attribute__((aligned(%d)))", structAlignment);
    builder->endOfStatement(true);
}

}  // namespace EBPF
