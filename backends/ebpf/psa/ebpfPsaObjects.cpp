
#include "ebpfPsaObjects.h"

namespace EBPF {

// =====================EBPFTablePSA=============================
void EBPFTablePSA::emitInstance(CodeBuilder *builder) {
    builder->target->emitTableDecl(builder, name, TableHash,
                                   cstring("struct ") + keyTypeName,
                                   cstring("struct ") + valueTypeName, size);
    builder->target->emitTableDecl(builder, defaultActionMapName, TableArray,
                                   program->arrayIndexType,
                                   cstring("struct ") + valueTypeName, 1);
}

// =====================EBPFTernaryTablePSA=============================
void EBPFTernaryTablePSA::emitInstance(CodeBuilder *builder) {
    builder->target->emitTableDecl(builder, name + "_prefixes", TableHash,
                                   "struct " + keyTypeName + "_mask",
                                   "struct " + valueTypeName + "_mask", size);
    builder->target->emitMapInMapDecl(builder, name + "_tuple",
                                      TableHash, "struct " + keyTypeName,
                                      "struct " + valueTypeName, size,
                                      name + "_tuples_map",TableArray, "__u32", size);
    builder->target->emitTableDecl(builder, defaultActionMapName, TableArray,
                                   program->arrayIndexType,
                                   cstring("struct ") + valueTypeName, 1);
}

void EBPFTernaryTablePSA::emitKeyType(CodeBuilder *builder) {
    builder->emitIndent();
    builder->appendFormat("struct %s ", keyTypeName.c_str());
    builder->blockStart();

    CodeGenInspector commentGen(program->refMap, program->typeMap);
    commentGen.setBuilder(builder);

    unsigned int structAlignment = 4; // 4 by default
    unsigned int totalSizeOfKeys = 0;
    unsigned int lengthOfTernaryFields = 0;
    unsigned int lengthOfLPMFields = 0;
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

            auto mtdecl = program->refMap->getDeclaration(c->matchType->path, true);
            auto matchType = mtdecl->getNode()->to<IR::Declaration_ID>();
            if (matchType->name.name == P4::P4CoreLibrary::instance.ternaryMatch.name) {
                lengthOfTernaryFields += width;
            } else if (matchType->name.name == P4::P4CoreLibrary::instance.lpmMatch.name) {
                lengthOfLPMFields += width;
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
    // we set 256 as maximum number of ternary masks due to BPF_COMPLEXITY_LIMIT_JMP_SEQ.
    // TODO: find better solution to workaround BPF_COMPLEXITY_LIMIT_JMP_SEQ.
    builder->appendFormat("#define MAX_%s_MASKS %d", keyTypeName.toUpper(), 256);
    builder->newline();

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

void EBPFTernaryTablePSA::emitTableLookup(CodeBuilder *builder, cstring key, cstring value) {
    builder->appendFormat("struct %s_mask head = {0};", keyTypeName);
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("struct %s_mask *", valueTypeName);
    builder->target->emitTableLookup(builder, name + "_prefixes", "head", "val");
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->append("if (val && val->has_next != 0) ");
    builder->blockStart();
    builder->emitIndent();
    builder->appendFormat("struct %s_mask next = val->next_tuple_mask;", keyTypeName);
    builder->newline();
    builder->emitIndent();
    builder->appendLine("#pragma clang loop unroll(disable)");
    builder->emitIndent();
    builder->appendFormat("for (int i = 0; i < MAX_%s_MASKS; i++) ", keyTypeName.toUpper());
    builder->blockStart();
    builder->emitIndent();
    builder->appendFormat("struct %s_mask *", valueTypeName);
    builder->target->emitTableLookup(builder, name + "_prefixes", "next", "v");
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->append("if (!v) ");
    builder->blockStart();
    builder->target->emitTraceMessage(builder,
                                      "Control: No next element found!");
    builder->emitIndent();
    builder->appendLine("break;");
    builder->blockEnd(true);
    builder->emitIndent();
    cstring new_key = "k";
    builder->appendFormat("struct %s %s = {};", keyTypeName, new_key);
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("__u32 *chunk = ((__u32 *) &%s);", new_key);
    builder->newline();
    builder->emitIndent();
    builder->appendLine("__u32 *mask = ((__u32 *) &next);");
    builder->emitIndent();
    builder->appendLine("#pragma clang loop unroll(disable)");
    builder->emitIndent();
    builder->appendFormat("for (int i = 0; i < sizeof(struct %s_mask) / 4; i++) ", keyTypeName);
    builder->blockStart();
    cstring str = Util::printf_format("*(((__u32 *) &%s) + i)", key);
    builder->target->emitTraceMessage(builder,
                                      "Control: [Ternary] Masking next 4 bytes of %llx with mask %llx",
                                      2, str, "mask[i]");

    builder->emitIndent();
    builder->appendFormat("chunk[i] = ((__u32 *) &%s)[i] & mask[i];", key);
    builder->newline();
    builder->blockEnd(true);

    builder->emitIndent();
    builder->appendLine("__u32 tuple_id = v->tuple_id;");
    builder->emitIndent();
    builder->append("next = v->next_tuple_mask;");
    builder->newline();
    builder->emitIndent();
    builder->append("struct bpf_elf_map *");
    builder->target->emitTableLookup(builder, name + "_tuples_map",
            "tuple_id", "tuple");
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->append("if (!tuple) ");
    builder->blockStart();
    builder->target->emitTraceMessage(builder,
      Util::printf_format("Control: Tuples map %s not found during ternary lookup. Bug?",
              name));
    builder->emitIndent();
    builder->append("break;");
    builder->newline();
    builder->blockEnd(true);

    builder->emitIndent();
    builder->appendFormat("struct %s *tuple_entry = "
                          "bpf_map_lookup_elem(%s, &%s)",
                          valueTypeName, "tuple", new_key);
    builder->endOfStatement(true);
    builder->emitIndent();
    builder->append("if (!tuple_entry) ");
    builder->blockStart();
    builder->emitIndent();
    builder->append("if (v->has_next == 0) ");
    builder->blockStart();
    builder->emitIndent();
    builder->appendLine("break;");
    builder->blockEnd(true);
    builder->emitIndent();
    builder->append("continue;");
    builder->newline();
    builder->blockEnd(true);
    builder->target->emitTraceMessage(builder,
            "Control: Ternary match found, priority=%d.", 1, "tuple_entry->priority");

    builder->emitIndent();
    builder->appendFormat("if (%s == NULL || tuple_entry->priority > %s->priority) ",
            value, value);
    builder->blockStart();
    builder->emitIndent();
    builder->appendFormat("%s = tuple_entry;", value);
    builder->newline();
    builder->blockEnd(true);

    builder->emitIndent();
    builder->append("if (v->has_next == 0) ");
    builder->blockStart();
    builder->emitIndent();
    builder->appendLine("break;");
    builder->blockEnd(true);
    builder->blockEnd(true);
    builder->blockEnd(true);
}

}  // namespace EBPF
