#include "ebpfPsaTypes.h"
#include "ebpfPipeline.h"

namespace EBPF {

void EBPFErrorTypePSA::emit(CodeBuilder* builder) {
    auto terr = this->getType();
    int id = -1;
    for (auto decl : terr->members) {
        ++id;
        auto sourceFile = decl->srcInfo.getSourceFile();
        // all the error codes are located in core.p4 file, they are defined in psa.h
        if (sourceFile.endsWith("p4include/core.p4"))
            continue;
        // for future, also exclude definitions in psa.p4 file
        if (sourceFile.endsWith("p4include/psa.p4"))
            continue;

        builder->emitIndent();
        builder->append("static const ParserError_t ");
        builder->appendFormat("%s = %d", decl->name.name, id);
        builder->endOfStatement(true);

        // type u8 can have values from 0 to 255
        if (id > 255) {
            ::warning(ErrorType::ERR_OVERLIMIT,
                      "%1%: Reached maximum number of possible errors", decl);
        }
    }

    builder->newline();
}

void EBPFErrorTypePSA::declare(CodeBuilder* builder, cstring id, bool asPointer) {
    (void) builder; (void) id; (void) asPointer;
    BUG("Error type is not declarable");
}

void EBPFErrorTypePSA::emitInitializer(CodeBuilder* builder) {
    (void) builder;
    BUG("Error type cannot be initialized");
}

//////////////////////////////////////////////////////////

EBPFHeaderTypePSA::EBPFHeaderTypePSA(const IR::Type_Header* header) : EBPFStructType(header) {
    createFieldsGroups();
}

void EBPFHeaderTypePSA::createFieldsGroups() {
    // This algorithm groups fields within byte(s) boundary or separate fields larger than 64 bits
    FieldsGroup * currentGroup = nullptr;
    unsigned int currentOffset = 0;
    unsigned int groupSize = 0;
    bool unableToCreateType = false;

    for (auto f : fields) {
        if (currentGroup == nullptr) {
            currentGroup = new FieldsGroup;
            currentGroup->groupOffset = currentOffset;
            groupSize = 0;
        }

        auto wt = f->type->to<IHasWidth>();
        if (wt == nullptr)
            continue;
        unsigned int width = wt->widthInBits();

        if (width > 64) {
            if (groupSize != 0 || width % 8 != 0) {
                unableToCreateType = true;
                break;
            } else {
                currentGroup->fields.push_back(f);
                currentGroup->groupWidth += width;
                groupedFields.push_back(currentGroup);
                currentGroup = nullptr;
            }
        } else {
            if (groupSize + width > 64) {
                unableToCreateType = true;
                break;
            } else if ((groupSize + width) % 8 == 0) {
                currentGroup->fields.push_back(f);
                currentGroup->groupWidth += width;
                groupedFields.push_back(currentGroup);
                currentGroup = nullptr;
            } else {
                currentGroup->fields.push_back(f);
                currentGroup->groupWidth += width;
                groupSize += width;
            }
        }

        currentOffset += width;
    }

    // clear artifacts if algorithm failed
    if (unableToCreateType)
        groupedFields.clear();
}

void EBPFHeaderTypePSA::emitField(CodeBuilder* builder, EBPFField* field) {
    builder->emitIndent();

    auto type = field->type;
    auto wt = type->to<IHasWidth>();
    if (wt == nullptr)
        return;

    unsigned int width = wt->widthInBits();
    if (width > 64) {
        type->declare(builder, field->field->name, false);
        builder->append("; ");
    } else {
        builder->appendFormat("unsigned long %s : %u; ", field->field->name.name.c_str(), width);
    }
    builder->append("/* ");
    builder->append(type->type->toString());
    if (field->comment != nullptr) {
        builder->append(" ");
        builder->append(field->comment);
    }
    builder->append(" */");
    builder->newline();
}

void EBPFHeaderTypePSA::emit(CodeBuilder* builder) {
    if (!isReadyToMemcpy()) {
        EBPFStructType::emit(builder);
        return;
    }

    builder->emitIndent();
    builder->appendFormat("%s %s ", kind.c_str(), name.c_str());
    builder->blockStart();

    builder->appendLine("#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__");

    // In big endian byte order we can just define fields as in P4 program
    for (auto f : fields) {
        emitField(builder, f);
    }

    builder->appendLine("#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__");

    // In little endian byte order emit fields in group in reverse order. Preserve order of groups.
    for (auto group : groupedFields) {
        for (auto iter = group->fields.rbegin(); iter != group->fields.rend(); ++iter) {
            emitField(builder, *iter);
        }
    }

    builder->appendLine("#endif");

    // For now add validity bit at the end of this structure
    auto type = EBPFTypeFactory::instance->create(IR::Type_Boolean::get());
    if (type != nullptr) {
        builder->emitIndent();
        type->declare(builder, "ebpf_valid", false);
        builder->endOfStatement(true);
    }

    builder->blockEnd(false);
    builder->append(" __attribute__((packed))");
    builder->endOfStatement(true);
}

void EBPFHeaderTypePSA::skipByteSwapForUnusedFields(UsageInspector * usedFields,
                                                    const IR::Expression * header) {
    for (auto group : groupedFields) {
        group->byteSwapRequired = false;
        for (auto f : group->fields) {
            cstring key = usedFields->resolveNodePath(header, f->field->name.name);
            if (usedFields->isUsed(key)) {
                group->byteSwapRequired = true;
                break;
            }
        }
    }
}

bool EBPFHeaderTypePSA::isReadyToMemcpy() const {
    return !groupedFields.empty();
}

}  // namespace EBPF
