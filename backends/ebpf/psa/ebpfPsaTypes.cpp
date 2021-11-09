#include "ebpfPsaTypes.h"

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

}  // namespace EBPF
