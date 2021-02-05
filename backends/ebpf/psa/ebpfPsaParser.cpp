#include "ebpfPsaParser.h"

namespace EBPF_PSA {

    bool EBPFPsaParser::build() {
        auto pl = parserBlock->type->applyParams;
        if (pl->size() != 6) {
            ::error(ErrorType::ERR_EXPECTED,
                    "Expected parser to have exactly 6 parameters");
            return false;
        }

        return true;
    }

}