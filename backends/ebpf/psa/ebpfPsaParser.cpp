#include "ebpfPsaParser.h"

namespace EBPF_PSA {

    bool EBPFPsaParser::build() {
        auto pl = parserBlock->type->applyParams;
        if (pl->size() != 6) {
            ::error(ErrorType::ERR_EXPECTED,
                    "Expected parser to have exactly 6 parameters");
            return false;
        }

        auto it = pl->parameters.begin();
        packet = *it; ++it;
        headers = *it;
        for (auto state : parserBlock->states) {
            auto ps = new EBPF::EBPFParserState(state, this);
            states.push_back(ps);
        }

        auto ht = typeMap->getType(headers);
        if (ht == nullptr)
            return false;
        headerType = EBPF::EBPFTypeFactory::instance->create(ht);

        return true;
    }

}