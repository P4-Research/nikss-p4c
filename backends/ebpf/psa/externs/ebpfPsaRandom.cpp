#include "frontends/p4/methodInstance.h"
#include "ebpfPsaRandom.h"

namespace EBPF {

EBPFRandomPSA::EBPFRandomPSA(const IR::Declaration_Instance* di) :
        minValue(0), maxValue(0), range(0) {
    CHECK_NULL(di);

    // verify type
    if (!di->type->is<IR::Type_Specialized>()) {
        ::error(ErrorType::ERR_MODEL, "Missing specialization: %1%", di);
        return;
    }
    auto ts = di->type->to<IR::Type_Specialized>();
    BUG_CHECK(ts->arguments->size() == 1, "%1%, Lack of specialization argument", ts);
    auto type = ts->arguments->at(0);
    if (!type->is<IR::Type_Bits>()) {
        ::error(ErrorType::ERR_UNSUPPORTED, "Must be bit or int type: %1%", ts);
        return;
    }
    if (type->width_bits()  > 32) {
        ::error(ErrorType::ERR_UNSUPPORTED, "%1%: up to 32 bits width is supported", ts);
    }

    uint32_t tmp[2] = {0};
    for (int i = 0; i < 2; ++i) {
        auto expr = di->arguments->at(i)->expression->to<IR::Constant>();
        if (expr != nullptr) {
            if (expr->fitsUint()) {
                tmp[i] = expr->asUnsigned();
            } else {
                ::error(ErrorType::ERR_OVERLIMIT, "%1%: size too large", expr);
            }
        } else {
            ::error(ErrorType::ERR_UNSUPPORTED, "Must be constant value: %1%",
                    di->arguments->at(i)->expression);
        }
    }
    minValue = tmp[0];
    maxValue = tmp[1];
    range = maxValue - minValue;
    range = range + 1;

    // verify constructor parameters
    if (minValue > maxValue) {
        ::error(ErrorType::ERR_INVALID, "%1%: Max value lower than min value", di);
    }
    if (minValue == maxValue) {
        ::warning(ErrorType::WARN_IGNORE,
            "%1%: No randomness, will always return the same value "
            "due to that the min value is equal to the max value", di);
    }
}

void EBPFRandomPSA::processMethod(CodeBuilder* builder, const P4::ExternMethod* method) const {
    if (method->method->type->name == "read") {
        emitRead(builder);
    } else {
        ::error(ErrorType::ERR_UNSUPPORTED, "%1%: Method not implemented yet", method->expr);
    }
}

void EBPFRandomPSA::emitRead(CodeBuilder* builder) const {
    if (minValue == maxValue || range == 0) {
        builder->append(minValue);
        return;
    }

    bool rangeIsPowerOf2 = (range & (range - 1)) == 0;

    if (minValue != 0)
        builder->appendFormat("(%uu + ", minValue);

    builder->appendFormat("(bpf_get_prandom_u32() ", minValue);
    if (rangeIsPowerOf2) {
        builder->appendFormat("& 0x%llxu", range - 1);
    } else {
        builder->appendFormat("%% %lluu", range);
    }
    builder->append(")");

    if (minValue != 0)
        builder->append(")");
}

}  // namespace EBPF
