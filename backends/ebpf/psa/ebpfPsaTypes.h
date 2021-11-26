#ifndef BACKENDS_EBPF_PSA_EBPFPSATYPES_H_
#define BACKENDS_EBPF_PSA_EBPFPSATYPES_H_

#include "backends/ebpf/ebpfType.h"

namespace EBPF {

// represents an error type for PSA
class EBPFErrorTypePSA : public EBPFType {
 public:
    explicit EBPFErrorTypePSA(const IR::Type_Error * type) : EBPFType(type) {}

    void emit(CodeBuilder* builder) override;
    void declare(CodeBuilder* builder, cstring id, bool asPointer) override;
    void emitInitializer(CodeBuilder* builder) override;

    const IR::Type_Error* getType() const { return type->to<IR::Type_Error>(); }
};

class UsageInspector;
class EBPFHeaderTypePSA : public EBPFStructType {
 protected:
    class FieldsGroup {
     public:
        std::vector<EBPFField*> fields;
        unsigned int groupWidth = 0;
        unsigned int groupOffset = 0;
        bool byteSwapRequired = true;
    };
    std::vector<FieldsGroup*> groupedFields;

    void createFieldsGroups();
    void emitField(CodeBuilder* builder, EBPFField* field);

 public:
    explicit EBPFHeaderTypePSA(const IR::Type_Header* header);

    void emit(CodeBuilder* builder) override;

    void skipByteSwapForUnusedFields(UsageInspector * usedFields, const IR::Expression * header);
    bool isReadyToMemcpy() const;

    template<class F1, class F2, class F3>
    void emitBELEConversion(CodeBuilder * builder, F1 ByteSwapper, bool skipBuiltinMethods,
                            F2 LognFieldSwapper, F3 BuiltinByteSwapper) const {
        builder->appendLine("#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__");
        for (auto group : groupedFields) {
            cstring swap, swap_type;
            unsigned swap_size;
            if (group->groupWidth <= 8 || !group->byteSwapRequired) {
                continue;
            } else if (group->groupWidth <= 16) {
                if (skipBuiltinMethods) {
                    ByteSwapper(0, 1, group->groupOffset);
                    continue;
                }
                swap = "htons";
                swap_size = 16;
                swap_type = "u16";
            } else if (group->groupWidth <= 24) {
                ByteSwapper(0, 2, group->groupOffset);
                continue;
            } else if (group->groupWidth <= 32) {
                if (skipBuiltinMethods) {
                    ByteSwapper(0, 3, group->groupOffset);
                    ByteSwapper(1, 2, group->groupOffset);
                    continue;
                }
                swap = "htonl";
                swap_size = 32;
                swap_type = "u32";
            } else if (group->groupWidth <= 40) {
                ByteSwapper(0, 4, group->groupOffset);
                ByteSwapper(1, 3, group->groupOffset);
                continue;
            } else if (group->groupWidth <= 48) {
                ByteSwapper(0, 5, group->groupOffset);
                ByteSwapper(1, 4, group->groupOffset);
                ByteSwapper(2, 3, group->groupOffset);
                continue;
            } else if (group->groupWidth <= 56) {
                ByteSwapper(0, 6, group->groupOffset);
                ByteSwapper(1, 5, group->groupOffset);
                ByteSwapper(2, 4, group->groupOffset);
                continue;
            } else if (group->groupWidth <= 64) {
                if (skipBuiltinMethods) {
                    ByteSwapper(0, 7, group->groupOffset);
                    ByteSwapper(1, 6, group->groupOffset);
                    ByteSwapper(2, 5, group->groupOffset);
                    ByteSwapper(3, 4, group->groupOffset);
                    continue;
                }
                swap = "htonll";
                swap_size = 64;
                swap_type = "u64";
            } else {
                LognFieldSwapper(group->groupWidth / 8, group->groupOffset);
                continue;
            }

            BuiltinByteSwapper(swap, swap_type, swap_size - group->groupWidth,
                               group->groupOffset);
        }
        builder->appendLine("#endif");
    }
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EBPFPSATYPES_H_ */
