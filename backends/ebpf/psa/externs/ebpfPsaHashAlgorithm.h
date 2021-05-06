#ifndef BACKENDS_EBPF_PSA_EXTERNS_EBPFPSAHASHALGORITHM_H_
#define BACKENDS_EBPF_PSA_EXTERNS_EBPFPSAHASHALGORITHM_H_

#include "backends/ebpf/ebpfObject.h"

namespace EBPF {

class EBPFProgram;

class EBPFHashAlgorithmPSA : public EBPFObject {
 protected:
    cstring baseName;
    const EBPFProgram* program;
    Visitor * visitor;

    typedef std::vector<const IR::Expression *> argumentsList;
    argumentsList unpackArguments(const IR::MethodCallExpression * expr, int dataPos);

 public:
    // keep this enum in sync with psa.p4 file
    enum HashAlgorithm {
        IDENTITY,
        CRC32,
        CRC32_CUSTOM,
        CRC16,
        CRC16_CUSTOM,
        ONES_COMPLEMENT16,  // aka InternetChecksum
        TARGET_DEFAULT
    };

    EBPFHashAlgorithmPSA(const EBPFProgram* program, cstring name, Visitor * visitor)
        : baseName(name), program(program), visitor(visitor) {}

    virtual void emitVariables(CodeBuilder* builder, const IR::Declaration_Instance* decl);

    virtual void emitClear(CodeBuilder* builder);
    virtual void emitAddData(CodeBuilder* builder, int dataPos,
                             const IR::MethodCallExpression * expr);
    virtual void emitGet(CodeBuilder* builder);

    virtual void emitSubtractData(CodeBuilder* builder, int dataPos,
                                  const IR::MethodCallExpression * expr);

    virtual void emitGetInternalState(CodeBuilder* builder);
    virtual void emitSetInternalState(CodeBuilder* builder,
                                      const IR::MethodCallExpression * expr);
};

class InternetChecksumAlgorithm : public EBPFHashAlgorithmPSA {
 protected:
    cstring stateVar;

    void updateChecksum(CodeBuilder* builder, int dataPos,
                        const IR::MethodCallExpression * expr, bool addData);

 public:
    InternetChecksumAlgorithm(const EBPFProgram* program, cstring name, Visitor * visitor)
        : EBPFHashAlgorithmPSA(program, name, visitor) {}

    static void emitGlobals(CodeBuilder* builder);

    void emitVariables(CodeBuilder* builder, const IR::Declaration_Instance* decl) override;

    void emitClear(CodeBuilder* builder) override;
    void emitAddData(CodeBuilder* builder, int dataPos,
                     const IR::MethodCallExpression * expr) override;
    void emitGet(CodeBuilder* builder) override;

    void emitSubtractData(CodeBuilder* builder, int dataPos,
                          const IR::MethodCallExpression * expr) override;

    void emitGetInternalState(CodeBuilder* builder) override;
    void emitSetInternalState(CodeBuilder* builder,
                              const IR::MethodCallExpression * expr) override;
};

class CRCChecksumAlgorithm : public EBPFHashAlgorithmPSA {
 protected:
    cstring registerVar;
    cstring initialValue;
    cstring updateMethod;
    cstring finalizeMethod;
    cstring polynomial;
    const int crcWidth;

    cstring reflect(cstring str);

 public:
    CRCChecksumAlgorithm(const EBPFProgram* program, cstring name, Visitor * visitor, int width)
            : EBPFHashAlgorithmPSA(program, name, visitor), crcWidth(width) {}

    static void emitUpdateMethod(CodeBuilder* builder, int crcWidth);

    void emitVariables(CodeBuilder* builder, const IR::Declaration_Instance* decl) override;

    void emitClear(CodeBuilder* builder) override;
    void emitAddData(CodeBuilder* builder, int dataPos,
                     const IR::MethodCallExpression * expr) override;
    void emitGet(CodeBuilder* builder) override;

    void emitSubtractData(CodeBuilder* builder, int dataPos,
                          const IR::MethodCallExpression * expr) override;

    void emitGetInternalState(CodeBuilder* builder) override;
    void emitSetInternalState(CodeBuilder* builder,
                              const IR::MethodCallExpression * expr) override;
};

class CRC16ChecksumAlgorithm : public CRCChecksumAlgorithm {
 public:
    CRC16ChecksumAlgorithm(const EBPFProgram* program, cstring name, Visitor * visitor)
            : CRCChecksumAlgorithm(program, name, visitor, 16) {
        initialValue = "0";
        polynomial = reflect("0x8005");
        updateMethod = "crc16_update";
        finalizeMethod = "crc16_finalize";
    }

    static void emitGlobals(CodeBuilder* builder);
};

class CRC32ChecksumAlgorithm : public CRCChecksumAlgorithm {
 public:
    CRC32ChecksumAlgorithm(const EBPFProgram* program, cstring name, Visitor * visitor)
            : CRCChecksumAlgorithm(program, name, visitor, 32) {
        initialValue = "0xffffffff";
        polynomial = reflect("0x04c11db7");
        updateMethod = "crc32_update";
        finalizeMethod = "crc32_finalize";
    }

    static void emitGlobals(CodeBuilder* builder);
};

class EBPFHashAlgorithmTypeFactoryPSA {
 public:
    static EBPFHashAlgorithmTypeFactoryPSA * instance() {
        static EBPFHashAlgorithmTypeFactoryPSA factory;
        return &factory;
    }

    EBPFHashAlgorithmPSA * create(int type, const EBPFProgram* program, cstring name,
                                  Visitor * visitor) {
        if (type == EBPFHashAlgorithmPSA::HashAlgorithm::CRC32)
            return new CRC32ChecksumAlgorithm(program, name, visitor);
        else if (type == EBPFHashAlgorithmPSA::HashAlgorithm::CRC16)
            return new CRC16ChecksumAlgorithm(program, name, visitor);
        else if (type == EBPFHashAlgorithmPSA::HashAlgorithm::ONES_COMPLEMENT16 ||
                type == EBPFHashAlgorithmPSA::HashAlgorithm::TARGET_DEFAULT)
            return new InternetChecksumAlgorithm(program, name, visitor);

        return nullptr;
    }

    void emitGlobals(CodeBuilder* builder) {
        CRC16ChecksumAlgorithm::emitGlobals(builder);
        CRC32ChecksumAlgorithm::emitGlobals(builder);
        InternetChecksumAlgorithm::emitGlobals(builder);
    }
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_EXTERNS_EBPFPSAHASHALGORITHM_H_ */
