/*
Copyright 2022-present Orange
Copyright 2022-present Open Networking Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef BACKENDS_EBPF_PSA_EBPFPSATABLE_H_
#define BACKENDS_EBPF_PSA_EBPFPSATABLE_H_

#include "frontends/p4/methodInstance.h"
#include "backends/ebpf/ebpfTable.h"
#include "ebpfPsaControl.h"

namespace EBPF {

class EBPFTableImplementationPSA;

class EBPFTablePSA : public EBPFTable {
 private:
    void emitTableDecl(CodeBuilder *builder,
                       cstring tblName,
                       TableKind kind,
                       cstring keyTypeName,
                       cstring valueTypeName,
                       size_t size) const;

 protected:
    ActionTranslationVisitor* createActionTranslationVisitor(
            cstring valueName, const EBPFProgram* program) const override;

    void initImplementation();

    // Executes `func` for every entry in given property
    template<class F>
    void forEachPropertyEntry(cstring propertyName, F func) {
        auto counterProperty = table->container->properties->getProperty(propertyName);
        if (counterProperty == nullptr)
            return;
        if (counterProperty->value->is<IR::ExpressionValue>()) {
            auto ev = counterProperty->value->to<IR::ExpressionValue>();
            if (ev->expression->is<IR::PathExpression>()) {
                func(ev->expression->to<IR::PathExpression>());
            } else if (ev->expression->is<IR::ListExpression>()) {
                auto le = ev->expression->to<IR::ListExpression>();
                for (auto c : le->components) {
                    func(c->to<IR::PathExpression>());
                }
            } else {
                ::error(ErrorType::ERR_UNSUPPORTED,
                        "Unsupported list type: %1%", counterProperty->value);
            }
        } else {
            ::error(ErrorType::ERR_UNKNOWN,
                    "Unknown property expression type: %1%", counterProperty->value);
        }
    }

    void emitTableValue(CodeBuilder* builder, const IR::MethodCallExpression* actionMce,
                        cstring valueName);
    void emitDefaultActionInitializer(CodeBuilder *builder);
    void emitConstEntriesInitializer(CodeBuilder *builder);
    void emitMapUpdateTraceMsg(CodeBuilder *builder, cstring mapName,
                               cstring returnCode) const;

 public:
    // TODO: DirectMeter and DirectCounter are not implemented now, but
    //  they are need in table implementation to validate table properties
    std::vector<cstring> counters;
    std::vector<cstring> meters;
    EBPFTableImplementationPSA * implementation;

    EBPFTablePSA(const EBPFProgram* program, const IR::TableBlock* table,
                 CodeGenInspector* codeGen);
    EBPFTablePSA(const EBPFProgram* program, CodeGenInspector* codeGen, cstring name);

    void emitInstance(CodeBuilder* builder) override;
    void emitTypes(CodeBuilder* builder) override;
    void emitValueStructStructure(CodeBuilder* builder) override;
    void emitAction(CodeBuilder* builder, cstring valueName, cstring actionRunVariable) override;
    void emitInitializer(CodeBuilder* builder) override;
    void emitLookup(CodeBuilder* builder, cstring key, cstring value) override;
    void emitLookupDefault(CodeBuilder* builder, cstring key, cstring value) override;
    bool dropOnNoMatchingEntryFound() const override;
};

}  // namespace EBPF

#endif /* BACKENDS_EBPF_PSA_EBPFPSATABLE_H_ */
