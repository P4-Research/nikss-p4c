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
#include "ebpfPipeline.h"

namespace EBPF {

class ActionTranslationVisitorPSA : public ActionTranslationVisitor,
                                    public ControlBodyTranslatorPSA {
 public:
    ActionTranslationVisitorPSA(const EBPFProgram* program, cstring valueName) :
            CodeGenInspector(program->refMap, program->typeMap),
            ActionTranslationVisitor(valueName, program),
            ControlBodyTranslatorPSA(program->to<EBPFPipeline>()->control) {}

    bool preorder(const IR::PathExpression* pe) override;
    bool isActionParameter(const IR::Expression *expression) const;

    void processMethod(const P4::ExternMethod* method) override;
};

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
            cstring valueName, const EBPFProgram* program) const override {
        return new ActionTranslationVisitorPSA(program->to<EBPFPipeline>(), valueName);
    }

    void emitTableValue(CodeBuilder* builder, const IR::MethodCallExpression* actionMce,
                        cstring valueName);
    void emitDefaultActionInitializer(CodeBuilder *builder);
    void emitConstEntriesInitializer(CodeBuilder *builder);
    void emitMapUpdateTraceMsg(CodeBuilder *builder, cstring mapName,
                               cstring returnCode) const;

 public:
    EBPFTablePSA(const EBPFProgram* program, const IR::TableBlock* table,
                 CodeGenInspector* codeGen);
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
