
#include "ebpfPipeline.h"

namespace EBPF {

    void EBPFPipeline::emit(CodeBuilder *builder) {
        builder->target->emitCodeSection(builder, functionName);
        builder->emitIndent();
        builder->target->emitMain(builder, functionName, model.CPacketName.str());
        builder->spc();
        builder->blockStart();

        parser->emit(builder);
        control->emit(builder);
        // TODO: emit deparser
        // deparser->emit(builder);

        builder->blockEnd(true);  // end of function
    }
}
