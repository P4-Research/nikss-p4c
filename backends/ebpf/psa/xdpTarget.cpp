
#include "xdpTarget.h"

namespace EBPF {
    void XdpTarget::emitIncludes(Util::SourceCodeBuilder* builder) const {
        builder->append("#include \"ebpf_kernel.h\"\n");
        builder->newline();
    }
}  // namespace EBPF
