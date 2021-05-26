
#include "xdpTarget.h"

namespace EBPF {
    void XdpTarget::emitIncludes(Util::SourceCodeBuilder* builder) const {
        builder->append("#include \"xdp_kernel.h\"\n");
        builder->newline();
    }
}  // namespace EBPF
