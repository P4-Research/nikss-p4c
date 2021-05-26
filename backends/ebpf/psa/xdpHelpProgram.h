#ifndef BACKENDS_EBPF_PSA_XDPHELPPROGRAM_H_
#define BACKENDS_EBPF_PSA_XDPHELPPROGRAM_H_

#include "backends/ebpf/ebpfProgram.h"

namespace EBPF {

// In the current implementation, XDPHelpProgram implements the XDP "helper" program,
// that makes the packet pre-processing before passing it up to the TC subsystem.
// TODO: if XDP offloading will be used, we will need to inherit from EBPFProgram or EBPFPipeline.
// Thus, we use EBPFProgram for future use.
class XDPHelpProgram : public EBPFProgram {
 public:
    cstring sectionName;
    explicit XDPHelpProgram(const EbpfOptions& options) :
        EBPFProgram(options, nullptr, nullptr, nullptr, nullptr) {
        sectionName = "xdp/xdp-ingress";
        functionName = "xdp_func";
    }

    void emit(CodeBuilder *builder);
};

}  // namespace EBPF

#endif  /* BACKENDS_EBPF_PSA_XDPHELPPROGRAM_H_ */
