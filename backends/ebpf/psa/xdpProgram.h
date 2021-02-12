#ifndef P4C_XDPPROGRAM_H
#define P4C_XDPPROGRAM_H

#include "backends/ebpf/ebpfProgram.h"

namespace EBPF {

// In the current implementation, XDPProgram implements the XDP "helper" program, that makes the packet pre-processing before
// passing it up to the TC subsystem.
// TODO: if XDP offloading will be used, we will need to inherit from EBPFProgram or EBPFPipeline.
// Thus, we use EBPFProgram for future use.
class XDPProgram : public EBPFProgram {
  public:
    cstring sectionName;
    explicit XDPProgram(const EbpfOptions& options) :
        EBPFProgram(options, nullptr, nullptr, nullptr, nullptr) {
        sectionName = "xdp-ingress";
        functionName = "xdp_func";
    }

    void emit(CodeBuilder *builder);
};

}

#endif //P4C_XDPPROGRAM_H
