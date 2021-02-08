/*
Copyright 2013-present Barefoot Networks, Inc.

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

#include "backends/bmv2/psa_switch/psaSwitch.h"
#include "lib/error.h"
#include "lib/nullstream.h"
#include "frontends/p4/evaluator/evaluator.h"

#include "backends/ebpf/target.h"
#include "backends/ebpf/ebpfType.h"
#include "backends/ebpf/psa/ebpfPsaArch.h"

#include "ebpfPsaBackend.h"

namespace EBPF_PSA {

    void run_ebpf_backend(const EbpfOptions &options, const IR::ToplevelBlock *tlb,
                          P4::ReferenceMap *refMap, P4::TypeMap *typeMap) {
        CHECK_NULL(tlb);
        BMV2::PsaProgramStructure structure(refMap, typeMap);
        auto parsePsaArch = new BMV2::ParsePsaArchitecture(&structure);
        auto main = tlb->getMain();
        if (!main)
            return;

        if (main->type->name != "PSA_Switch")
            ::warning(ErrorType::WARN_INVALID,
                      "%1%: the main package should be called PSA_Switch"
                      "; are you using the wrong architecture?",
                      main->type->name);

        main->apply(*parsePsaArch);
        auto program = tlb->getProgram();

        EBPF::EBPFTypeFactory::createFactory(typeMap);
        auto convertToEbpfPSA = new ConvertToEbpfPSA(options,structure, refMap, typeMap);
        PassManager psaPasses = {
                new BMV2::DiscoverStructure(&structure),
                new BMV2::InspectPsaProgram(refMap, typeMap, &structure),
                // convert to EBPF objects
                convertToEbpfPSA,
        };
        psaPasses.addDebugHook(options.getDebugHook(), true);
        tlb->apply(psaPasses);

        EBPF::Target* target;
        if (options.target.isNullOrEmpty() || options.target == "kernel") {
            target = new EBPF::KernelSamplesTarget();
        } else if (options.target == "test") {
            target = new EBPF::TestTarget();
        } else {
            // currently we don't support more for PSA
            ::error(ErrorType::ERR_UNKNOWN,
                    "Unknown target %s; legal choices are 'bcc', 'kernel', and test", options.target);
            return;
        }

        if (options.outputFile.isNullOrEmpty())
            return;

        cstring cfile = options.outputFile;
        auto cstream = openFile(cfile, false);
        if (cstream == nullptr)
            return;

        EBPF::CodeBuilder c(target);
        auto psaArchForEbpf = convertToEbpfPSA->getPSAArchForEBPF();
        // instead of generating two files, put all the code in a single file
        psaArchForEbpf->emit(&c);
        *cstream << c.toString();
        cstream->flush();
    }

}  // namespace EBPF_PSA
