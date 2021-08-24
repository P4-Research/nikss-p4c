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

#include "ebpfBackend.h"
#include "target.h"
#include "ebpfType.h"
#include "ebpfProgram.h"

#include "psa/ebpfPsaArch.h"
#include "psa/xdpTarget.h"

namespace EBPF {

void emitFilterModel(const EbpfOptions& options, Target* target, const IR::ToplevelBlock* toplevel,
                     P4::ReferenceMap* refMap, P4::TypeMap* typeMap) {
    CodeBuilder c(target);
    CodeBuilder h(target);

    EBPFTypeFactory::createFactory(typeMap);
    auto ebpfprog = new EBPFProgram(options, toplevel->getProgram(), refMap, typeMap, toplevel);
    if (!ebpfprog->build())
        return;

    if (options.outputFile.isNullOrEmpty())
        return;

    cstring cfile = options.outputFile;
    auto cstream = openFile(cfile, false);
    if (cstream == nullptr)
        return;

    cstring hfile;
    const char* dot = cfile.findlast('.');
    if (dot == nullptr)
        hfile = cfile + ".h";
    else
        hfile = cfile.before(dot) + ".h";
    auto hstream = openFile(hfile, false);
    if (hstream == nullptr)
        return;

    ebpfprog->emitH(&h, hfile);
    ebpfprog->emitC(&c, hfile);
    *cstream << c.toString();
    *hstream << h.toString();
    cstream->flush();
    hstream->flush();
}

void emitPSAModel(const EbpfOptions& options, Target* target, const IR::ToplevelBlock* toplevel,
                  P4::ReferenceMap* refMap, P4::TypeMap* typeMap) {
    auto main = toplevel->getMain();
    if (main->type->name != "PSA_Switch") {
        ::warning(ErrorType::WARN_INVALID,
                  "%1%: the main package should be called PSA_Switch"
                  "; are you using the wrong architecture?",
                  main->type->name);
        return;
    }

    BMV2::PsaProgramStructure structure(refMap, typeMap);
    auto parsePsaArch = new BMV2::ParsePsaArchitecture(&structure);
    main->apply(*parsePsaArch);

    EBPFTypeFactory::createFactory(typeMap);
    auto convertToEbpfPSA = new ConvertToEbpfPSA(options, structure, refMap, typeMap);
    PassManager psaPasses = {
            new BMV2::DiscoverStructure(&structure),
            new BMV2::InspectPsaProgram(refMap, typeMap, &structure),
            new DoMakeStandardMetadataNamesUnique(),
            // convert to EBPF objects
            convertToEbpfPSA,
    };
    psaPasses.addDebugHook(options.getDebugHook(), true);
    toplevel->apply(psaPasses);

    if (options.outputFile.isNullOrEmpty())
        return;

    cstring cfile = options.outputFile;
    auto cstream = openFile(cfile, false);
    if (cstream == nullptr)
        return;

    CodeBuilder c(target);
    auto psaArchForEbpf = convertToEbpfPSA->getPSAArchForEBPF();
    // instead of generating two files, put all the code in a single file
    if (!options.generateToXDP) {
        psaArchForEbpf->emit2TC(&c);
    } else {
        psaArchForEbpf->emit2XDP(&c);
    }
    *cstream << c.toString();
    cstream->flush();
}

void run_ebpf_backend(const EbpfOptions& options, const IR::ToplevelBlock* toplevel,
                      P4::ReferenceMap* refMap, P4::TypeMap* typeMap) {
    if (toplevel == nullptr)
        return;

    auto main = toplevel->getMain();
    if (main == nullptr) {
        ::warning(ErrorType::WARN_MISSING,
                  "Could not locate top-level block; is there a %1% module?",
                  IR::P4Program::main);
        return;
    }

    Target* target;
    if (options.target.isNullOrEmpty() || options.target == "kernel") {
        if (!options.generateToXDP)
            target = new KernelSamplesTarget(options.emitTraceMessages);
        else
            target = new XdpTarget(options.emitTraceMessages);
    } else if (options.target == "bcc") {
        target = new BccTarget();
    } else if (options.target == "test") {
        target = new TestTarget();
    } else {
        ::error(ErrorType::ERR_UNKNOWN,
                "Unknown target %s; legal choices are 'bcc', 'kernel', and test", options.target);
        return;
    }

    if (options.arch.isNullOrEmpty() || options.arch == "filter") {
        emitFilterModel(options, target, toplevel, refMap, typeMap);
    } else if (options.arch == "psa") {
        emitPSAModel(options, target, toplevel, refMap, typeMap);
    } else {
        ::error(ErrorType::ERR_UNKNOWN,
                "Unknown architecture %s; legal choices are 'filter', and 'psa'", options.arch);
        return;
    }
}

}  // namespace EBPF
