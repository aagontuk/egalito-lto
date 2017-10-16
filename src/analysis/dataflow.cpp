#include "analysis/dataflow.h"
#include "analysis/walker.h"
#include "analysis/usedef.h"
#include "analysis/usedefutil.h"
#include "elf/elfspace.h"
#include "chunk/concrete.h"
#include "instr/semantic.h"
#include "instr/linked-aarch64.h"
#include "operation/find2.h"

#include "log/log.h"

#ifdef ARCH_AARCH64
void DataFlow::addUseDefFor(Function *function) {
    auto graph = new ControlFlowGraph(function);
    auto config = new UDConfiguration(graph);
    auto working = new UDRegMemWorkingSet(function, graph);
    auto usedef = new UseDef(config, working);

    SccOrder order(graph);
    order.genFull(0);
    usedef->analyze(order.get());

    flowList[function] = usedef;
    workingList.push_back(working);
    configList.push_back(config);
    graphList.push_back(graph);
}

UDRegMemWorkingSet *DataFlow::getWorkingSet(Function *function) {
    auto it = flowList.find(function);
    if(it == flowList.end()) {
        addUseDefFor(function);
    }
    return flowList[function]->getWorkingSet<UDRegMemWorkingSet>();
}

void DataFlow::adjustCallUse(
    LiveRegister *live, Function *function, Module *module) {

    //LOG(1, "adjusting callUse for " << function->getName());

    for(auto block : CIter::children(function)) {
        for(auto instr: CIter::children(block)) {
            auto s = instr->getSemantic();
            auto assembly = s->getAssembly();
            if(!assembly) continue;
            if(assembly->getId() == ARM64_INS_BL) {
                auto v = dynamic_cast<ControlFlowInstruction *>(s);
                Function *func = nullptr;
                if(auto target = v->getLink()->getTarget()) {
                    // in some cases (like Go binary), it jumps to the
                    // middle of a function (runtime.duffzero)
                    if(auto f = dynamic_cast<Function *>(&*target)) {
                        func = ChunkFind2().findFunctionInModule(
                            f->getName().c_str(), module);
                    }
                }
                if(!func) continue;

                if(dynamic_cast<PLTTrampoline *>(func)) continue;

                auto working = getWorkingSet(function);
                auto state = working->getState(instr);

                auto info = live->getInfo(func);

                //R0 - R18
                auto ud = flowList[function];
                for(int i = 0; i < 19; i++) {
                    if(info.get(i)) {
                        LOG(10, "canceling use of " << std::dec << i);
                        ud->cancelUseDefReg(state, i);
                    }
                }
                IF_LOG(11) state->dumpState();
            }
            else if(assembly->getId() == ARM64_INS_BLR) {
                auto working = getWorkingSet(function);
                auto state = working->getState(instr);
                if(isTLSdescResolveCall(state, module)) {
                    auto ud = flowList[function];
                    // reg0 holds the TLS offset after return
                    for(int i = 1; i < 19; i++) {
                        LOG(10, "canceling use of " << std::dec << i);
                        ud->cancelUseDefReg(state, i);
                    }
                }
                IF_LOG(11) state->dumpState();
            }
        }
    }
}

bool DataFlow::isTLSdescResolveCall(UDState *state, Module *module) {
    // this always comes in the form of page + offset
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > MakePointerForm;

    FlowPatternMatch<MakePointerForm> pm;
    FlowUtil::collectUpDef(state, AARCH64GPRegister::R0, pm);
    for(auto& capList : pm.getResult()) {
        auto upState = capList[0].state;
        auto reg = dynamic_cast<TreeNodePhysicalRegister *>(capList[0].tree)
            ->getRegister();
        auto offset = dynamic_cast<TreeNodeConstant *>(capList[1].tree)
            ->getValue();

        LOG(10, "arg0 offset = 0x" << std::hex << offset);
        typedef TreePatternCapture<
            TreePatternTerminal<TreeNodeAddress>
        > PointerPageForm;

        FlowPatternMatch<PointerPageForm> pm2;
        FlowUtil::collectUpDef(upState, reg, pm2);
        for(auto& capList2 : pm2.getResult()) {
            auto page = dynamic_cast<TreeNodeAddress *>(capList2[0].tree)
                ->getValue();

            LOG(10, "arg0 addr = 0x" << std::hex << (page + offset));
            auto r = module->getElfSpace()->getRelocList()->find(page + offset);
            if(r && r->getType() == R_AARCH64_TLSDESC) {
                return true;
            }
        }
    }
    return false;
}

DataFlow::~DataFlow() {
    for(auto m : flowList) {
        delete m.second;
    }
    for(auto s : workingList) {
        delete s;
    }
    for(auto c : configList) {
        delete c;
    }
    for(auto g : graphList) {
        delete g;
    }
}
#endif
