#pragma once
#include "native_code.hpp"

namespace vrp {
struct HalDiscovery {
    uint64_t worker=0,workerEnd=0,creator=0,createPc=0,readPc=0,getPc=0,putPc=0,propertyPc=0;
    uint64_t procBranchPc=0,successBranchPc=0,flagBranchPc=0,rootLoadPc=0,rootStorePc=0;
    uint32_t bufferBytes=0,rootOffset=0;
    std::string implementationSoname,vtable;
};
inline std::string halString(const NativeElf& elf,uint64_t address) {
    std::string out;
    for(unsigned i=0;i<512;i++){auto offset=elf.fileOffset(address+i,1);char ch=char(elf.bytes[size_t(offset)]);if(!ch)return out;require(ch>=32&&ch<=126,"Native contract string is not printable");out+=ch;}
    throw std::runtime_error("Native contract string exceeds bound");
}
inline bool halStringIs(const NativeElf& elf,const NativeValue& value,const std::string& expected) {
    if(value.kind!=NativeValue::Constant)return false;
    try{return halString(elf,value.value)==expected;}catch(const std::exception&){return false;}
}
inline std::vector<std::string> halDynamicNames(const NativeElf& elf,uint64_t tag) {
    const auto& dynamic=elf.section(".dynamic");require(dynamic.type==6&&dynamic.link<elf.sections.size()&&dynamic.size%16==0&&dynamic.size<=65536,"Malformed ELF dynamic names");
    const auto& strings=elf.sections[dynamic.link];require(strings.type==3,"ELF dynamic string table missing");std::vector<std::string> result;
    for(uint64_t at=dynamic.offset;at<dynamic.offset+dynamic.size;at+=16){uint64_t kind=elf.u64(at);if(!kind)break;if(kind==tag)result.push_back(elf.string(strings,elf.u64(at+8)));}return result;
}
inline std::set<uint64_t> halStringAddresses(const NativeElf& elf,const std::string& wanted) {
    std::set<uint64_t> addresses;
    for(const auto& s:elf.sections)if((s.flags&2)&&!(s.flags&4)&&s.type!=8&&s.size>=wanted.size()+1) {
        for(uint64_t i=0;i+wanted.size()+1<=s.size;i++)if(std::memcmp(elf.bytes.data()+s.offset+i,wanted.c_str(),wanted.size()+1)==0)addresses.insert(s.address+i);
    }
    return addresses;
}
inline std::set<uint64_t> halAddressReferences(const NativeElf& elf,const std::set<uint64_t>& addresses) {
    const auto& text=elf.section(".text");std::set<uint64_t> result;
    for(uint64_t pc=text.address;pc+8<=text.address+text.size;pc+=4) {
        uint32_t word=elf.instruction(pc);if((word&0x9f000000u)!=0x90000000u&&(word&0x9f000000u)!=0x10000000u)continue;
        int64_t immediate=((word>>5)&0x7ffffu)*4+((word>>29)&3);if(immediate&(1<<20))immediate-=int64_t(1)<<21;
        uint64_t address=(word&0x80000000u)?uint64_t(int64_t(pc&~uint64_t(4095))+immediate*4096):uint64_t(int64_t(pc)+immediate);
        if((word&0x80000000u)==0){if(addresses.count(address))result.insert(pc);continue;}
        unsigned destination,source;uint32_t offset;
        if(a64_add_immediate(elf.instruction(pc+4),destination,source,offset)&&source==(word&31)&&addresses.count(address+offset))result.insert(pc);
    }
    return result;
}
inline std::set<std::pair<uint64_t,uint64_t>> halWorkers(const NativeElf& elf,const NativeCode& code) {
    auto addresses=halStringAddresses(elf,"/proc/isroot/isroot");require(!addresses.empty(),"HAL lacks proc input contract");std::set<std::pair<uint64_t,uint64_t>> result;
    for(auto pc:halAddressReferences(elf,addresses))result.insert(code.function(pc));
    return result;
}
inline NativeValue halOperand(const NativeFlow& flow,uint64_t pc,unsigned index) {
    const auto& ins=flow.code.instruction(pc);const auto& op=flow.code.operand(ins,index);
    if(op.type==ARM64_OP_IMM)return NativeValue::constant(uint64_t(op.imm));
    if(op.type==ARM64_OP_REG){int reg=flow.code.regIndex(op.reg);if(reg>=0)return flow.value(pc,reg);}return {};
}
inline uint32_t halNvBufferBytes(const NativeElf& factory,const NvLayout& layout) {
    auto get=factory.symbol("get_IQOO_NV_item");require(get.size&&get.size<=65536,"Unbounded public NV read API");std::set<uint32_t> lengths;
    for(uint64_t pc=get.address+4;pc+4<=get.address+get.size;pc+=4)if(factory.call(pc,"memcmp")) {
        uint32_t length;if(a64_mov_immediate(factory.instruction(pc-4),2,length)&&length>=layout.digestOffset+16&&length<=layout.recordBytes)lengths.insert(length);
    }
    require(lengths.size()==1,"Missing/ambiguous public NV payload extent");return *lengths.begin();
}
inline HalDiscovery halWorker(const NativeElf& elf,const NativeCode& code,uint64_t start,uint64_t end,const NvLayout& layout,uint32_t payloadBytes) {
    NativeFlow first(code,start,end);HalDiscovery plan;plan.worker=start;plan.workerEnd=end;plan.bufferBytes=payloadBytes;plan.rootOffset=layout.rootOffset;
    const std::set<std::string> allowed={"__open_2","open","read","close","sleep","__errno","strerror","log_em_module","memset","get_IQOO_NV_item","put_IQOO_NV_item","vivoatcmd_set_system_property","pthread_self","pthread_detach","__stack_chk_fail"};
    std::vector<uint64_t> reads,gets,puts,properties,clears;
    for(const auto& entry:first.states) {
        uint64_t pc=entry.first;const auto& ins=code.instruction(pc);std::string mnemonic=ins.mnemonic;
        require(mnemonic!="blr"&&mnemonic!="br","Indirect HAL worker control flow unsupported");if(mnemonic!="bl")continue;
        std::string name=code.callName(ins);require(allowed.count(name),"Unknown call in root-writing HAL worker: "+name);
        if(name=="__open_2"||name=="open")require(halStringIs(elf,first.value(pc,0),"/proc/isroot/isroot")&&first.value(pc,1)==NativeValue::constant(0),"HAL opens an unknown proc source");
        if(name=="read")reads.push_back(pc);
        if(name=="get_IQOO_NV_item")gets.push_back(pc);
        if(name=="put_IQOO_NV_item")puts.push_back(pc);
        if(name=="vivoatcmd_set_system_property")properties.push_back(pc);
        if(name=="memset")clears.push_back(pc);
    }
    require(reads.size()==1&&gets.size()==1&&puts.size()==1&&properties.size()==1,"Missing/ambiguous HAL read/write/property flow");
    plan.readPc=reads[0];plan.getPc=gets[0];plan.putPc=puts[0];plan.propertyPc=properties[0];
    auto descriptor=first.value(plan.readPc,0),procBuffer=first.value(plan.readPc,1),readBytes=first.value(plan.readPc,2),nvBuffer=first.value(plan.getPc,0);
    require(descriptor.kind==NativeValue::ProcFile&&halStringIs(elf,NativeValue::constant(descriptor.value),"/proc/isroot/isroot")
            &&procBuffer.kind==NativeValue::Stack&&readBytes.kind==NativeValue::Constant&&readBytes.value>0&&readBytes.value<=64,"Unverified HAL proc read buffer");
    require(nvBuffer.kind==NativeValue::Stack&&first.value(plan.putPc,0)==nvBuffer,"NV read/write buffers differ");
    require(layout.rootOffset+4<=payloadBytes&&payloadBytes<=layout.recordBytes,"HAL root field outside NV payload");
    unsigned cleared=0;
    for(auto pc:clears)if(first.value(pc,0)==nvBuffer&&first.value(pc,1)==NativeValue::constant(0)&&first.value(pc,2)==NativeValue::constant(payloadBytes)&&first.dominates(pc,plan.getPc))cleared++;
    require(cleared==1,"HAL NV buffer does not match official payload extent");
    require(halStringIs(elf,first.value(plan.propertyPc,0),"persist.sys.is_root")&&halStringIs(elf,first.value(plan.propertyPc,1),"1"),"Unknown HAL root property semantics");
    std::vector<NativeMemorySource> sources={{NativeValue::ProcBytes,int64_t(procBuffer.value),uint32_t(readBytes.value),plan.readPc},
        {NativeValue::NvField,int64_t(nvBuffer.value),payloadBytes,plan.getPc}};
    require(sources[0].start+int64_t(sources[0].bytes)<=sources[1].start||sources[1].start+int64_t(sources[1].bytes)<=sources[0].start,"HAL input and NV buffers overlap");
    NativeFlow flow(code,start,end,sources);
    std::vector<uint64_t> procBranches,flagBranches,successBranches,stores,rootLoads;
    for(const auto& entry:flow.states) {
        uint64_t pc=entry.first;const auto& ins=code.instruction(pc);std::string name=ins.mnemonic;
        require(name!="svc"&&name!="hvc"&&name!="smc"&&name!="msr"&&name!="eret"&&name!="sys"&&name!="sysl","Unexpected system side effect in HAL worker");
        if((name=="ldr"||name=="ldur")&&pc>plan.getPc&&pc<plan.putPc&&code.operand(ins,0).type==ARM64_OP_REG) {
            auto pointer=flow.address(pc,code.operand(ins,1));
            if(pointer.kind==NativeValue::Stack&&int64_t(pointer.value)-int64_t(nvBuffer.value)==layout.rootOffset&&code.width(code.operand(ins,0).reg)==4)rootLoads.push_back(pc);
        }
        if(name=="cbz"&&halOperand(flow,pc,0).kind==NativeValue::NvResult&&halOperand(flow,pc,0).origin==plan.getPc) {
            uint64_t target=uint64_t(code.operand(ins,1).imm);
            if(flow.edgeDominates(pc,target,plan.putPc)&&flow.edgeDominates(pc,target,plan.propertyPc))successBranches.push_back(pc);
        }
        if(name=="b.eq"&&pc>=start+4) {
            const auto& previous=code.instruction(pc-4);uint64_t target=uint64_t(code.operand(ins,0).imm);
            if(std::string(previous.mnemonic)=="cmp") {
                auto left=halOperand(flow,pc-4,0),right=halOperand(flow,pc-4,1);
                if(left.kind==NativeValue::NvField&&left.origin==plan.getPc&&left.width==4&&left.value==layout.rootOffset&&right==NativeValue::constant(1)
                        &&target>plan.putPc&&flow.edgeDominates(pc,pc+4,plan.putPc))flagBranches.push_back(pc);
            }
            if(std::string(previous.mnemonic)=="ccmp"&&pc>=start+8&&std::string(code.instruction(pc-8).mnemonic)=="cmp"
                    &&previous.detail->arm64.cc==ARM64_CC_EQ&&code.operand(previous,2).type==ARM64_OP_IMM&&(code.operand(previous,2).imm&4)==0) {
                std::vector<int> bytes(size_t(readBytes.value),-1);bool valid=true;
                for(uint64_t compare:{pc-8,pc-4}) {
                    auto left=halOperand(flow,compare,0),right=halOperand(flow,compare,1);
                    if(left.kind!=NativeValue::ProcBytes||left.origin!=plan.readPc||right.kind!=NativeValue::Constant||left.value+left.width>bytes.size()){valid=false;break;}
                    for(uint32_t i=0;i<left.width;i++){int value=int((right.value>>(8*i))&255);auto at=size_t(left.value+i);if(bytes[at]>=0&&bytes[at]!=value)valid=false;bytes[at]=value;}
                }
                std::string text;for(int byte:bytes){if(byte<0)valid=false;text+=char(byte);}
                if(valid&&text=="mount state:1"&&flow.edgeDominates(pc,target,plan.getPc))procBranches.push_back(pc);
            }
        }
        if((name=="str"||name=="stur")&&pc>plan.getPc&&pc<plan.putPc) {
            auto pointer=flow.address(pc,code.operand(ins,1));require(pointer.kind==NativeValue::Stack,"Unknown HAL store while NV data is live");
            int64_t relative=int64_t(pointer.value)-int64_t(nvBuffer.value);uint32_t width=code.width(code.operand(ins,0).reg);
            if(relative>=0&&uint64_t(relative)+width<=payloadBytes) {
                require(relative==layout.rootOffset&&width==4&&halOperand(flow,pc,0)==NativeValue::constant(1),"HAL modifies an unknown NV field/value");stores.push_back(pc);
            }
        }
        if((name=="stp"||name=="stnp")&&pc>plan.getPc&&pc<plan.putPc)throw std::runtime_error("Unrecognized pair store while HAL NV data is live");
        if(pc>plan.getPc&&pc<plan.putPc)for(unsigned i=0;i<ins.detail->arm64.op_count;i++) {
            const auto& op=ins.detail->arm64.operands[i];
            if(op.type==ARM64_OP_MEM&&(op.access&CS_AC_WRITE))require(name=="str"||name=="stur","Unrecognized memory write while HAL NV data is live");
        }
    }
    require(procBranches.size()==1&&successBranches.size()==1&&flagBranches.size()==1&&stores.size()==1&&rootLoads.size()==1,"HAL root gating/store contract is ambiguous or incomplete");
    require(flow.dominates(stores[0],plan.putPc)&&flow.dominates(plan.propertyPc,plan.putPc),"HAL writes NV without the identified store/property path");
    require(flow.dominates(rootLoads[0],flagBranches[0]),"NV root load does not reach the root comparison");
    plan.procBranchPc=procBranches[0];plan.successBranchPc=successBranches[0];plan.flagBranchPc=flagBranches[0];plan.rootStorePc=stores[0];plan.rootLoadPc=rootLoads[0];
    return plan;
}
inline HalDiscovery discover_hal_contract(const Bytes& serviceData,const Bytes& implementationData,const Bytes& factoryData,const NvLayout& layout) {
    NativeElf service(serviceData),implementation(implementationData),factory(factoryData);
    auto actual=discover_factory_layout(factoryData).layout;
    require(valid_nv_layout(layout)&&actual.recordBytes==layout.recordBytes&&actual.rootOffset==layout.rootOffset&&actual.digestOffset==layout.digestOffset&&actual.copyStride==layout.copyStride,"HAL layout input differs from actual NV library");
    require(service.u16(16)==3&&implementation.u16(16)==3&&factory.u16(16)==3,"HAL images are not PIE/shared ELF");
    auto names=halDynamicNames(implementation,14);require(names.size()==1&&!names[0].empty()&&names[0].find('/')==std::string::npos,"HAL implementation SONAME unavailable");
    auto needed=halDynamicNames(service,1),dependencies=halDynamicNames(implementation,1);
    require(std::count(needed.begin(),needed.end(),names[0])==1&&std::count(dependencies.begin(),dependencies.end(),"libvivofactory.so")==1,"HAL/NV dependency chain is not declared");
    std::set<std::string> sharedVtables;
    for(const auto& imported:service.dynamicSymbols)if(!imported.section&&imported.type==1&&imported.name.rfind("_ZTV",0)==0)
        for(const auto& exported:implementation.dynamicSymbols)if(exported.section&&exported.type==1&&exported.name==imported.name)sharedVtables.insert(imported.name);
    require(sharedVtables.size()==1,"Missing/ambiguous service implementation vtable");
    for(const char* api:{"AServiceManager_addService","ABinderProcess_joinThreadPool"}) {
        unsigned count=0;for(const auto& symbol:service.dynamicSymbols)if(!symbol.section&&symbol.type==2&&symbol.name==api)count++;
        require(count==1,"HAL Binder registration ABI missing");
    }
    uint32_t payload=halNvBufferBytes(factory,layout);NativeCode code(implementation);std::vector<HalDiscovery> workers;
    for(auto range:halWorkers(implementation,code))workers.push_back(halWorker(implementation,code,range.first,range.second,layout,payload));
    require(workers.size()==1,"Missing/ambiguous HAL root writer");HalDiscovery plan=workers[0];
    std::set<std::pair<uint64_t,uint64_t>> creatorRanges,creators;
    for(auto pc:halAddressReferences(implementation,{plan.worker}))creatorRanges.insert(code.function(pc));
    for(auto range:creatorRanges) {
        NativeFlow flow(code,range.first,range.second);
        for(const auto& entry:flow.states) {
            auto pc=entry.first;if(!implementation.call(pc,"pthread_create")||flow.value(pc,2)!=NativeValue::constant(plan.worker))continue;
            require(flow.value(pc,0).kind==NativeValue::Stack&&flow.value(pc,1)==NativeValue::constant(0)&&flow.value(pc,3)==NativeValue::constant(0),"Unknown HAL root thread creation ABI");
            unsigned exports=0;for(const auto& symbol:implementation.dynamicSymbols)if(symbol.section&&symbol.type==2&&symbol.address==range.first&&symbol.size>=pc-range.first+4)exports++;
            require(exports==1,"HAL thread creator is not a unique public factory entry");creators.insert({range.first,pc});
        }
    }
    require(creators.size()==1,"Missing/ambiguous registered HAL root thread");plan.creator=creators.begin()->first;plan.createPc=creators.begin()->second;
    plan.implementationSoname=names[0];plan.vtable=*sharedVtables.begin();return plan;
}
} // namespace vrp
