#pragma once
#include "kernel_control.hpp"

namespace vrp {
inline std::optional<uint64_t> kernelConstantBefore(const KernelModule& module,int target,uint64_t pc,unsigned depth=0) {
    if(target==31)return 0;
    if(depth>4)return {};
    for(int64_t at=int64_t(pc)-4;at>=0&&uint64_t(at)+512>=pc;at-=4){const auto* pointer=module.tryInstruction(uint64_t(at));if(!pointer)continue;
        const auto& ins=*pointer;if((named(ins,"bl")||named(ins,"blr"))&&target<19)return {};
        if(!module.writes(ins).count(target))continue;
        if(named(ins,"mov")){
            if(operand(ins,1).type==ARM64_OP_IMM){uint64_t value=uint64_t(imm(ins,1));if(module.registerName(operand(ins,0).reg).front()=='w')value&=0xffffffffu;return value;}
            return kernelConstantBefore(module,reg(module,ins,1),uint64_t(at),depth+1);
        }
        if(named(ins,"movk")){auto previous=kernelConstantBefore(module,target,uint64_t(at),depth+1);if(!previous)return {};
            unsigned shift=operand(ins,1).shift.value;require(shift<=48,"MOVK shift invalid");
            return (*previous&~(uint64_t(65535)<<shift))|((uint64_t(imm(ins,1))&65535)<<shift);}
        return {};
    }return {};
}
inline std::optional<uint32_t> kernelBufferArgumentBefore(const KernelModule& module,int target,int buffer,uint64_t pc) {
    for(int64_t at=int64_t(pc)-4;at>=0&&uint64_t(at)+128>=pc;at-=4){const auto& ins=module.instruction(uint64_t(at));
        if((named(ins,"bl")||named(ins,"blr"))&&target<19)return {};
        if(!module.writes(ins).count(target))continue;
        if(named(ins,"mov")&&operand(ins,1).type==ARM64_OP_REG&&reg(module,ins,1)==buffer)return 0;
        if(named(ins,"add")&&reg(module,ins,1)==buffer&&operand(ins,2).type==ARM64_OP_IMM&&operand(ins,2).shift.value==0){
            int64_t offset=imm(ins,2);require(offset>=0&&offset<=UINT32_MAX,"Buffer argument displacement invalid");return uint32_t(offset);}
        return {};
    }return {};
}
inline bool kernelHelperCalls(const KernelModule& module,uint64_t pc,const std::string& name) {
    for(uint64_t at=pc;at<pc+64;at+=4){const auto& ins=module.instruction(at);
        if(named(ins,"bl")&&module.externalCall(at,name))return true;
        if(named(ins,"ret"))return false;
    }return false;
}
inline bool kernelByteCopyHelper(const KernelModule& module,uint64_t pc) {
    const auto& end=module.instruction(pc);const auto& alias=module.instruction(pc+4);const auto& load=module.instruction(pc+8);
    const auto& count=module.instruction(pc+12);const auto& store=module.instruction(pc+16);const auto& again=module.instruction(pc+20);
    if(!(named(end,"cbz")&&named(alias,"mov")&&named(load,"ldrb")&&named(count,"subs")&&named(store,"strb")&&named(again,"b.ne")&&named(module.instruction(pc+24),"ret")))return false;
    return reg(module,end,0)==2&&codeAddress(imm(end,1))==pc+24&&reg(module,alias,1)==0
        &&operand(load,1).type==ARM64_OP_MEM&&module.registerIndex(operand(load,1).mem.base)==1&&imm(load,2)==1
        &&reg(module,count,0)==2&&reg(module,count,1)==2&&imm(count,2)==1
        &&reg(module,store,0)==reg(module,load,0)&&operand(store,1).type==ARM64_OP_MEM
        &&module.registerIndex(operand(store,1).mem.base)==reg(module,alias,0)&&imm(store,2)==1&&codeAddress(imm(again,0))==pc+8;
}
struct KernelTextCodec {uint32_t seed=0,period=0,rotate=0;bool operator==(const KernelTextCodec& other)const{return seed==other.seed&&period==other.period&&rotate==other.rotate;}};
inline KernelTextCodec discoverKernelTextCodec(const KernelModule& module,uint64_t copyPc) {
    for(uint64_t at=copyPc+4;at<copyPc+84;at+=4){const auto& ins=module.instruction(at);
        if(!named(ins,"eor")||operand(ins,2).type!=ARM64_OP_REG)continue;
        int key=reg(module,ins,2);std::optional<uint64_t> last,seed,initial;
        for(uint64_t before=at>=28?std::max(copyPc+4,at-28):copyPc+4;before<at;before+=4){const auto& candidate=module.instruction(before);
            if(named(candidate,"cmp")&&reg(module,candidate,0)==key&&operand(candidate,1).type==ARM64_OP_IMM){last=uint64_t(imm(candidate,1));initial=kernelConstantBefore(module,key,before);}
            if(named(candidate,"csinc")&&reg(module,candidate,0)==key&&reg(module,candidate,2)==key&&candidate.detail->arm64.cc==ARM64_CC_HS)
                seed=kernelConstantBefore(module,reg(module,candidate,1),before);
        }
        require(last&&seed&&initial&&*seed>0&&*seed<=*last&&*last<32&&*initial+1==*seed,"Unknown record text key cycle");
        const auto& rotate=module.instruction(at+12);const auto& combine=module.instruction(at+16);const auto& store=module.instruction(at+20);
        require(named(rotate,"ubfx")&&named(combine,"orr")&&named(store,"strb"),"Unknown record text rotation");
        int64_t right=imm(rotate,2),width=imm(rotate,3);require(width>0&&width<8&&right+width==8
                &&operand(combine,2).shift.value==uint64_t(width)&&reg(module,rotate,1)==reg(module,combine,2)
                &&reg(module,combine,1)==reg(module,rotate,0)&&reg(module,store,0)==reg(module,combine,0),"Record text rotation operands disagree");
        return {uint32_t(*seed),uint32_t(*last-*seed+1),uint32_t(width)};
    }throw std::runtime_error("No record text encoding loop");
}
struct KernelLogPlan {MountLogLayout layout;uint64_t headerPc=0,recordPc=0,ringPc=0,tailPc=0;};
inline KernelLogPlan discoverKernelLogLayout(const KernelModule& module) {
    struct Header {uint64_t pc;uint32_t magic,marker;int buffer;};
    std::map<std::tuple<uint32_t,uint32_t,int>,std::vector<Header>> groups;
    for(uint64_t at=0;at<module.textSize();at+=4){const auto* pointer=module.tryInstruction(at);if(!pointer)continue;const auto& ins=*pointer;
        if(!named(ins,"stp")||module.registerName(operand(ins,0).reg).front()!='w'||operand(ins,2).type!=ARM64_OP_MEM||operand(ins,2).mem.disp!=0)continue;
        auto magic=kernelConstantBefore(module,reg(module,ins,0),at),marker=kernelConstantBefore(module,reg(module,ins,1),at);
        int buffer=module.registerIndex(operand(ins,2).mem.base);
        if(!magic||*magic<=65535||*magic>UINT32_MAX||!marker||*marker==0||*marker>UINT32_MAX||buffer<0||buffer==32)continue;
        groups[{uint32_t(*magic),uint32_t(*marker),buffer}].push_back({at,uint32_t(*magic),uint32_t(*marker),buffer});
    }
    std::vector<std::vector<Header>> pairs;for(const auto& group:groups)if(group.second.size()==2)pairs.push_back(group.second);
    require(pairs.size()==1,"No unique paired kernel header/record construction");
    const auto header=pairs[0][0],record=pairs[0][1];int buffer=header.buffer;std::vector<uint32_t> sizes;
    for(const auto& store:{header,record}){std::vector<uint64_t> found;
        for(int64_t at=int64_t(store.pc)-4;at>=0&&uint64_t(at)+64>store.pc;at-=4){const auto& ins=module.instruction(uint64_t(at));
            if(!named(ins,"bl")||module.relocation(uint64_t(at))||module.hasExternal(uint64_t(at)))continue;
            auto offset=kernelBufferArgumentBefore(module,0,buffer,uint64_t(at));
            if(offset&&*offset==0&&kernelHelperCalls(module,codeAddress(imm(ins,0)),"memset")){
                auto size=kernelConstantBefore(module,1,uint64_t(at));if(size)found.push_back(*size);}
        }
        require(found.size()==1&&found[0]<=UINT32_MAX,"No unique kernel record buffer clear");sizes.push_back(uint32_t(found[0]));
    }
    require(sizes[0]==sizes[1]&&sizes[0]>=128&&sizes[0]<=8192&&(sizes[0]&(sizes[0]-1))==0,"Kernel record clear sizes differ");
    uint32_t size=sizes[0];KernelLogPlan plan;auto& layout=plan.layout;layout.magic=header.magic;layout.marker=header.marker;
    layout.recordBytes=size;plan.headerPc=header.pc;plan.recordPc=record.pc;
    unsigned geometries=0;
    for(uint64_t at=record.pc>=256?record.pc-256:0;at<record.pc;at+=4){const auto& ins=module.instruction(at);
        if(!named(ins,"and")||operand(ins,2).type!=ARM64_OP_IMM)continue;
        int64_t mask=imm(ins,2);if(mask<int64_t(size)||mask%size||at<12)continue;
        const auto& shift=module.instruction(at-12);const auto& compare=module.instruction(at-8);
        const auto& increment=module.instruction(at-4);const auto& select=module.instruction(at+4);
        if(!(named(shift,"lsl")&&named(compare,"cmp")&&named(increment,"add")&&named(select,"csel")))continue;
        int64_t bits=imm(shift,2);require(bits>=0&&bits<32&&(uint64_t(1)<<bits)==size&&imm(increment,2)==size
                &&imm(compare,1)+1==(mask+size)/size&&reg(module,shift,0)==reg(module,ins,1)
                &&reg(module,shift,0)==reg(module,increment,0)&&reg(module,increment,0)==reg(module,increment,1)
                &&reg(module,shift,1)==reg(module,compare,0)&&reg(module,select,1)==reg(module,ins,1)
                &&reg(module,select,2)==reg(module,ins,0),"Inconsistent kernel ring geometry");
        require(mask+size<=UINT32_MAX,"Kernel ring size overflow");layout.regionBytes=uint32_t(mask+size);plan.ringPc=at;++geometries;
    }
    require(geometries==1,"No unique kernel ring geometry");unsigned tails=0;
    for(uint64_t at=header.pc>=4096?header.pc-4096:0;at<header.pc;at+=4){const auto* pointer=module.tryInstruction(at);if(!pointer)continue;const auto& ins=*pointer;
        if(!named(ins,"sub")||operand(ins,2).type!=ARM64_OP_IMM)continue;
        unsigned shift=operand(ins,2).shift.value;if(shift>20||imm(ins,2)<0)continue;uint64_t tail=uint64_t(imm(ins,2))<<shift;
        if(tail<layout.regionBytes||tail>1048576)continue;
        for(uint64_t later=at+4;later<at+28;later+=4){const auto& candidate=module.instruction(later);
            if(named(candidate,"blr")){auto offset=kernelBufferArgumentBefore(module,1,reg(module,ins,0),later);auto origin=kernelConstantBefore(module,2,later);
                if(offset&&*offset==0&&origin&&*origin==0){layout.tailOffset=uint32_t(tail);plan.tailPc=at;++tails;}break;}
        }
    }
    require(tails==1,"No unique kernel partition-tail seek");
    struct Copy {uint32_t offset;KernelTextCodec codec;};std::vector<Copy> copies;
    for(uint64_t at=record.pc+4;at<module.textSize()&&at<record.pc+512;at+=4){const auto& ins=module.instruction(at);
        if(!named(ins,"bl")||module.hasExternal(at))continue;
        auto offset=kernelBufferArgumentBefore(module,0,buffer,at);if(!offset||*offset==0||*offset>=size)continue;
        if(kernelByteCopyHelper(module,codeAddress(imm(ins,0))))copies.push_back({*offset,discoverKernelTextCodec(module,at)});
    }
    std::sort(copies.begin(),copies.end(),[](const Copy& a,const Copy& b){return a.offset<b.offset;});
    require(copies.size()==3&&copies[0].offset<copies[1].offset&&copies[1].offset<copies[2].offset,"Unknown kernel record text fields");
    require(copies[0].codec==copies[1].codec&&copies[0].codec==copies[2].codec,"Kernel record fields use different text encodings");
    std::optional<uint32_t> counter;std::vector<uint32_t> sentinels;
    for(uint64_t at=header.pc+4;at<header.pc+20;at+=4){const auto& ins=module.instruction(at);
        if(named(ins,"stp")&&operand(ins,2).type==ARM64_OP_MEM&&module.registerIndex(operand(ins,2).mem.base)==buffer){
            auto value=kernelConstantBefore(module,reg(module,ins,1),at);if(value&&*value==0xffffffffu){int32_t offset=operand(ins,2).mem.disp;
                require(offset>=0,"Negative kernel header field");counter=uint32_t(offset);sentinels.push_back(uint32_t(offset)+4);}}
        if(named(ins,"str")&&operand(ins,1).type==ARM64_OP_MEM&&module.registerIndex(operand(ins,1).mem.base)==buffer){
            auto value=kernelConstantBefore(module,reg(module,ins,0),at);if(value&&*value==0xffffffffu){int32_t offset=operand(ins,1).mem.disp;
                require(offset>=0,"Negative kernel sentinel offset");sentinels.push_back(uint32_t(offset));}}
    }
    std::sort(sentinels.begin(),sentinels.end());require(counter&&sentinels.size()==2&&sentinels[0]!=sentinels[1],"Unknown kernel header counter/sentinels");
    layout.counterOffset=*counter;layout.sentinelOffsets[0]=sentinels[0];layout.sentinelOffsets[1]=sentinels[1];
    layout.firmwareOffset=copies[0].offset;layout.firmwareBytes=copies[1].offset-copies[0].offset;
    layout.eventOffset=copies[1].offset;layout.eventBytes=copies[2].offset-copies[1].offset;
    layout.messageOffset=copies[2].offset;layout.messageBytes=size-copies[2].offset;
    layout.xorSeed=copies[0].codec.seed;layout.xorPeriod=copies[0].codec.period;layout.rotateLeft=copies[0].codec.rotate;
    require(valid_mount_log_layout(layout),"Derived kernel log layout failed range validation");return plan;
}
}
