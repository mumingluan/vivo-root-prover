#pragma once
#include "kernel_module.hpp"

namespace vrp {
struct KernelBooleanCommand {
    std::string command;
    KernelRelocation target;
    unsigned value=0;
    uint64_t comparisonPc=0,comparatorPc=0,storePc=0;
};
struct KernelGateControl {
    KernelBooleanCommand disable,enable;
    uint64_t gatePc=0,exitPc=0;
};
struct KernelControlPlan {Bytes buildIdNote;std::vector<KernelGateControl> controls;};

inline uint64_t codeAddress(int64_t value){require(value>=0,"Negative kernel code address");return uint64_t(value);}
inline bool sameLocation(const KernelRelocation& a,const KernelRelocation& b){return a.section==b.section && a.offset==b.offset;}
inline uint8_t kernelComparatorKey(const KernelModule& module,uint64_t pc,uint32_t argument) {
    std::map<int,std::pair<uint32_t,bool>> values{{31,{0,false}},{3,{argument,true}}};
    std::map<int,int> pointers{{0,0},{1,1}};
    std::optional<std::pair<int,uint8_t>> key;uint64_t at=pc;
    for(;at<pc+64;at+=4){const auto& ins=module.instruction(at);if(named(ins,"ldrb"))break;
        std::optional<std::pair<uint32_t,bool>> result;std::optional<int> pointer;
        if(named(ins,"mov")){
            if(operand(ins,1).type==ARM64_OP_IMM)result={uint32_t(imm(ins,1)),false};
            else{int source=reg(module,ins,1);auto found=values.find(source);if(found!=values.end())result=found->second;
                auto alias=pointers.find(source);if(alias!=pointers.end())pointer=alias->second;}
        }else if(named(ins,"and")||named(ins,"eor")){
            auto a=values.find(reg(module,ins,1)),b=values.find(reg(module,ins,2));
            require(operand(ins,2).shift.value==0,"Shifted comparison-key expression unsupported");
            if(a!=values.end()&&b!=values.end()){
                result={named(ins,"and")?(a->second.first&b->second.first):(a->second.first^b->second.first),a->second.second||b->second.second};
                if(named(ins,"eor")&&result->second){require(!key,"Ambiguous kernel comparison key");key={reg(module,ins,0),uint8_t(result->first)};}
            }
        }
        for(int written:module.writes(ins)){values.erase(written);pointers.erase(written);}
        if(result)values[reg(module,ins,0)]=*result;
        if(pointer)pointers[reg(module,ins,0)]=*pointer;
        values[31]={0,false};
    }
    require(key.has_value()&&at<pc+64,"No parameter-derived kernel comparison key");
    const auto& cipher=module.instruction(at);const auto& zero=module.instruction(at+4);
    const auto& plain=module.instruction(at+8);const auto& decode=module.instruction(at+12);
    const auto& compare=module.instruction(at+16);const auto& different=module.instruction(at+20);
    require(named(cipher,"ldrb")&&named(zero,"cbz")&&named(plain,"ldrb")&&named(decode,"eor")
            &&named(compare,"subs")&&named(different,"b.ne"),"Unknown kernel byte comparison loop");
    const auto& cipherMemory=operand(cipher,1);const auto& plainMemory=operand(plain,1);
    require(cipherMemory.type==ARM64_OP_MEM&&plainMemory.type==ARM64_OP_MEM,"Comparison bytes not loaded from memory");
    int cipherBase=module.registerIndex(cipherMemory.mem.base),plainBase=module.registerIndex(plainMemory.mem.base);
    require(pointers.count(cipherBase)&&pointers.at(cipherBase)==1&&pointers.count(plainBase)&&pointers.at(plainBase)==0
            &&cipherMemory.mem.disp==0&&plainMemory.mem.disp==0,"Comparison loads have wrong sources");
    require(reg(module,zero,0)==reg(module,cipher,0)&&reg(module,decode,0)==reg(module,cipher,0)
            &&reg(module,decode,1)==reg(module,cipher,0)&&reg(module,decode,2)==key->first
            &&reg(module,compare,1)==reg(module,plain,0)&&reg(module,compare,2)==reg(module,decode,0)
            &&operand(compare,2).ext==ARM64_EXT_UXTB,"Comparison does not compare plaintext with decoded cipher");
    unsigned decrements=0;
    for(uint64_t later=at+24;later<at+52;later+=4){const auto& ins=module.instruction(later);
        if(named(ins,"sub")&&reg(module,ins,0)==key->first&&reg(module,ins,1)==key->first
                &&operand(ins,2).type==ARM64_OP_IMM&&imm(ins,2)==1){const auto& branch=module.instruction(later+4);
            if(named(branch,"b.ne")&&codeAddress(imm(branch,0))==at)++decrements;}
    }
    require(decrements==1,"Comparison key does not decrement through its byte loop");return key->second;
}

inline KernelBooleanCommand kernelControlAction(const KernelModule& module,uint64_t pc) {
    std::map<int,int64_t> constants{{31,0}};std::optional<std::pair<int,KernelRelocation>> base;
    std::optional<KernelBooleanCommand> result;
    for(uint64_t at=pc;at<pc+24;at+=4){const auto& ins=module.instruction(at);
        if(named(ins,"adrp")){auto location=module.relocation(at);require(location.has_value(),"Boolean store base not relocated");base={reg(module,ins,0),*location};}
        else if(named(ins,"mov")&&operand(ins,1).type==ARM64_OP_IMM)constants[reg(module,ins,0)]=imm(ins,1);
        else if(named(ins,"strb")){
            auto target=module.relocation(at);require(base&&target&&sameLocation(base->second,*target),"Boolean store relocation pair disagrees");
            const auto& memory=operand(ins,1);
            require(memory.type==ARM64_OP_MEM&&module.registerIndex(memory.mem.base)==base->first&&memory.mem.disp==0,"Unexpected boolean byte store");
            int source=reg(module,ins,0);
            require((module.sections[target->section].flags&1)&&constants.count(source)
                    &&(constants.at(source)==0||constants.at(source)==1),"Not a writable boolean control");
            KernelBooleanCommand value;value.target=*target;value.value=unsigned(constants.at(source));value.storePc=at;result=value;break;
        }else throw std::runtime_error("Unexpected kernel control-action instruction");
    }
    require(result.has_value(),"No kernel control-action byte store");uint64_t at=result->storePc+4;
    for(unsigned steps=0;steps<20;++steps){const auto& ins=module.instruction(at);
        if(named(ins,"ret"))return *result;
        if(named(ins,"b")){at=codeAddress(imm(ins,0));continue;}
        require(named(ins,"sxtw")||named(ins,"ldp")||named(ins,"ldr")||named(ins,"add")||named(ins,"autiasp")||named(ins,"mov"),"Control action has other side effects");at+=4;
    }
    throw std::runtime_error("Kernel control action does not return within bound");
}

inline KernelControlPlan discoverKernelControls(const KernelModule& module) {
    using Location=std::pair<unsigned,uint64_t>;
    std::map<Location,std::vector<KernelBooleanCommand>> groups;
    for(const auto& entry:module.textRelocations()){
        uint64_t pc=entry.first;const auto& location=entry.second;const auto& section=module.sections[location.section];
        if(location.type!=275 || !(section.flags&2) || (section.flags&5))continue;
        try {
            const auto& first=module.instruction(pc);const auto& second=module.instruction(pc+4);auto low=module.relocation(pc+4);
            require(named(first,"adrp")&&named(second,"add")&&reg(module,first,0)==1&&reg(module,second,0)==1
                    &&reg(module,second,1)==1&&low&&low->type==277&&sameLocation(location,*low),"Not a relocated comparison argument");
            std::map<int,uint32_t> arguments;std::optional<uint64_t> call;
            for(uint64_t at=pc+8;at<pc+36;at+=4){const auto& ins=module.instruction(at);
                if(named(ins,"mov")&&(reg(module,ins,0)==2||reg(module,ins,0)==3)&&operand(ins,1).type==ARM64_OP_IMM)
                    arguments[reg(module,ins,0)]=uint32_t(imm(ins,1));
                else if(named(ins,"bl")){call=at;break;}
                else require(named(ins,"mov")&&reg(module,ins,0)==0,"Unknown comparison arguments");
            }
            require(call&&arguments.size()==2&&arguments.count(2)&&arguments.count(3)&&arguments.at(2)>0&&arguments.at(2)<=128,"No bounded kernel comparison call");
            const auto& match=module.instruction(*call+4);require(named(match,"cbz")&&reg(module,match,0)==0,"Unknown comparator success branch");
            require(!module.hasExternal(*call)&&!module.relocation(*call),"Indirect comparison target unsupported");
            uint64_t comparator=codeAddress(imm(module.instruction(*call),0));uint8_t key=kernelComparatorKey(module,comparator,arguments.at(3));
            require(section.type!=8&&location.offset<section.size&&arguments.at(2)+1<=section.size-location.offset,"Kernel cipher literal outside section");
            uint64_t start=section.offset+location.offset;require(module.data[size_t(start+arguments.at(2))]==0,"Kernel cipher literal lacks terminator");
            std::string command;for(unsigned i=0;i<arguments.at(2);++i){uint8_t byte=module.data[size_t(start+i)]^uint8_t(key-i);
                require(byte>=33&&byte<=126,"Decoded kernel command is not printable");command+=char(byte);}
            auto action=kernelControlAction(module,codeAddress(imm(match,1)));action.command=command;action.comparisonPc=*call;action.comparatorPc=comparator;
            groups[{action.target.section,action.target.offset}].push_back(action);
        }catch(const std::runtime_error&){continue;}
    }
    std::map<Location,std::pair<KernelBooleanCommand,KernelBooleanCommand>> pairs;
    for(const auto& group:groups){if(group.second.size()!=2||group.second[0].value==group.second[1].value)continue;
        const auto& a=group.second[0];const auto& b=group.second[1];pairs[group.first]=a.value?std::make_pair(b,a):std::make_pair(a,b);}
    require(pairs.size()==2,"Missing/ambiguous paired kernel boolean controls");
    struct GateRead {uint64_t pc,exit;Location flag;};std::vector<GateRead> reads;
    for(const auto& entry:module.textRelocations()){
        Location flag{entry.second.section,entry.second.offset};if(!pairs.count(flag))continue;
        const auto& ins=module.instruction(entry.first);if(!named(ins,"ldrb"))continue;
        const auto& compare=module.instruction(entry.first+4);const auto& skip=module.instruction(entry.first+8);
        if(named(compare,"cmp")&&reg(module,compare,0)==reg(module,ins,0)&&operand(compare,1).type==ARM64_OP_IMM
                &&imm(compare,1)==1&&named(skip,"b.ne"))reads.push_back({entry.first,codeAddress(imm(skip,0)),flag});
    }
    std::vector<std::pair<GateRead,GateRead>> gates;
    for(const auto& a:reads)for(const auto& b:reads)if(a.pc<b.pc&&b.pc-a.pc<=32&&a.flag!=b.flag&&a.exit==b.exit)gates.push_back({a,b});
    require(gates.size()==1,"No unique shared kernel skip gate");KernelControlPlan plan;plan.buildIdNote=module.buildIdNote();
    for(const auto& read:{gates[0].first,gates[0].second}){const auto& pair=pairs.at(read.flag);plan.controls.push_back({pair.first,pair.second,read.pc,read.exit});}
    return plan;
}
}
