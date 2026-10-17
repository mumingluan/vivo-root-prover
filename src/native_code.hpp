#pragma once
#include "native_layout.hpp"
#include <capstone/capstone.h>
#include <array>
#include <deque>
#include <memory>
#include <optional>

namespace vrp {
// Native executable provenance uses ELF virtual addresses; no firmware code PCs.
class NativeCode {
    struct Decoded {cs_insn* value;explicit Decoded(cs_insn* p):value(p){}~Decoded(){cs_free(value,1);}};
    csh decoder=0;mutable std::map<uint64_t,std::unique_ptr<Decoded>> cache;
public:
    const NativeElf& elf;
    explicit NativeCode(const NativeElf& source):elf(source){require(cs_open(CS_ARCH_ARM64,CS_MODE_ARM,&decoder)==CS_ERR_OK,"Native AArch64 decoder unavailable");require(cs_option(decoder,CS_OPT_DETAIL,CS_OPT_ON)==CS_ERR_OK,"Native decoder detail unavailable");}
    ~NativeCode(){cache.clear();cs_close(&decoder);}
    NativeCode(const NativeCode&)=delete;NativeCode& operator=(const NativeCode&)=delete;
    const cs_insn& instruction(uint64_t pc)const {
        auto old=cache.find(pc);if(old!=cache.end())return *old->second->value;
        auto offset=elf.fileOffset(pc);cs_insn* value=nullptr;size_t count=cs_disasm(decoder,elf.bytes.data()+offset,4,pc,1,&value);
        require(count==1&&value&&value->detail,"Unknown native instruction");cache.emplace(pc,std::make_unique<Decoded>(value));return *value;
    }
    int regIndex(unsigned value)const {
        std::string name=regName(value);if(name=="wzr"||name=="xzr")return 31;if(name=="sp"||name=="wsp")return 32;if(name=="fp")return 29;if(name=="lr")return 30;
        if(name.size()<2||(name[0]!='w'&&name[0]!='x'))return -1;
        unsigned index=0;for(size_t i=1;i<name.size();++i){if(name[i]<'0'||name[i]>'9')return -1;index=index*10+unsigned(name[i]-'0');}return index<=30?int(index):-1;
    }
    std::string regName(unsigned value)const {const char* name=cs_reg_name(decoder,value);return name?name:"";}
    const cs_arm64_op& operand(const cs_insn& ins,unsigned index)const {require(index<ins.detail->arm64.op_count,"Missing native operand");return ins.detail->arm64.operands[index];}
    int reg(const cs_insn& ins,unsigned index)const {const auto& op=operand(ins,index);require(op.type==ARM64_OP_REG,"Native operand is not a register");int r=regIndex(op.reg);require(r>=0,"Native operand is not a scalar register");return r;}
    unsigned width(unsigned value)const {auto name=regName(value);return !name.empty()&&name[0]=='w'?4:regIndex(value)>=0?8:0;}
    std::set<int> writes(const cs_insn& ins)const {
        cs_regs read{},written{};uint8_t readCount=0,count=0;require(cs_regs_access(decoder,&ins,read,&readCount,written,&count)==CS_ERR_OK,"Missing native register effects");
        std::set<int> result;for(unsigned i=0;i<count;i++){int index=regIndex(written[i]);if(index>=0&&index!=31)result.insert(index);}return result;
    }
    std::optional<uint64_t> callTarget(const cs_insn& ins)const {if(std::string(ins.mnemonic)!="bl"||operand(ins,0).type!=ARM64_OP_IMM)return {};return uint64_t(operand(ins,0).imm);}
    std::string callName(const cs_insn& ins)const {auto target=callTarget(ins);if(!target)return "";auto found=elf.calls.find(*target);return found==elf.calls.end()?"":found->second;}
    std::pair<uint64_t,uint64_t> function(uint64_t pc)const {
        const auto& text=elf.section(".text");require(pc>=text.address&&pc<text.address+text.size&&pc%4==0,"Native PC outside text");
        uint64_t start=pc;while(elf.instruction(start)!=0xd503233fu){require(start>=text.address+4&&pc-start<16384,"Native function entry unavailable");start-=4;}
        uint64_t end=start+4;while(end<text.address+text.size&&elf.instruction(end)!=0xd503233fu){require(end-start<16384,"Native function exceeds bound");end+=4;}
        require(end>pc,"Native function boundary does not contain PC");return {start,end};
    }
};
struct NativeValue {
    enum Kind {Unknown,Constant,Stack,ProcFile,NvResult,ProcBytes,NvField};
    Kind kind=Unknown;uint64_t value=0,origin=0;uint32_t width=0;
    bool operator==(const NativeValue& b)const{return kind==b.kind&&value==b.value&&origin==b.origin&&width==b.width;}
    bool operator!=(const NativeValue& b)const{return !(*this==b);}
    static NativeValue constant(uint64_t value){return {Constant,value,0,0};}
    static NativeValue stack(int64_t value){return {Stack,uint64_t(value),0,0};}
};
struct NativeMemorySource {NativeValue::Kind kind;int64_t start;uint32_t bytes;uint64_t callPc;};
// Must-analysis over every normal CFG edge. Unknown/conflicting definitions do
// not become values simply because their last textual assignment looks right.
class NativeFlow {
public:
    using State=std::array<NativeValue,33>;
    const NativeCode& code;uint64_t begin,end;
    std::map<uint64_t,std::vector<uint64_t>> edges;
    std::map<uint64_t,State> states;
    std::vector<NativeMemorySource> memory;
    NativeFlow(const NativeCode& source,uint64_t start,uint64_t finish,const std::vector<NativeMemorySource>& regions={}):code(source),begin(start),end(finish),memory(regions) {
        require(begin%4==0&&end%4==0&&end>begin&&end-begin<=16384,"Unbounded native flow");
        for(uint64_t pc=begin;pc<end;pc+=4)edges[pc]=successors(pc);
        State initial{};initial[31]=NativeValue::constant(0);initial[32]=NativeValue::stack(0);std::deque<uint64_t> queue;merge(begin,initial,queue);
        size_t iterations=0;
        while(!queue.empty()){require(++iterations<=(end-begin)*32,"Native dataflow does not converge");auto pc=queue.front();queue.pop_front();auto after=transfer(pc,states.at(pc));for(auto next:edges.at(pc))merge(next,after,queue);}
    }
    const State& before(uint64_t pc)const {auto found=states.find(pc);require(found!=states.end(),"Native instruction is unreachable");return found->second;}
    NativeValue value(uint64_t pc,int reg)const {require(reg>=0&&reg<=32,"Native register outside state");return before(pc)[size_t(reg)];}
    bool edgeDominates(uint64_t from,uint64_t to,uint64_t target)const {return unreachableAvoiding(target,std::make_pair(from,to),{});}
    bool dominates(uint64_t anchor,uint64_t target)const {if(anchor==target)return states.count(anchor)!=0;return unreachableAvoiding(target,{},anchor);}
    NativeValue address(uint64_t pc,const cs_arm64_op& memoryOperand)const {
        if(memoryOperand.type!=ARM64_OP_MEM||memoryOperand.mem.index!=ARM64_REG_INVALID)return {};
        int base=code.regIndex(memoryOperand.mem.base);if(base<0)return {};auto result=value(pc,base);
        if(result.kind==NativeValue::Stack||result.kind==NativeValue::Constant)result.value+=uint64_t(int64_t(memoryOperand.mem.disp));else return {};
        return result;
    }
private:
    bool unreachableAvoiding(uint64_t target,std::optional<std::pair<uint64_t,uint64_t>> skipped,std::optional<uint64_t> node)const {
        require(states.count(target),"Dominance target unreachable");std::set<uint64_t> seen;std::deque<uint64_t> queue{begin};
        while(!queue.empty()){auto pc=queue.front();queue.pop_front();if(node&&pc==*node)continue;if(!seen.insert(pc).second)continue;if(pc==target)return false;
            for(auto next:edges.at(pc))if(!skipped||skipped->first!=pc||skipped->second!=next)queue.push_back(next);}
        return true;
    }
    std::vector<uint64_t> successors(uint64_t pc)const {
        const auto& ins=code.instruction(pc);std::string name=ins.mnemonic;std::vector<uint64_t> result;
        if(name=="ret"||name=="br"||code.callName(ins)=="__stack_chk_fail")return result;
        if(name=="b")result.push_back(uint64_t(code.operand(ins,0).imm));
        else {
            if(pc+4<end)result.push_back(pc+4);
            if(name.rfind("b.",0)==0)result.push_back(uint64_t(code.operand(ins,0).imm));
            else if(name=="cbz"||name=="cbnz")result.push_back(uint64_t(code.operand(ins,1).imm));
            else if(name=="tbz"||name=="tbnz")result.push_back(uint64_t(code.operand(ins,2).imm));
        }
        for(auto target:result)require(target>=begin&&target<end&&target%4==0,"Native branch leaves recognized function");
        return result;
    }
    void merge(uint64_t pc,const State& incoming,std::deque<uint64_t>& queue) {
        auto old=states.find(pc);if(old==states.end()){states.emplace(pc,incoming);queue.push_back(pc);return;}
        bool changed=false;for(size_t i=0;i<old->second.size();i++)if(old->second[i].kind!=NativeValue::Unknown&&old->second[i]!=incoming[i]){old->second[i]={};changed=true;}
        if(changed)queue.push_back(pc);
    }
    State transfer(uint64_t pc,const State& before)const {
        const auto& ins=code.instruction(pc);const auto& detail=ins.detail->arm64;std::string name=ins.mnemonic;State after=before;
        for(int r:code.writes(ins))after[size_t(r)]={};
        auto set=[&](int reg,NativeValue value){require(reg>=0&&reg<=32,"Native write register invalid");if(reg==31)return;after[size_t(reg)]=value;};
        auto operandValue=[&](unsigned index)->NativeValue {const auto& op=code.operand(ins,index);if(op.type==ARM64_OP_IMM)return NativeValue::constant(uint64_t(op.imm));if(op.type==ARM64_OP_REG){int r=code.regIndex(op.reg);if(r>=0)return before[size_t(r)];}return {};};
        if(name=="mov"&&detail.op_count==2){auto v=operandValue(1);if(v.kind==NativeValue::Constant&&code.width(code.operand(ins,0).reg)==4)v.value&=0xffffffffu;set(code.reg(ins,0),v);}
        else if(name=="movk") {
            int r=code.reg(ins,0);auto v=before[size_t(r)];auto op=code.operand(ins,1);require(op.type==ARM64_OP_IMM&&op.shift.value<=48,"Invalid native MOVK");
            if(v.kind==NativeValue::Constant){v.value=(v.value&~(uint64_t(65535)<<op.shift.value))|((uint64_t(op.imm)&65535)<<op.shift.value);if(code.width(code.operand(ins,0).reg)==4)v.value&=0xffffffffu;}else v={};set(r,v);
        } else if(name=="adr"||name=="adrp")set(code.reg(ins,0),operandValue(1));
        else if((name=="add"||name=="sub")&&detail.op_count==3) {
            auto base=operandValue(1),delta=operandValue(2);const auto& op=code.operand(ins,2);
            if((base.kind==NativeValue::Stack||base.kind==NativeValue::Constant)&&delta.kind==NativeValue::Constant&&op.shift.value<=12) {
                uint64_t amount=delta.value<<op.shift.value;base.value+=name=="add"?amount:uint64_t(0)-amount;set(code.reg(ins,0),base);
            }
        } else if((name=="ldr"||name=="ldur")&&detail.op_count>=2&&code.regIndex(code.operand(ins,0).reg)>=0) {
            const auto& op=code.operand(ins,1);auto pointer=address(pc,op);uint32_t width=code.width(code.operand(ins,0).reg);NativeValue result;
            if(pointer.kind==NativeValue::Stack)for(const auto& source:memory) {
                int64_t relative=int64_t(pointer.value)-source.start;
                if(relative>=0&&uint64_t(relative)+width<=source.bytes&&dominates(source.callPc,pc)) {
                    require(result.kind==NativeValue::Unknown,"Ambiguous native buffer load");result={source.kind,uint64_t(relative),source.callPc,width};
                }
            }
            set(code.reg(ins,0),result);
        }
        if(detail.writeback) {
            const cs_arm64_op* mem=nullptr;for(unsigned i=0;i<detail.op_count;i++)if(detail.operands[i].type==ARM64_OP_MEM)mem=&detail.operands[i];
            require(mem,"Writeback instruction lacks memory operand");int base=code.regIndex(mem->mem.base);require(base>=0,"Unsupported native writeback register");auto old=before[size_t(base)];
            int64_t delta=mem->mem.disp;if(detail.post_index){const auto& op=detail.operands[detail.op_count-1];require(op.type==ARM64_OP_IMM,"Unknown post-index displacement");delta=op.imm;}
            if(old.kind==NativeValue::Stack||old.kind==NativeValue::Constant){old.value+=uint64_t(delta);set(base,old);}
        }
        if(name=="bl"||name=="blr") {
            for(unsigned r=0;r<=18;r++)after[r]={};
            after[30]={};auto called=code.callName(ins);
            if((called=="__open_2"||called=="open")&&before[0].kind==NativeValue::Constant&&before[1]==NativeValue::constant(0))after[0]={NativeValue::ProcFile,before[0].value,0,0};
            else if(called=="get_IQOO_NV_item")after[0]={NativeValue::NvResult,0,pc,0};
        }
        after[31]=NativeValue::constant(0);return after;
    }
};
} // namespace vrp
