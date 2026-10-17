#pragma once
#include "core.hpp"
#include <capstone/capstone.h>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string_view>

namespace vrp {
struct KernelSection {
    uint32_t type=0,link=0,info=0;
    uint64_t flags=0,offset=0,size=0,stride=0;
    std::string name;
};
struct KernelRelocation {
    unsigned section=0,type=0;
    uint64_t offset=0;
};
class KernelModule {
    struct Decoded {
        cs_insn* value=nullptr;
        explicit Decoded(cs_insn* instruction):value(instruction){}
        ~Decoded(){if(value)cs_free(value,1);}
    };
    struct Symbol {std::string name;unsigned section;uint64_t value;};
    csh decoder=0;
    unsigned textIndex=0;
    mutable std::map<uint64_t,std::unique_ptr<Decoded>> cache;
    mutable std::set<uint64_t> invalid;
    using Location=std::pair<unsigned,uint64_t>;
    std::map<Location,KernelRelocation> relocations;
    std::map<Location,std::pair<std::string,unsigned>> externals;
    std::string stringAt(const KernelSection& table,uint32_t index)const {
        require(table.type==3 && index<table.size,"Kernel ELF string-table index invalid");
        uint64_t end=index;while(end<table.size && data[size_t(table.offset+end)])++end;
        require(end<table.size,"Unterminated kernel ELF string");
        return std::string(data.begin()+table.offset+index,data.begin()+table.offset+end);
    }
    void parse() {
        require(data.size()>=64 && data[0]==0x7f && data[1]=='E' && data[2]=='L' && data[3]=='F'
                && data[4]==2 && data[5]==1 && data[6]==1 && u16(16)==1 && u16(18)==183 && u32(20)==1,
                "Not a little-endian AArch64 relocatable kernel module");
        uint64_t base=u64(40);unsigned stride=u16(58),count=u16(60),names=u16(62);
        require(stride>=64 && stride<=256 && count>0 && count<=4096 && names<count,"Kernel section table invalid");
        range(base,uint64_t(stride)*count);
        for(unsigned i=0;i<count;++i){uint64_t p=base+uint64_t(i)*stride;KernelSection section;
            section.type=u32(p+4);section.flags=u64(p+8);section.offset=u64(p+24);section.size=u64(p+32);
            section.link=u32(p+40);section.info=u32(p+44);section.stride=u64(p+56);
            if(section.type!=8)range(section.offset,section.size);
            sections.push_back(section);
        }
        const auto namesSection=sections[names];
        for(unsigned i=0;i<count;++i)sections[i].name=stringAt(namesSection,u32(base+uint64_t(i)*stride));
        textIndex=sectionIndex(".text");const auto& text=sections[textIndex];
        require(text.type==1 && (text.flags&6)==6 && text.size>0 && text.size<=4*1024*1024 && text.size%4==0,"Kernel text section invalid");
        unsigned symbolIndex=sectionIndex(".symtab");const auto& symbols=sections[symbolIndex];
        require(symbols.type==2 && symbols.stride>=24 && symbols.stride<=256 && symbols.size%symbols.stride==0
                && symbols.link<sections.size() && symbols.size/symbols.stride<=1048576,"Kernel symbol table invalid");
        std::vector<Symbol> entries;const auto& strings=sections[symbols.link];
        for(uint64_t p=symbols.offset;p<symbols.offset+symbols.size;p+=symbols.stride)
            entries.push_back({stringAt(strings,u32(p)),u16(p+6),u64(p+8)});
        for(const auto& section:sections)if(section.type==4){
            require(section.link==symbolIndex && section.info<sections.size() && section.stride>=24 && section.stride<=256
                    && section.size%section.stride==0,"Kernel relocation table invalid");
            for(uint64_t p=section.offset;p<section.offset+section.size;p+=section.stride){
                uint64_t at=u64(p),info=u64(p+8);unsigned type=unsigned(info&0xffffffffu);uint64_t index=info>>32;
                require(index<entries.size() && at<sections[section.info].size,"Kernel relocation index/range invalid");
                Location key{section.info,at};const auto& symbol=entries[size_t(index)];
                if(symbol.section==0){require(!externals.count(key),"Duplicate kernel external relocation");externals[key]={symbol.name,type};continue;}
                if(symbol.section>=sections.size())continue;
                int64_t addend=int64_t(u64(p+16));uint64_t value;
                if(addend>=0){require(uint64_t(addend)<=UINT64_MAX-symbol.value,"Kernel relocation overflow");value=symbol.value+uint64_t(addend);}
                else {uint64_t magnitude=uint64_t(-(addend+1))+1;require(magnitude<=symbol.value,"Kernel relocation underflow");value=symbol.value-magnitude;}
                require(value<=sections[symbol.section].size && !relocations.count(key),"Kernel relocation target invalid/ambiguous");
                relocations[key]={symbol.section,type,value};
            }
        }
    }
public:
    Bytes data;
    std::vector<KernelSection> sections;
    explicit KernelModule(Bytes source):data(std::move(source)) {
        require(data.size()<=32*1024*1024,"Kernel module file too large");parse();
        require(cs_open(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN,&decoder)==CS_ERR_OK,"AArch64 decoder unavailable");
        if(cs_option(decoder,CS_OPT_DETAIL,CS_OPT_ON)!=CS_ERR_OK){cs_close(&decoder);throw std::runtime_error("AArch64 instruction detail unavailable");}
    }
    ~KernelModule(){if(decoder)cs_close(&decoder);}
    KernelModule(const KernelModule&)=delete;KernelModule& operator=(const KernelModule&)=delete;
    void range(uint64_t offset,uint64_t length)const {require(offset<=data.size() && length<=data.size()-offset,"Kernel ELF range invalid");}
    uint16_t u16(uint64_t at)const{range(at,2);return uint16_t(data[size_t(at)])|uint16_t(data[size_t(at+1)])<<8;}
    uint32_t u32(uint64_t at)const{range(at,4);return le32(data.data()+at);}
    uint64_t u64(uint64_t at)const{return uint64_t(u32(at))|uint64_t(u32(at+4))<<32;}
    unsigned sectionIndex(const std::string& name)const {
        std::optional<unsigned> found;for(unsigned i=0;i<sections.size();++i)if(sections[i].name==name){require(!found,"Duplicate kernel ELF section");found=i;}
        require(found.has_value(),"Missing kernel ELF section: "+name);return *found;
    }
    Bytes sectionBytes(unsigned index)const {
        require(index<sections.size() && sections[index].type!=8,"Kernel section is not file-backed");const auto& s=sections[index];
        return Bytes(data.begin()+s.offset,data.begin()+s.offset+s.size);
    }
    const cs_insn* tryInstruction(uint64_t pc)const {
        const auto& text=sections[textIndex];if(pc%4 || pc>text.size || text.size-pc<4 || invalid.count(pc))return nullptr;
        auto found=cache.find(pc);if(found!=cache.end())return found->second->value;
        cs_insn* instruction=nullptr;size_t count=cs_disasm(decoder,data.data()+text.offset+pc,4,pc,1,&instruction);
        if(count!=1 || !instruction || !instruction->detail){if(instruction)cs_free(instruction,count);invalid.insert(pc);return nullptr;}
        auto result=instruction;cache.emplace(pc,std::make_unique<Decoded>(instruction));return result;
    }
    const cs_insn& instruction(uint64_t pc)const {auto value=tryInstruction(pc);require(value,"Unknown/out-of-range AArch64 kernel instruction");return *value;}
    uint64_t textSize()const{return sections[textIndex].size;}
    uint64_t textFileOffset()const{return sections[textIndex].offset;}
    std::optional<KernelRelocation> relocation(uint64_t pc)const {auto found=relocations.find({textIndex,pc});if(found==relocations.end())return {};return found->second;}
    std::vector<std::pair<uint64_t,KernelRelocation>> textRelocations()const {
        std::vector<std::pair<uint64_t,KernelRelocation>> result;
        for(const auto& entry:relocations)if(entry.first.first==textIndex)result.push_back({entry.first.second,entry.second});
        return result;
    }
    bool externalCall(uint64_t pc,const std::string& name)const {
        auto found=externals.find({textIndex,pc});return found!=externals.end() && found->second.first==name && found->second.second==283;
    }
    bool hasExternal(uint64_t pc)const{return externals.count({textIndex,pc})!=0;}
    int registerIndex(unsigned value)const {
        const char* raw=cs_reg_name(decoder,value);if(!raw)return -1;std::string name(raw);
        if(name=="wzr"||name=="xzr")return 31;
        if(name=="sp"||name=="wsp")return 32;
        if(name=="fp")return 29;
        if(name=="lr")return 30;
        if(name.size()>=2 && (name[0]=='w'||name[0]=='x')){
            unsigned number=0;for(size_t i=1;i<name.size();++i){if(name[i]<'0'||name[i]>'9')return -1;number=number*10+unsigned(name[i]-'0');}
            if(number<=30)return int(number);
        }return -1;
    }
    std::string registerName(unsigned value)const {const char* name=cs_reg_name(decoder,value);return name?name:"";}
    std::set<int> writes(const cs_insn& instruction)const {
        cs_regs read{},written{};uint8_t reads=0,count=0;require(cs_regs_access(decoder,&instruction,read,&reads,written,&count)==CS_ERR_OK,"No AArch64 register effects");
        std::set<int> result;for(unsigned i=0;i<count;++i){int reg=registerIndex(written[i]);if(reg>=0)result.insert(reg);}return result;
    }
    Bytes buildIdNote()const {
        auto value=sectionBytes(sectionIndex(".note.gnu.build-id"));require(value.size()>=16,"GNU build-id note truncated");
        uint32_t name=le32(value.data()),length=le32(value.data()+4),type=le32(value.data()+8);
        require(name==4 && type==3 && std::memcmp(value.data()+12,"GNU\0",4)==0 && length>=16 && length<=64
                && 16+length<=value.size() && std::all_of(value.begin()+16+length,value.end(),[](uint8_t byte){return byte==0;}),"GNU build-id note invalid");return value;
    }
};
inline bool named(const cs_insn& instruction,std::string_view name){return name==instruction.mnemonic;}
inline const cs_arm64_op& operand(const cs_insn& instruction,unsigned index){require(instruction.detail && index<instruction.detail->arm64.op_count,"Missing AArch64 operand");return instruction.detail->arm64.operands[index];}
inline int reg(const KernelModule& module,const cs_insn& instruction,unsigned index){const auto& value=operand(instruction,index);require(value.type==ARM64_OP_REG,"Expected AArch64 register");int result=module.registerIndex(value.reg);require(result>=0,"Expected general-purpose AArch64 register");return result;}
inline int64_t imm(const cs_insn& instruction,unsigned index){const auto& value=operand(instruction,index);require(value.type==ARM64_OP_IMM,"Expected AArch64 immediate");return value.imm;}
}
