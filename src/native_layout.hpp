#pragma once
#include "core.hpp"
#include <map>
#include <set>
#include <utility>

namespace vrp {
struct NvDiscovery { NvLayout layout;uint64_t writerPc=0,digestPc=0,writePc=0; };

// ELF/DEX/header offsets describe their published file formats. No firmware
// address or whole-file fingerprint is used to locate the NV implementation.
class NativeElf {
public:
    struct Section { uint32_t type=0,link=0;uint64_t flags=0,address=0,offset=0,size=0,entrySize=0;std::string name; };
    struct Symbol { uint64_t address=0,size=0;uint16_t section=0;uint8_t type=0;std::string name; };
    const Bytes& bytes;
    std::vector<Section> sections;
    std::vector<Symbol> dynamicSymbols;
    std::map<uint64_t,std::string> calls;
    explicit NativeElf(const Bytes& input):bytes(input) {
        require(bytes.size()>=64&&std::memcmp(bytes.data(),"\x7f" "ELF",4)==0&&bytes[4]==2&&bytes[5]==1,"unsupported ELF identity");
        require(u16(18)==183,"native image is not AArch64");
        uint64_t at=u64(40);uint16_t stride=u16(58),count=u16(60),names=u16(62);
        require(stride>=64&&count>0&&names<count,"ELF section table invalid");range(at,uint64_t(stride)*count);
        for(unsigned i=0;i<count;++i){uint64_t p=at+uint64_t(i)*stride;Section s;
            s.type=u32(p+4);s.flags=u64(p+8);s.address=u64(p+16);s.offset=u64(p+24);s.size=u64(p+32);s.link=u32(p+40);s.entrySize=u64(p+56);
            if(s.type!=8)range(s.offset,s.size);
            sections.push_back(s);}
        const auto strings=sections[names];require(strings.type==3,"ELF section names are not a string table");range(strings.offset,strings.size);
        for(unsigned i=0;i<count;++i)sections[i].name=string(strings,u32(at+uint64_t(i)*stride));
        const auto& symbols=section(".dynsym");require(symbols.type==11&&symbols.entrySize>=24&&symbols.size%symbols.entrySize==0&&symbols.link<sections.size(),"ELF dynamic symbols invalid");
        const auto& namesSection=sections[symbols.link];require(namesSection.type==3,"ELF symbol names are not a string table");
        for(uint64_t p=symbols.offset;p<symbols.offset+symbols.size;p+=symbols.entrySize){Symbol s;
            s.name=string(namesSection,u32(p));s.type=bytes[size_t(p+4)]&15;s.section=u16(p+6);s.address=u64(p+8);s.size=u64(p+16);dynamicSymbols.push_back(s);
            if(s.section&&s.type==2&&s.address)calls[s.address]=s.name;}
        const auto& relocations=section(".rela.plt");const auto& plt=section(".plt");
        require(relocations.type==4&&relocations.entrySize>=24&&relocations.size%relocations.entrySize==0,"ELF PLT relocations invalid");
        uint64_t entries=relocations.size/relocations.entrySize;require(entries&&plt.size>=32&&(plt.size-32)%entries==0,"ELF PLT layout invalid");
        uint64_t entry=(plt.size-32)/entries;require(entry==16||entry==24,"unsupported AArch64 PLT stride");
        for(uint64_t i=0;i<entries;++i){uint64_t symbolIndex=u64(relocations.offset+i*relocations.entrySize+8)>>32;
            require(symbolIndex<dynamicSymbols.size(),"ELF PLT symbol out of bounds");calls[plt.address+32+i*entry]=dynamicSymbols[size_t(symbolIndex)].name;}
    }
    void range(uint64_t offset,uint64_t length)const { require(offset<=bytes.size()&&length<=bytes.size()-offset,"ELF file range out of bounds"); }
    uint16_t u16(uint64_t offset)const {range(offset,2);return uint16_t(bytes[size_t(offset)])|uint16_t(bytes[size_t(offset+1)])<<8;}
    uint32_t u32(uint64_t offset)const {range(offset,4);return le32(bytes.data()+offset);}
    uint64_t u64(uint64_t offset)const {range(offset,8);return uint64_t(u32(offset))|uint64_t(u32(offset+4))<<32;}
    std::string string(const Section& strings,uint64_t offset)const {
        require(offset<strings.size,"ELF string offset invalid");uint64_t start=strings.offset+offset,end=start;
        while(end<strings.offset+strings.size&&bytes[size_t(end)])++end;
        require(end<strings.offset+strings.size,"ELF string unterminated");return std::string(bytes.begin()+start,bytes.begin()+end);
    }
    const Section& section(const std::string& name)const {
        const Section* found=nullptr;for(const auto& s:sections)if(s.name==name){require(!found,"duplicate ELF section");found=&s;}
        require(found,"missing ELF section: "+name);return *found;
    }
    Symbol symbol(const std::string& name)const {
        const Symbol* found=nullptr;for(const auto& s:dynamicSymbols)if(s.section&&s.name==name){require(!found,"ambiguous native ABI symbol: "+name);found=&s;}
        require(found,"missing native ABI symbol: "+name);return *found;
    }
    uint64_t fileOffset(uint64_t address,uint64_t length=4)const {
        for(const auto& s:sections)if(s.type!=8&&(s.flags&2)&&address>=s.address&&address-s.address<=s.size&&length<=s.size-(address-s.address))return s.offset+address-s.address;
        throw std::runtime_error("native virtual address outside file-backed sections");
    }
    uint32_t instruction(uint64_t address)const {return u32(fileOffset(address));}
    bool call(uint64_t pc,const std::string& name)const {
        uint32_t word=instruction(pc);if((word&0xfc000000u)!=0x94000000u)return false;
        int64_t immediate=word&0x3ffffffu;if(immediate&(1<<25))immediate-=int64_t(1)<<26;
        auto found=calls.find(uint64_t(int64_t(pc)+immediate*4));return found!=calls.end()&&found->second==name;
    }
    bool directCall(uint64_t pc,uint64_t target)const {
        uint32_t word=instruction(pc);if((word&0xfc000000u)!=0x94000000u)return false;
        int64_t immediate=word&0x3ffffffu;if(immediate&(1<<25))immediate-=int64_t(1)<<26;
        return uint64_t(int64_t(pc)+immediate*4)==target;
    }
};
inline bool a64_mov_immediate(uint32_t word,unsigned destination,uint32_t& result) {
    if((word&0xff80001fu)!=(0x52800000u|destination))return false;
    unsigned shift=((word>>21)&3)*16;if(shift>=32)return false;result=((word>>5)&65535u)<<shift;return true;
}
inline bool a64_mov_register(uint32_t word,unsigned destination,unsigned& source) {
    if((word&0xffe0ffffu)!=(0xaa0003e0u|destination))return false;
    source=(word>>16)&31;return true;
}
inline bool a64_add_immediate(uint32_t word,unsigned& destination,unsigned& source,uint32_t& value) {
    if((word&0xff000000u)!=0x91000000u)return false;
    destination=word&31;source=(word>>5)&31;
    value=((word>>10)&4095u)<<((word&(1<<22))?12:0);return true;
}
inline bool references_backup_partition(const NativeElf& elf,uint64_t entry) {
    const auto& text=elf.section(".text");std::map<unsigned,uint64_t> registers;
    for(uint64_t pc=entry;pc+4<=text.address+text.size&&pc<entry+65536;pc+=4) {
        uint32_t word=elf.instruction(pc);if(pc!=entry&&word==0xd503233fu)break;
        if((word&0x1f000000u)==0x10000000u) {
            int64_t immediate=((word>>5)&0x7ffffu)*4+((word>>29)&3);if(immediate&(1<<20))immediate-=int64_t(1)<<21;
            registers[word&31]=(word&0x80000000u)?uint64_t(int64_t(pc&~uint64_t(4095))+immediate*4096):uint64_t(int64_t(pc)+immediate);
        } else {
            unsigned destination,source;uint32_t immediate;
            if(a64_add_immediate(word,destination,source,immediate)) {
                auto found=registers.find(source);if(found!=registers.end())registers[destination]=found->second+immediate;
            }
        }
        for(const auto& value:registers)for(const char* path:{"/dev/block/by-name/backup","/dev/block/bootdevice/by-name/backup","/dev/block/platform/bootdevice/by-name/backup"}) {
            try {auto offset=elf.fileOffset(value.second,std::strlen(path)+1);
                if(std::memcmp(elf.bytes.data()+offset,path,std::strlen(path)+1)==0)return true;
            }catch(const std::exception&) { }
        }
    }
    return false;
}
inline NvDiscovery discover_factory_layout(const Bytes& data) {
    NativeElf elf(data);const auto& text=elf.section(".text");auto lookup=elf.symbol("get_IQOO_NV_by_name"),table=elf.symbol("backup_offset_table"),put=elf.symbol("put_IQOO_NV_item");
    require(lookup.size&&lookup.size<=65536&&put.size&&put.size<=65536,"unbounded native NV API");
    (void)elf.fileOffset(lookup.address,lookup.size);(void)elf.fileOffset(put.address,put.size);
    std::set<uint32_t> strides;
    for(uint64_t pc=lookup.address;pc+4<=lookup.address+lookup.size;pc+=4){unsigned destination,source;uint32_t value;
        if(a64_add_immediate(elf.instruction(pc),destination,source,value)&&destination==source&&destination!=31&&value>12&&value<512&&table.size%value==0)strides.insert(value);}
    require(strides.size()==1,"missing/ambiguous NV descriptor stride");uint32_t stride=*strides.begin(),nameBytes=stride-12;
    require(nameBytes>=8&&nameBytes<=256&&table.size>=stride&&table.size<=2*1024*1024,"NV descriptor table bounds invalid");
    uint64_t tableOffset=elf.fileOffset(table.address,table.size);std::vector<uint32_t> roots;
    for(uint64_t at=tableOffset;at<tableOffset+table.size;at+=stride) {
        if(std::memcmp(data.data()+at,"is_root\0",8))continue;
        require(std::all_of(data.begin()+at+7,data.begin()+at+nameBytes,[](uint8_t b){return b==0;}),"NV root name padding invalid");
        require(elf.u32(at+nameBytes+4)==2&&elf.u32(at+nameBytes+8)==1,"unknown NV root scalar ABI");roots.push_back(elf.u32(at+nameBytes));
    }
    require(roots.size()==1,"missing/ambiguous named NV root field");std::vector<NvDiscovery> candidates;
    for(uint64_t pc=text.address+8;pc+4<=text.address+text.size;pc+=4) {
        if(!elf.call(pc,"MD5_Update"))continue;
        uint32_t covered;unsigned buffer;
        if(!a64_mov_immediate(elf.instruction(pc-4),2,covered)||!a64_mov_register(elf.instruction(pc-8),1,buffer))continue;
        for(uint64_t finish=pc+4;finish<pc+48&&finish+4<=text.address+text.size;finish+=4) {
            if(!elf.call(finish,"MD5_Final"))continue;
            unsigned destination,source;uint32_t offset;
            if(!a64_add_immediate(elf.instruction(finish-8),destination,source,offset)||destination!=0||source!=buffer||offset!=covered)continue;
            uint64_t write=0,seek=0;
            for(uint64_t next=finish+4;next<finish+128&&next+4<=text.address+text.size;next+=4)if(elf.call(next,"write")){write=next;break;}
            uint32_t size;if(!write||!a64_mov_immediate(elf.instruction(write-4),2,size)||size<512||size>8192||size%512)continue;
            for(uint64_t previous=write-4;previous>finish;previous-=4)if(elf.call(previous,"lseek")){seek=previous;break;}
            if(!seek||seek<text.address+12)continue;
            uint32_t shiftWord=elf.instruction(seek-12);unsigned immr=(shiftWord>>16)&63,imms=(shiftWord>>10)&63;
            if((shiftWord&0xff80001fu)!=0x53000001u||imms+1!=immr||immr>=32)continue;
            unsigned shift=32-immr;if(shift<9||shift>20)continue;
            require(roots[0]%4==0&&roots[0]<=covered&&covered-roots[0]>=4&&covered<=size&&size-covered>=16,"NV layout fields exceed record");
            uint64_t entry=pc;while(entry>=text.address&&elf.instruction(entry)!=0xd503233fu){if(entry==text.address)break;entry-=4;}
            require(elf.instruction(entry)==0xd503233fu,"NV writer entry not recognized");bool reached=false;
            for(uint64_t parent=put.address;parent+4<=put.address+put.size;parent+=4)if(elf.directCall(parent,entry))reached=true;
            require(reached,"NV writer not reached by exported API");
            require(references_backup_partition(elf,entry),"NV writer does not reference the backup partition");
            candidates.push_back({{size,roots[0],covered,uint32_t(1u<<shift)},entry,pc,write});
        }
    }
    require(candidates.size()==1,"missing/ambiguous native NV write layout");return candidates[0];
}
} // namespace vrp
