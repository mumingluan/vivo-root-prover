#include "../src/native_layout.hpp"
#include <fstream>
#include <iostream>
using namespace vrp;
template<class Action>void rejects(Action action) {bool failed=false;try{action();}catch(const std::exception&){failed=true;}require(failed,"invalid native layout was accepted");}
int main(int argc,char** argv) {try{
    require(argc==2,"provide factory library fixture");std::ifstream file(argv[1],std::ios::binary);require(bool(file),"fixture missing");Bytes data(std::istreambuf_iterator<char>(file),{});
    auto plan=discover_factory_layout(data);NativeElf elf(data);
    auto missing=data;bool replaced=false;for(size_t i=0;i+8<missing.size();++i)if(std::memcmp(missing.data()+i,"is_root\0",8)==0){missing[i]='X';replaced=true;}
    require(replaced,"fixture lacks named root field");rejects([&]{discover_factory_layout(missing);});
    rejects([&]{discover_factory_layout(Bytes(data.begin(),data.begin()+60));});
    auto corrupt=data;corrupt[18]=0;rejects([&]{discover_factory_layout(corrupt);});
    auto digestChanged=data;size_t at=elf.fileOffset(plan.digestPc-4);uint32_t word=le32(digestChanged.data()+at);word^=(1u<<5);put32(digestChanged.data()+at,word);
    rejects([&]{discover_factory_layout(digestChanged);});
    std::cout<<"PASS native NV table/code discovery: bytes="<<plan.layout.recordBytes<<" root="<<plan.layout.rootOffset<<" digest="<<plan.layout.digestOffset<<" stride="<<plan.layout.copyStride
        <<"; missing field, malformed ELF, wrong architecture and inconsistent digest rejected\n";
    return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<"\n";return 1;}}
