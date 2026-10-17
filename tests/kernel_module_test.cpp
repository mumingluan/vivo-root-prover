#include "../src/kernel_module.hpp"
#include <fstream>
#include <iostream>
using namespace vrp;
int main(int argc,char** argv){try{
    require(argc==2,"kernel_module_test FILE");std::ifstream file(argv[1],std::ios::binary);require(bool(file),"Missing module fixture");
    Bytes bytes(std::istreambuf_iterator<char>(file),{});KernelModule module(bytes);
    auto note=module.buildIdNote();size_t count=0;for(uint64_t pc=0;pc<module.textSize();pc+=4)if(module.tryInstruction(pc))++count;
    require(count>0 && !module.textRelocations().empty(),"No decoded kernel instructions/relocations");
    auto wrong=bytes;wrong[18]=62;bool rejected=false;try{KernelModule invalid(wrong);}catch(const std::exception&){rejected=true;}require(rejected,"Wrong architecture accepted");
    std::cout<<"PASS ELF sections/symbols/relocations, build-id note, bounded AArch64 decode, wrong architecture refusal; instructions="<<count<<" noteBytes="<<note.size()<<"\n";
    return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}}
