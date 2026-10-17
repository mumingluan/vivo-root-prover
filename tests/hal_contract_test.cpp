#include "../src/hal_contract.hpp"
#include <fstream>
#include <iostream>
using namespace vrp;
Bytes file(const char* path){std::ifstream stream(path,std::ios::binary);require(bool(stream),"HAL fixture missing");return Bytes(std::istreambuf_iterator<char>(stream),{});}
int main(int argc,char** argv){try{
    require(argc==4,"provide service, implementation and NV library");auto service=file(argv[1]),implementation=file(argv[2]),factory=file(argv[3]);auto nv=discover_factory_layout(factory);
    auto plan=discover_hal_contract(service,implementation,factory,nv.layout);
    std::cout<<"{\"worker\":"<<plan.worker<<",\"creator\":"<<plan.creator<<",\"createPc\":"<<plan.createPc<<",\"readPc\":"<<plan.readPc<<",\"getPc\":"<<plan.getPc<<",\"putPc\":"<<plan.putPc
        <<",\"propertyPc\":"<<plan.propertyPc<<",\"procBranchPc\":"<<plan.procBranchPc<<",\"successBranchPc\":"<<plan.successBranchPc<<",\"flagBranchPc\":"<<plan.flagBranchPc<<",\"rootStorePc\":"<<plan.rootStorePc
        <<",\"rootLoadPc\":"<<plan.rootLoadPc<<",\"rootOffset\":"<<plan.rootOffset<<",\"bufferBytes\":"<<plan.bufferBytes<<"}\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<"\n";return 1;}}
