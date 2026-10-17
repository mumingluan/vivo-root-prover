#include "../src/kernel_log_layout.hpp"
#include <fstream>
#include <iostream>
using namespace vrp;
static Bytes load(const char* path){std::ifstream file(path,std::ios::binary);require(bool(file),"Missing native cleaner fixture");return Bytes(std::istreambuf_iterator<char>(file),{});}
int main(int argc,char** argv){try{
    require(argc==4,"kernel_cleaner_test vr.ko input-log output-log");KernelModule module(load(argv[1]));
    (void)discoverKernelControls(module);auto plan=discoverKernelLogLayout(module);auto output=clear_log(load(argv[2]),plan.layout);
    std::ofstream target(argv[3],std::ios::binary);target.write(reinterpret_cast<const char*>(output.data()),std::streamsize(output.size()));require(bool(target),"Native cleaner fixture output failed");return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}}
