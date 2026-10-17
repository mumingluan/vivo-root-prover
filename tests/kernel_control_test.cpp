#include "../src/kernel_control.hpp"
#include <fstream>
#include <iostream>
using namespace vrp;
static std::string quote(const std::string& text){std::string out="\"";for(char c:text){if(c=='\\'||c=='\"')out+='\\';out+=c;}return out+'"';}
int main(int argc,char** argv){try{
    require(argc==2,"kernel_control_test FILE");std::ifstream file(argv[1],std::ios::binary);require(bool(file),"Missing module fixture");
    KernelModule module(Bytes(std::istreambuf_iterator<char>(file),{}));auto plan=discoverKernelControls(module);
    std::cout<<"{\"noteHex\":"<<quote(hex(plan.buildIdNote))<<",\"controls\":[";bool first=true;
    for(const auto& control:plan.controls){if(!first)std::cout<<",";first=false;
        std::cout<<"{\"disable\":"<<quote(control.disable.command)<<",\"enable\":"<<quote(control.enable.command)
            <<",\"flagSection\":"<<quote(module.sections[control.disable.target.section].name)<<",\"flagOffset\":"<<control.disable.target.offset
            <<",\"gatePc\":"<<control.gatePc<<",\"gateExit\":"<<control.exitPc<<"}";}
    std::cout<<"]}\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}}
