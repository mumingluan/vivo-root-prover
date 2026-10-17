#include "../src/kernel_log_layout.hpp"
#include <fstream>
#include <iostream>
using namespace vrp;
int main(int argc,char** argv){try{
    require(argc==2,"kernel_layout_test FILE");std::ifstream file(argv[1],std::ios::binary);require(bool(file),"Missing kernel fixture");
    KernelModule module(Bytes(std::istreambuf_iterator<char>(file),{}));auto control=discoverKernelControls(module);auto plan=discoverKernelLogLayout(module);const auto& layout=plan.layout;
    std::cout<<"{\"magic\":"<<layout.magic<<",\"marker\":"<<layout.marker<<",\"recordBytes\":"<<layout.recordBytes
        <<",\"regionBytes\":"<<layout.regionBytes<<",\"partitionTailOffset\":"<<layout.tailOffset<<",\"counterOffset\":"<<layout.counterOffset
        <<",\"sentinelOffsets\":["<<layout.sentinelOffsets[0]<<","<<layout.sentinelOffsets[1]<<"],\"textFields\":{"
        <<"\"firmware\":{\"offset\":"<<layout.firmwareOffset<<",\"bytes\":"<<layout.firmwareBytes<<"},"
        <<"\"event\":{\"offset\":"<<layout.eventOffset<<",\"bytes\":"<<layout.eventBytes<<"},"
        <<"\"message\":{\"offset\":"<<layout.messageOffset<<",\"bytes\":"<<layout.messageBytes<<"}},"
        <<"\"textCodec\":{\"xorSeed\":"<<layout.xorSeed<<",\"xorPeriod\":"<<layout.xorPeriod<<",\"rotateLeft\":"<<layout.rotateLeft<<"},"
        <<"\"headerPc\":"<<plan.headerPc<<",\"recordPc\":"<<plan.recordPc<<",\"ringPc\":"<<plan.ringPc<<",\"tailPc\":"<<plan.tailPc<<"}\n";
    return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}}
