#include "../src/vendor_ramdisk.hpp"
#include <fstream>
#include <iostream>
using namespace vrp;
int main(int argc,char** argv){try{
    require(argc==3,"vendor_ramdisk_test vendor_boot.img expected-vr.ko");std::ifstream image(argv[1],std::ios::binary);require(bool(image),"Missing vendor boot fixture");
    image.seekg(0,std::ios::end);auto length=image.tellg();require(length>=0,"No vendor boot size");
    auto read=[&](uint64_t offset,size_t size){Bytes data(size);image.seekg(std::streamoff(offset));image.read(reinterpret_cast<char*>(data.data()),std::streamsize(size));require(image.gcount()==std::streamsize(size),"Image fixture short read");return data;};
    auto module=vrModuleFromVendorBoot(uint64_t(length),read);std::ifstream expectedFile(argv[2],std::ios::binary);require(bool(expectedFile),"Missing independent module fixture");
    Bytes expected(std::istreambuf_iterator<char>(expectedFile),{});require(module==expected,"Native extraction differs from independently extracted vr module");
    bool rejected=false;try{decodeLegacyLz4({2,0x21,0x4c,0x18,3,0,0,0,0,0,0});}catch(const std::exception&){rejected=true;}require(rejected,"Bad LZ4 match accepted");
    rejected=false;try{vrModuleFromCpio(Bytes(110));}catch(const std::exception&){rejected=true;}require(rejected,"Bad CPIO accepted");
    std::cout<<"PASS native vendor_boot/LZ4/newc extraction equals independent vr module; malformed LZ4/CPIO rejected; bytes="<<module.size()<<"\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}}
