#include "../src/hal_process.hpp"
#include <iostream>
using namespace vrp;
template<class F>void reject(F action){bool failed=false;try{action();}catch(const std::exception&){failed=true;}require(failed,"Unsafe HAL mapping accepted");}
int main(){try{
    std::vector<HalImageIdentity> images={{"/vendor/bin/hw/service",120,253,0},{"/vendor/lib64/hw/implementation.so",121,253,0},{"/vendor/lib64/factory.so",122,253,0}};
    std::string good="1000-2000 r-xp 0000 fd:00 120 /vendor/bin/hw/service\n2000-3000 r-xp 0000 fd:00 121 /vendor/lib64/hw/implementation.so\n3000-4000 r-xp 0000 fd:00 122 /vendor/lib64/factory.so\n4000-5000 rw-p 0000 00:00 0 [heap]\n";
    verify_hal_image_mappings(good,images);
    auto alias=good;alias.replace(alias.find("/vendor/lib64/factory.so"),std::string("/vendor/lib64/factory.so").size(),"/another/namespace/factory.so");verify_hal_image_mappings(alias,images);
    auto wrong=good;wrong.replace(wrong.find(" 121 "),5," 999 ");reject([&]{verify_hal_image_mappings(wrong,images);});
    wrong=good;wrong.replace(wrong.find("fd:00 122"),9,"fd:01 122");reject([&]{verify_hal_image_mappings(wrong,images);});
    wrong=good;wrong.insert(wrong.find("\n")," (deleted)");reject([&]{verify_hal_image_mappings(wrong,images);});
    wrong=good;wrong.replace(wrong.find("r-xp"),4,"r--p");reject([&]{verify_hal_image_mappings(wrong,images);});
    reject([&]{verify_hal_image_mappings("1000-2000 r-xp",images);});reject([&]{verify_hal_image_mappings("2000-1000 r-xp 0 fd:00 120 /vendor/bin/hw/service\n",images);});
    reject([&]{verify_hal_image_mappings("",images);});images.push_back(images[0]);reject([&]{verify_hal_image_mappings(good,images);});
    std::cout<<"PASS loaded HAL mapping file/device/inode identity, namespace aliases; deleted, wrong inode/device, nonexecutable, missing, malformed and duplicate refusal\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<"\n";return 1;}}
