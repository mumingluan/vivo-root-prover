#pragma once
#include "core.hpp"
#include <sstream>
#include <set>

namespace vrp {
struct HalImageIdentity {
    std::string path;uint64_t inode=0;uint32_t majorDevice=0,minorDevice=0;
    bool operator==(const HalImageIdentity& b)const{return path==b.path&&inode==b.inode&&majorDevice==b.majorDevice&&minorDevice==b.minorDevice;}
};
inline uint64_t halMapInteger(const std::string& text,int base) {
    require(!text.empty()&&text.size()<=32&&text[0]!='-'&&text[0]!='+',"Malformed HAL map integer");size_t used=0;
    uint64_t value=std::stoull(text,&used,base);require(used==text.size(),"Trailing characters in HAL map integer");return value;
}
inline void verify_hal_image_mappings(const std::string& maps,const std::vector<HalImageIdentity>& expected) {
    require(!expected.empty()&&expected.size()<=16&&maps.size()<=8*1024*1024,"HAL map input exceeds bound");std::vector<bool> executable(expected.size(),false);std::istringstream lines(maps);std::string line;unsigned count=0;
    std::set<std::string> paths;for(const auto& image:expected)require(image.inode&&paths.insert(image.path).second,"Missing/duplicate HAL image identity");
    while(std::getline(lines,line)) {
        require(++count<=65536&&!line.empty(),"Malformed/unbounded HAL maps");std::istringstream fields(line);std::string range,permissions,offset,device,inode,path;
        require(bool(fields>>range>>permissions>>offset>>device>>inode),"Truncated HAL mapping");std::getline(fields,path);auto first=path.find_first_not_of(' ');path=first==std::string::npos?"":path.substr(first);
        auto dash=range.find('-'),colon=device.find(':');require(dash!=std::string::npos&&colon!=std::string::npos&&permissions.size()==4,"Malformed HAL map fields");
        uint64_t start=halMapInteger(range.substr(0,dash),16),end=halMapInteger(range.substr(dash+1),16);require(start<end,"Invalid HAL mapping range");
        (void)halMapInteger(offset,16);uint64_t major=halMapInteger(device.substr(0,colon),16),minor=halMapInteger(device.substr(colon+1),16),node=halMapInteger(inode,10);
        require(major<=UINT32_MAX&&minor<=UINT32_MAX,"HAL map device number overflows");
        require((permissions[0]=='r'||permissions[0]=='-')&&(permissions[1]=='w'||permissions[1]=='-')&&(permissions[2]=='x'||permissions[2]=='-')&&(permissions[3]=='p'||permissions[3]=='s'),"Unknown HAL map permissions");
        for(size_t i=0;i<expected.size();i++) {
            const auto& image=expected[i];bool same=node==image.inode&&major==image.majorDevice&&minor==image.minorDevice;
            require(path!=image.path+" (deleted)","HAL is executing a deleted image");
            if(path==image.path)require(same,"HAL map does not match the verified file identity");
            if(same){require(path.find(" (deleted)")==std::string::npos,"Verified HAL mapping was deleted");if(permissions[2]=='x')executable[i]=true;}
        }
    }
    require(std::all_of(executable.begin(),executable.end(),[](bool value){return value;}),"HAL lacks an executable mapping of a verified image");
}
} // namespace vrp
