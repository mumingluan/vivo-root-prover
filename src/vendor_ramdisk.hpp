#pragma once
#include "core.hpp"

namespace vrp {
inline void ramdiskRange(const Bytes& data,size_t at,size_t count){require(at<=data.size()&&count<=data.size()-at,"Vendor ramdisk range invalid");}
inline size_t alignRamdisk(size_t value,size_t alignment){require(alignment&&value<=SIZE_MAX-(alignment-1),"Vendor ramdisk alignment overflow");return (value+alignment-1)&~(alignment-1);}
inline Bytes decodeLegacyLz4(const Bytes& data) {
    require(data.size()>=4&&le32(data.data())==0x184c2102u,"Unsupported vendor ramdisk compression");
    constexpr size_t blockMaximum=8*1024*1024,totalMaximum=64*1024*1024;Bytes output;size_t position=4;
    while(position<data.size()){
        ramdiskRange(data,position,4);uint32_t compressed=le32(data.data()+position);position+=4;if(compressed==0)break;
        require(compressed<=blockMaximum+65536,"LZ4 legacy block too large");ramdiskRange(data,position,compressed);
        size_t end=position+compressed,base=output.size();
        auto extended=[&](size_t value){if(value==15){uint8_t byte;do{require(position<end,"LZ4 length extension truncated");byte=data[position++];require(value<=blockMaximum-byte,"LZ4 length overflow");value+=byte;}while(byte==255);}return value;};
        while(position<end){uint8_t token=data[position++];size_t literals=extended(token>>4);
            require(literals<=end-position&&literals<=blockMaximum-(output.size()-base)&&literals<=totalMaximum-output.size(),"LZ4 literal range invalid");
            output.insert(output.end(),data.begin()+position,data.begin()+position+literals);position+=literals;if(position==end)break;
            require(end-position>=2,"LZ4 match offset truncated");size_t offset=size_t(data[position])|size_t(data[position+1])<<8;position+=2;
            require(offset>0&&offset<=output.size()-base,"LZ4 match points outside independent block");size_t count=extended(token&15);
            require(count<=blockMaximum-4,"LZ4 match length overflow");count+=4;
            require(count<=blockMaximum-(output.size()-base)&&count<=totalMaximum-output.size(),"LZ4 match exceeds output bound");
            for(size_t i=0;i<count;++i)output.push_back(output[output.size()-offset]);
        }
        require(output.size()>base,"Empty LZ4 legacy block");
    }
    require(std::all_of(data.begin()+position,data.end(),[](uint8_t byte){return byte==0;}),"Additional vendor ramdisk frame unsupported");return output;
}
inline uint32_t cpioHex(const Bytes& data,size_t position){ramdiskRange(data,position,8);uint32_t value=0;
    for(size_t i=0;i<8;++i){uint8_t c=data[position+i];unsigned digit;
        if(c>='0'&&c<='9')digit=c-'0';else if(c>='a'&&c<='f')digit=c-'a'+10;else if(c>='A'&&c<='F')digit=c-'A'+10;else throw std::runtime_error("Invalid CPIO hexadecimal field");
        value=(value<<4)|digit;}return value;}
inline Bytes vrModuleFromCpio(const Bytes& archive) {
    require(archive.size()<=64*1024*1024,"Vendor CPIO too large");size_t position=0;unsigned matches=0;Bytes result;
    while(position<archive.size()){
        while(position<archive.size()&&archive[position]==0)++position;
        if(position==archive.size())break;
        ramdiskRange(archive,position,110);bool crc=std::memcmp(archive.data()+position,"070702",6)==0;
        require(crc||std::memcmp(archive.data()+position,"070701",6)==0,"Unknown vendor CPIO header");
        uint32_t mode=cpioHex(archive,position+6+8),length=cpioHex(archive,position+6+6*8),nameSize=cpioHex(archive,position+6+11*8),check=cpioHex(archive,position+6+12*8);
        require(nameSize>0&&nameSize<=4096,"Vendor CPIO name invalid");size_t nameAt=position+110;ramdiskRange(archive,nameAt,nameSize);
        require(archive[nameAt+nameSize-1]==0&&std::find(archive.begin()+nameAt,archive.begin()+nameAt+nameSize-1,0)==archive.begin()+nameAt+nameSize-1,"CPIO name not terminated");
        std::string name(archive.begin()+nameAt,archive.begin()+nameAt+nameSize-1);size_t start=alignRamdisk(nameAt+nameSize,4);ramdiskRange(archive,start,length);
        if(crc){uint32_t sum=0;for(size_t i=0;i<length;++i)sum+=archive[start+i];require(sum==check,"Vendor CPIO checksum mismatch");}
        else require(check==0,"Unexpected newc checksum field");
        if(!name.empty()&&name.front()=='/')name.erase(0,1);
        while(name.rfind("./",0)==0)name.erase(0,2);
        if(name=="lib/modules/vr.ko"){
            require((mode&0170000)==0100000&&length>=64&&length<=32*1024*1024&&++matches==1,"Kernel module CPIO entry invalid/duplicate");
            result=Bytes(archive.begin()+start,archive.begin()+start+length);
        }
        position=alignRamdisk(start+length,4);require(position<=archive.size(),"Vendor CPIO trailing alignment invalid");
    }
    require(matches==1,"No unique vr module in vendor CPIO");return result;
}
template<class Read>inline Bytes vrModuleFromVendorBoot(uint64_t fileSize,Read read) {
    require(fileSize>=2112,"Vendor boot header truncated");Bytes header=read(0,2112);require(header.size()==2112&&std::memcmp(header.data(),"VNDRBOOT",8)==0,"Vendor boot magic invalid");
    uint32_t version=le32(header.data()+8),page=le32(header.data()+12),ramdiskSize=le32(header.data()+24),headerSize=le32(header.data()+2096);
    require((version==3||version==4)&&page>=2048&&page<=65536&&(page&(page-1))==0&&headerSize>=2112&&headerSize<=1048576,"Vendor boot format unsupported");
    uint64_t offset=alignRamdisk(headerSize,page);require(ramdiskSize>0&&ramdiskSize<=32*1024*1024&&offset<=fileSize&&ramdiskSize<=fileSize-offset,"Vendor boot ramdisk outside image");
    Bytes encoded=read(offset,ramdiskSize);require(encoded.size()==ramdiskSize,"Vendor ramdisk read truncated");
    Bytes archive;if(encoded.size()>=6&&(std::memcmp(encoded.data(),"070701",6)==0||std::memcmp(encoded.data(),"070702",6)==0))archive=std::move(encoded);
    else archive=decodeLegacyLz4(encoded);
    return vrModuleFromCpio(archive);
}
}
