#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace vrp {
using Bytes = std::vector<uint8_t>;
struct NvLayout {
    uint32_t recordBytes=0,rootOffset=0,digestOffset=0,copyStride=0;
    bool operator==(const NvLayout& other) const {
        return recordBytes==other.recordBytes&&rootOffset==other.rootOffset
            &&digestOffset==other.digestOffset&&copyStride==other.copyStride;
    }
};
struct MountLogLayout {
    uint32_t magic=0,marker=0,recordBytes=0,regionBytes=0,tailOffset=0,counterOffset=0;
    uint32_t sentinelOffsets[2]{};
    uint32_t firmwareOffset=0,firmwareBytes=0,eventOffset=0,eventBytes=0,messageOffset=0,messageBytes=0;
    uint32_t xorSeed=0,xorPeriod=0,rotateLeft=0;
};
inline bool valid_mount_log_layout(const MountLogLayout& layout) {
    return layout.magic && layout.marker && layout.recordBytes>=128 && layout.recordBytes<=8192
        && (layout.recordBytes&(layout.recordBytes-1))==0 && layout.regionBytes>=layout.recordBytes*2
        && layout.regionBytes<=32768 && layout.regionBytes%layout.recordBytes==0
        && layout.tailOffset>=layout.regionBytes && layout.tailOffset<=1048576
        && layout.counterOffset>=8 && layout.counterOffset<=layout.firmwareOffset
        && layout.firmwareOffset-layout.counterOffset>=4
        && layout.sentinelOffsets[0]>=layout.counterOffset+4 && layout.sentinelOffsets[0]%4==0
        && layout.sentinelOffsets[0]<=layout.recordBytes-4
        && layout.sentinelOffsets[1]>=layout.sentinelOffsets[0]+4 && layout.sentinelOffsets[1]%4==0
        && layout.sentinelOffsets[1]<=layout.recordBytes-4
        && layout.firmwareOffset>=layout.sentinelOffsets[1]+4
        && layout.firmwareBytes>0 && layout.firmwareBytes<=128 && layout.firmwareOffset<=layout.eventOffset
        && layout.eventOffset-layout.firmwareOffset==layout.firmwareBytes
        && layout.eventBytes>0 && layout.eventBytes<=64 && layout.eventOffset<=layout.messageOffset
        && layout.messageOffset-layout.eventOffset==layout.eventBytes
        && layout.messageOffset<layout.recordBytes && layout.messageBytes==layout.recordBytes-layout.messageOffset
        && layout.xorSeed>0 && layout.xorSeed<=31 && layout.xorPeriod>0 && layout.xorPeriod<=31 && layout.xorSeed+layout.xorPeriod<=32
        && layout.rotateLeft>0 && layout.rotateLeft<8;
}
inline bool valid_nv_layout(const NvLayout& layout) {
    return layout.recordBytes>=512&&layout.recordBytes<=8192&&layout.recordBytes%512==0
        &&layout.rootOffset%4==0&&layout.rootOffset<=layout.digestOffset&&layout.digestOffset-layout.rootOffset>=4
        &&layout.digestOffset<=layout.recordBytes&&layout.recordBytes-layout.digestOffset>=16
        &&layout.copyStride>=layout.recordBytes&&layout.copyStride<=1048576;
}
inline bool valid_cleanup_geometry(const NvLayout& nv,const MountLogLayout& log) {
    return valid_nv_layout(nv)&&valid_mount_log_layout(log)
        &&uint64_t(nv.recordBytes)*4+uint64_t(log.regionBytes)*2+(16+3*16+32)<65536;
}
inline void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}
inline uint32_t le32(const uint8_t* p) {
    return uint32_t(p[0]) | uint32_t(p[1])<<8 | uint32_t(p[2])<<16 | uint32_t(p[3])<<24;
}
inline uint32_t be32(const uint8_t* p) {
    return uint32_t(p[3]) | uint32_t(p[2])<<8 | uint32_t(p[1])<<16 | uint32_t(p[0])<<24;
}
inline uint64_t be64(const uint8_t* p) { return uint64_t(be32(p))<<32 | be32(p+4); }
inline void put32(uint8_t* p, uint32_t v) {
    for (unsigned i=0; i<4; ++i) p[i]=uint8_t(v>>(8*i));
}
inline uint32_t rol(uint32_t x, unsigned n) { return x<<n | x>>(32-n); }
inline uint32_t ror(uint32_t x, unsigned n) { return x>>n | x<<(32-n); }
inline Bytes padded(const Bytes& in, bool bigEndian) {
    require(in.size()<0x10000000, "digest input too large");
    Bytes out=in; out.push_back(0x80);
    while (out.size()%64!=56) out.push_back(0);
    uint64_t bits=uint64_t(in.size())*8;
    for (unsigned i=0; i<8; ++i) out.push_back(uint8_t(bits>>(8*(bigEndian ? 7-i : i))));
    return out;
}
inline Bytes md5(const Bytes& in) {
    static const uint32_t k[64]={
      0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
      0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
      0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
      0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
      0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
      0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
      0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
      0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
    static const unsigned s[16]={7,12,17,22,5,9,14,20,4,11,16,23,6,10,15,21};
    uint32_t h[4]={0x67452301,0xefcdab89,0x98badcfe,0x10325476};
    auto data=padded(in,false);
    for(size_t off=0; off<data.size(); off+=64) {
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3];
        for(unsigned i=0;i<64;++i) {
            unsigned phase=i/16, g;
            uint32_t f;
            if(phase==0){f=(b&c)|(~b&d);g=i;}
            else if(phase==1){f=(d&b)|(~d&c);g=(5*i+1)%16;}
            else if(phase==2){f=b^c^d;g=(3*i+5)%16;}
            else{f=c^(b|~d);g=(7*i)%16;}
            auto old=d; d=c;c=b;b+=rol(a+f+k[i]+le32(data.data()+off+g*4),s[phase*4+i%4]);a=old;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;
    }
    Bytes out(16);for(unsigned i=0;i<4;++i)put32(out.data()+4*i,h[i]);return out;
}
inline Bytes sha256(const Bytes& in) {
    static const uint32_t k[64]={
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    auto data=padded(in,true);
    for(size_t off=0;off<data.size();off+=64) {
        uint32_t w[64];for(unsigned i=0;i<16;++i)w[i]=be32(data.data()+off+i*4);
        for(unsigned i=16;i<64;++i){auto x=w[i-15],y=w[i-2];w[i]=w[i-16]+(ror(x,7)^ror(x,18)^(x>>3))+w[i-7]+(ror(y,17)^ror(y,19)^(y>>10));}
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],z=h[7];
        for(unsigned i=0;i<64;++i){auto t1=z+(ror(e,6)^ror(e,11)^ror(e,25))+((e&f)^(~e&g))+k[i]+w[i];auto t2=(ror(a,2)^ror(a,13)^ror(a,22))+((a&b)^(a&c)^(b&c));z=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=z;
    }
    Bytes out(32);for(unsigned i=0;i<8;++i)for(unsigned j=0;j<4;++j)out[i*4+j]=uint8_t(h[i]>>(24-8*j));return out;
}
inline std::string hex(const Bytes& data) {
    static const char* digits="0123456789abcdef";std::string out;
    for(auto c:data){out+=digits[c>>4];out+=digits[c&15];}return out;
}
struct ProcViewOps {
    std::function<void()> disableGates;
    std::function<std::string()> readUnderlying;
    std::function<bool()> hasOwnedMasks;
    std::function<void()> removeOwnedMasks;
    std::function<void()> applyMasks;
    std::function<bool()> readersSeeZero;
};
inline bool underlying_root(const std::string& state) {
    require(state=="mount state:0"||state=="mount state:1","unknown underlying proc state");
    return state=="mount state:1";
}
// Shared by the real helper and host fault tests. Return the resulting view
// mode; callers must not infer it from the visible (possibly masked) node.
inline std::string maintain_proc_view(const ProcViewOps& ops) {
    ops.disableGates();
    bool rooted=underlying_root(ops.readUnderlying());
    if(!rooted){
        if(ops.hasOwnedMasks())ops.removeOwnedMasks();
        // Catch a state transition during removal/checking without creating
        // any mount when the underlying state remains zero.
        bool readersZero=ops.readersSeeZero();
        rooted=underlying_root(ops.readUnderlying());
        if(!rooted){require(readersZero,"HAL or init proc view differs from zero underlying state");return "natural";}
    }
    ops.applyMasks();
    require(ops.readersSeeZero(),"root proc view protection failed");
    return "masked";
}
struct AvbName { uint64_t tag; std::string name; };
inline std::vector<AvbName> avb_names(const Bytes& descriptors) {
    size_t at=0;std::vector<AvbName> out;
    while(at<descriptors.size()){
        require(descriptors.size()-at>=16,"truncated AVB descriptor");auto p=descriptors.data()+at;
        uint64_t tag=be64(p),following=be64(p+8);
        require(tag<=4,"unsupported AVB descriptor type");
        require(following<=descriptors.size()-at-16&&following%8==0,"AVB descriptor length invalid");
        size_t total=size_t(following+16),nameAt=0,nameLenAt=0;
        if(tag==1){nameAt=180;nameLenAt=104;}else if(tag==2){nameAt=132;nameLenAt=56;}else if(tag==4){nameAt=92;nameLenAt=20;}
        if(nameAt){require(total>=nameAt&&nameLenAt+4<=total,"short AVB partition descriptor");size_t n=be32(p+nameLenAt);
            require(n>0&&n<=128&&n<=total-nameAt,"AVB partition name invalid");
            std::string name(reinterpret_cast<const char*>(p+nameAt),n);
            require(name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")==std::string::npos,"unsafe AVB partition name");out.push_back({tag,name});}
        at+=total;
    }
    return out;
}
inline bool valid_nv(const Bytes& data,const NvLayout& layout) {
    if(!valid_nv_layout(layout)||data.size()!=layout.recordBytes||le32(data.data()+layout.rootOffset)>1)return false;
    auto digest=md5(Bytes(data.begin(),data.begin()+layout.digestOffset));
    return std::equal(digest.begin(),digest.end(),data.begin()+layout.digestOffset);
}
inline Bytes clear_nv(const Bytes& data,const NvLayout& layout) {
    require(valid_nv(data,layout),"NV size, root field or MD5 mismatch");
    Bytes out=data;put32(out.data()+layout.rootOffset,0);
    auto digest=md5(Bytes(out.begin(),out.begin()+layout.digestOffset));
    std::copy(digest.begin(),digest.end(),out.begin()+layout.digestOffset);return out;
}
inline std::string log_text(const uint8_t* p, size_t count,const MountLogLayout& layout) {
    require(valid_mount_log_layout(layout),"Unverified mount-log text layout");
    std::string text;
    for(size_t i=0;i<count && p[i];++i){uint8_t rotated=uint8_t((p[i]>>layout.rotateLeft)|(p[i]<<(8-layout.rotateLeft)));
        uint8_t c=rotated^uint8_t(layout.xorSeed+i%layout.xorPeriod);require(c>=32&&c<=126,"log text not printable");text+=char(c);}
    return text;
}
inline Bytes clear_log(const Bytes& data,const MountLogLayout& layout) {
    require(valid_mount_log_layout(layout)&&data.size()==layout.regionBytes,"mount log region size/layout mismatch");
    if(std::all_of(data.begin(),data.end(),[](uint8_t b){return b==0;}))return data;
    require(le32(data.data())==layout.magic && le32(data.data()+4)==layout.marker,"mount log header mismatch");
    require(le32(data.data()+layout.sentinelOffsets[0])==0xffffffff && le32(data.data()+layout.sentinelOffsets[1])==0xffffffff,"mount log header sentinels mismatch");
    Bytes out=data;put32(out.data()+layout.counterOffset,0);
    uint32_t total=le32(data.data()+layout.counterOffset);
    for(size_t offset=layout.recordBytes;offset<data.size();offset+=layout.recordBytes) {
        auto p=data.data()+offset;
        if(std::all_of(p,p+layout.recordBytes,[](uint8_t b){return b==0;}))continue;
        require(le32(p)==layout.magic && le32(p+4)==layout.marker && le32(p+layout.counterOffset)<total,"unrecognized mount log record");
        require(log_text(p+layout.eventOffset,layout.eventBytes,layout)=="mnt","non-mount record in log region");
        // The firmware label is record metadata, not the binary schema version.
        // Header/slot geometry and marker checks above still define that schema.
        auto firmware=log_text(p+layout.firmwareOffset,layout.firmwareBytes,layout);
        require(std::any_of(firmware.begin(),firmware.end(),[](unsigned char c){return c>32;}),"mount log firmware label empty");
        (void)log_text(p+layout.messageOffset,layout.messageBytes,layout);
        std::fill(out.begin()+offset,out.begin()+offset+layout.recordBytes,0);
    }
    return out;
}
struct Region { uint32_t target; uint64_t offset; Bytes before,after; };
inline void append32(Bytes& b,uint32_t n){size_t at=b.size();b.resize(at+4);put32(b.data()+at,n);}
inline void append64(Bytes& b,uint64_t n){append32(b,uint32_t(n));append32(b,uint32_t(n>>32));}
inline Bytes journal(const std::vector<Region>& regions) {
    require(regions.size()==3,"transaction requires both NV copies and mount log");
    Bytes out={'V','R','P','J','N','L','0','1'};append32(out,1);append32(out,uint32_t(regions.size()));
    for(const auto& r:regions){require(r.before.size()==r.after.size(),"region length mismatch");append32(out,r.target);append32(out,uint32_t(r.before.size()));append64(out,r.offset);out.insert(out.end(),r.before.begin(),r.before.end());out.insert(out.end(),r.after.begin(),r.after.end());}
    auto hash=sha256(out);out.insert(out.end(),hash.begin(),hash.end());return out;
}
inline std::vector<Region> parse_journal(const Bytes& data,uint64_t reservedSize,const NvLayout& layout,const MountLogLayout& logLayout) {
    require(valid_cleanup_geometry(layout,logLayout),"unverified NV/log journal geometry");
    require(data.size()>=48 && data.size()<65536,"journal length invalid");
    require(std::string(data.begin(),data.begin()+8)=="VRPJNL01" && le32(data.data()+8)==1 && le32(data.data()+12)==3,"journal header invalid");
    auto h=sha256(Bytes(data.begin(),data.end()-32));require(std::equal(h.begin(),h.end(),data.end()-32),"journal SHA256 mismatch");
    size_t pos=16;std::vector<Region> out;
    for(unsigned i=0;i<3;++i){require(pos+16<=data.size()-32,"truncated journal");auto p=data.data()+pos;uint32_t type=le32(p),length=le32(p+4);uint64_t offset=uint64_t(le32(p+8))|(uint64_t(le32(p+12))<<32);pos+=16;
        bool nv=type==0 && length==layout.recordBytes && (offset==0||offset==layout.copyStride);
        bool log=type==1 && length==logLayout.regionBytes && reservedSize>=logLayout.tailOffset && offset==reservedSize-logLayout.tailOffset;
        require((nv||log) && pos+size_t(length)*2<=data.size()-32,"journal write range forbidden");
        Region r{type,offset,Bytes(data.begin()+pos,data.begin()+pos+length),Bytes(data.begin()+pos+length,data.begin()+pos+2*length)};pos+=2*length;
        require(r.after==(nv?clear_nv(r.before,layout):clear_log(r.before,logLayout)),"journal contains unauthorized changes");out.push_back(r);
    }
    require(pos==data.size()-32,"journal trailing data");
    require(out[0].target==0 && out[0].offset==layout.copyStride && out[1].target==0 && out[1].offset==0 && out[2].target==1,"journal region order invalid");
    return out;
}
// Caller creates and fsyncs an immutable journal before this function.
// A multi-region block-device transaction is not power-loss atomic.
inline void transact(const std::vector<Region>& regions,
    const std::function<Bytes(const Region&)>& read,
    const std::function<void(const Region&,const Bytes&)>& write,
    const std::function<void()>& sync,bool restore=false) {
    for(const auto& r:regions)require(read(r)==(restore?r.after:r.before),"concurrent change or restore baseline mismatch");
    std::vector<size_t> touched;
    try {
        for(size_t i=0;i<regions.size();++i){const auto& r=regions[i];const auto& previous=restore?r.after:r.before;const auto& next=restore?r.before:r.after;
            require(read(r)==previous,"concurrent region change");if(next==previous)continue;touched.push_back(i);write(r,next);sync();require(read(r)==next,"write readback mismatch");}
    } catch(...) {
        bool conflict=false;
        for(auto it=touched.rbegin();it!=touched.rend();++it){const auto& r=regions[*it];const auto& old=restore?r.after:r.before;const auto& next=restore?r.before:r.after;
            try{auto now=read(r);bool ours=now.size()==old.size();for(size_t j=0;ours&&j<now.size();++j)ours=now[j]==old[j]||now[j]==next[j];
                if(ours){write(r,old);sync();require(read(r)==old,"rollback readback mismatch");}else conflict=true;
            }catch(...){conflict=true;}
        }
        if(conflict)throw std::runtime_error("transaction failed; rollback incomplete, retain journal and stop");
        throw;
    }
}
} // namespace vrp
