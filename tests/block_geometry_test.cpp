#include "../src/block_geometry.hpp"
#include "../src/native_layout.hpp"
#include "../src/kernel_log_layout.hpp"
#include <fstream>
#include <iostream>
using namespace vrp;
static unsigned negatives=0;
template<class F>static void rejects(F action){bool failed=false;try{action();}catch(const std::exception&){failed=true;}require(failed,"Unsafe block geometry accepted");++negatives;}
static Bytes load(const std::string& path){std::ifstream file(path,std::ios::binary);require(bool(file),"Geometry input missing");return Bytes(std::istreambuf_iterator<char>(file),{});}
static uint64_t rounded(uint64_t value,uint32_t sector){return (value+sector-1)/sector*sector;}
static void scenario(const CleanupGeometry& g,const NvLayout& nv,const MountLogLayout& log,const Bytes& logBefore) {
    Bytes record(nv.recordBytes,0);put32(record.data()+nv.rootOffset,1);
    auto digest=md5(Bytes(record.begin(),record.begin()+nv.digestOffset));std::copy(digest.begin(),digest.end(),record.begin()+nv.digestOffset);
    std::vector<Region> regions={{0,g.secondaryOffset,record,clear_nv(record,nv)},{0,g.primaryOffset,record,clear_nv(record,nv)},{1,g.logOffset,logBefore,clear_log(logBefore,log)}};
    validate_cleanup_regions(g,regions);auto restored=parse_journal(journal(regions),g.reserved.bytes,nv,log);validate_cleanup_regions(g,restored);
    Bytes backup(size_t(g.backup.bytes),0xa5),reserved(size_t(g.reserved.bytes),0x5a);
    for(const auto& r:regions){auto& target=r.target?reserved:backup;std::copy(r.before.begin(),r.before.end(),target.begin()+r.offset);}
    const auto backupBefore=backup,reservedBefore=reserved;unsigned writes=0;
    auto read=[&](const Region& r){const auto& target=r.target?reserved:backup;return Bytes(target.begin()+r.offset,target.begin()+r.offset+r.before.size());};
    auto write=[&](const Region& r,const Bytes& value){auto& target=r.target?reserved:backup;std::copy(value.begin(),value.end(),target.begin()+r.offset);++writes;};
    auto sync=[](){};transact(regions,read,write,sync);require(writes==3,"All discovered NV/log changes must be committed");
    auto expectedBackup=backupBefore,expectedReserved=reservedBefore;
    for(const auto& r:regions){auto& target=r.target?expectedReserved:expectedBackup;std::copy(r.after.begin(),r.after.end(),target.begin()+r.offset);}
    require(backup==expectedBackup&&reserved==expectedReserved,"Geometry transaction changed bytes outside approved regions");
    transact(restored,read,write,sync,true);require(backup==backupBefore&&reserved==reservedBefore,"Geometry restore did not recover all bytes");
    // A partial write still uses the same transaction rollback on dynamically
    // located ranges; faults do not change range admission.
    bool fault=true;
    auto brokenWrite=[&](const Region& r,const Bytes& value){if(fault){fault=false;auto& target=r.target?reserved:backup;std::copy(value.begin(),value.begin()+value.size()/2,target.begin()+r.offset);throw std::runtime_error("injected short write");}write(r,value);};
    rejects([&]{transact(regions,read,brokenWrite,sync);});require(backup==backupBefore&&reserved==reservedBefore,"Partial geometry write rollback failed");
    auto changed=g.reserved;unsigned guardedWrites=0;
    auto checkedRead=[&](const Region& r){verify_geometry_stable(g,g.backup,changed);return read(r);};
    auto resizedWrite=[&](const Region& r,const Bytes& value){verify_geometry_stable(g,g.backup,changed);write(r,value);++guardedWrites;changed.bytes+=changed.logicalSector;};
    rejects([&]{transact(regions,checkedRead,resizedWrite,sync);});
    require(guardedWrites==1&&read(regions[1])==regions[1].before&&read(regions[2])==regions[2].before,"Writes continued after geometry change");
    // Retain journal and stop: unknown new geometry also blocks rollback I/O.
    auto forbidden=regions;--forbidden[2].offset;rejects([&]{validate_cleanup_regions(g,forbidden);});
    forbidden=regions;forbidden[0].target=1;rejects([&]{validate_cleanup_regions(g,forbidden);});
    forbidden=regions;forbidden[0].after.pop_back();rejects([&]{validate_cleanup_regions(g,forbidden);});
}
int main(int argc,char** argv){try{
    require(argc==4,"block_geometry_test FACTORY VR LOG");auto factory=load(argv[1]);auto moduleBytes=load(argv[2]);
    NvLayout nv=discover_factory_layout(factory).layout;KernelModule module(std::move(moduleBytes));MountLogLayout log=discoverKernelLogLayout(module).layout;
    auto logBefore=load(argv[3]);require(clear_log(logBefore,log)!=logBefore,"Geometry log input must contain a real layout-derived change");
    std::cout<<"{\"recordBytes\":"<<nv.recordBytes<<",\"copyStride\":"<<nv.copyStride<<",\"tailOffset\":"<<log.tailOffset<<",\"regionBytes\":"<<log.regionBytes<<",\"cases\":[";
    bool first=true;
    for(uint32_t sector:{512u,4096u})for(unsigned extra:{0u,5u}) {
        BlockGeometry backup{rounded(uint64_t(nv.copyStride)+nv.recordBytes,sector)+sector*3,sector,8,1};
        BlockGeometry reserved{rounded(log.tailOffset,sector)+sector*extra,sector,8,2};
        auto geometry=cleanup_geometry(backup,reserved,nv,log);scenario(geometry,nv,log,logBefore);
        verify_geometry_stable(geometry,backup,reserved);
        if(!first)std::cout<<",";
        first=false;
        std::cout<<"{\"sector\":"<<sector<<",\"backupBytes\":"<<backup.bytes<<",\"reservedBytes\":"<<reserved.bytes<<",\"logOffset\":"<<geometry.logOffset<<"}";
        auto badBackup=backup;badBackup.bytes=rounded(uint64_t(nv.copyStride)+nv.recordBytes,sector)-sector;
        rejects([&]{cleanup_geometry(badBackup,reserved,nv,log);});
        auto badReserved=reserved;badReserved.bytes=rounded(log.tailOffset,sector)-sector;rejects([&]{cleanup_geometry(backup,badReserved,nv,log);});
        badReserved=reserved;badReserved.deviceMinor=backup.deviceMinor;rejects([&]{cleanup_geometry(backup,badReserved,nv,log);});
        badReserved=reserved;badReserved.logicalSector=0;rejects([&]{cleanup_geometry(backup,badReserved,nv,log);});
        badReserved=reserved;++badReserved.bytes;rejects([&]{cleanup_geometry(backup,badReserved,nv,log);});
        badReserved=reserved;badReserved.bytes=uint64_t(std::numeric_limits<int64_t>::max())+1;rejects([&]{cleanup_geometry(backup,badReserved,nv,log);});
        badReserved=reserved;badReserved.bytes+=sector;rejects([&]{verify_geometry_stable(geometry,backup,badReserved);});
        badReserved=reserved;badReserved.logicalSector/=2;rejects([&]{verify_geometry_stable(geometry,backup,badReserved);});
        badReserved=reserved;++badReserved.deviceMajor;rejects([&]{verify_geometry_stable(geometry,backup,badReserved);});
    }
    BlockGeometry b{16384,512,8,1},r{(uint64_t(1)<<40)+512,512,8,2};auto large=cleanup_geometry(b,r,nv,log);
    require(large.logOffset==r.bytes-log.tailOffset&&large.logOffset>uint64_t(UINT32_MAX),"Large disk offset truncated");
    auto overlap=nv;overlap.copyStride=overlap.recordBytes-1;rejects([&]{cleanup_geometry(b,r,overlap,log);});
    auto invalidLog=log;invalidLog.tailOffset=invalidLog.regionBytes-1;rejects([&]{cleanup_geometry(b,r,nv,invalidLog);});
    require(!file_range(UINT64_MAX,1)&&!file_range(uint64_t(INT64_MAX)-3,4)&&file_range(uint64_t(INT64_MAX)-3,3)
        &&!device_range(10,9,2)&&!device_range(10,11,0)&&device_range(10,9,1),"Overflow/file/device range checks failed");
    std::cout<<"],\"largeLogOffset\":"<<large.logOffset<<",\"negativeChecks\":"<<negatives<<",\"allPassed\":true}\n";return 0;
}catch(const std::exception& failure){std::cerr<<failure.what()<<"\n";return 1;}}
