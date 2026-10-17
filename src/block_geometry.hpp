#pragma once
#include "core.hpp"
#include <limits>

namespace vrp {
// Values observed from the already-open block fd, not a firmware size table.
struct BlockGeometry {
    uint64_t bytes=0;
    uint32_t logicalSector=0,deviceMajor=0,deviceMinor=0;
    bool operator==(const BlockGeometry& other)const {
        return bytes==other.bytes&&logicalSector==other.logicalSector&&deviceMajor==other.deviceMajor&&deviceMinor==other.deviceMinor;
    }
};
inline bool file_range(uint64_t offset,uint64_t length) {
    const auto limit=uint64_t(std::numeric_limits<int64_t>::max());
    return offset<=limit&&length<=limit-offset;
}
inline bool device_range(uint64_t size,uint64_t offset,uint64_t length) {
    return file_range(offset,length)&&offset<=size&&length<=size-offset;
}
inline void validate_block_geometry(const BlockGeometry& value) {
    require(value.bytes>0&&file_range(0,value.bytes)&&value.logicalSector>0
        &&value.bytes%value.logicalSector==0,"Invalid observed block capacity/logical sector");
}
struct CleanupGeometry {
    BlockGeometry backup,reserved;
    uint64_t primaryOffset=0,secondaryOffset=0,logOffset=0;
    uint32_t nvBytes=0,logBytes=0;
};
inline CleanupGeometry cleanup_geometry(const BlockGeometry& backup,const BlockGeometry& reserved,
    const NvLayout& nv,const MountLogLayout& log) {
    require(valid_cleanup_geometry(nv,log),"Unverified cleanup layouts");
    validate_block_geometry(backup);validate_block_geometry(reserved);
    require(backup.deviceMajor!=reserved.deviceMajor||backup.deviceMinor!=reserved.deviceMinor,"Cleanup targets alias the same block device");
    require(device_range(backup.bytes,0,nv.recordBytes)&&device_range(backup.bytes,nv.copyStride,nv.recordBytes),"NV copies exceed observed backup capacity");
    require(reserved.bytes>=log.tailOffset,"Log tail exceeds observed reserved capacity");
    uint64_t logOffset=reserved.bytes-log.tailOffset;
    require(device_range(reserved.bytes,logOffset,log.regionBytes),"Log region exceeds observed reserved capacity");
    // Buffered I/O accepts byte ranges. Do not infer record/offset alignment
    // from hardware sector size (e.g. a 2KiB NV record on a 4KiB device).
    return {backup,reserved,0,nv.copyStride,logOffset,nv.recordBytes,log.regionBytes};
}
inline void verify_geometry_stable(const CleanupGeometry& expected,const BlockGeometry& backup,const BlockGeometry& reserved) {
    validate_block_geometry(backup);validate_block_geometry(reserved);
    require(expected.backup==backup&&expected.reserved==reserved,"Cleanup block identity/capacity/logical sector changed");
}
inline void validate_cleanup_regions(const CleanupGeometry& geometry,const std::vector<Region>& regions) {
    require(regions.size()==3,"Cleanup transaction region count changed");
    const uint32_t targets[]={0,0,1};
    const uint64_t offsets[]={geometry.secondaryOffset,geometry.primaryOffset,geometry.logOffset};
    for(size_t i=0;i<regions.size();++i) {
        const auto& region=regions[i];uint64_t length=i==2?geometry.logBytes:geometry.nvBytes;
        require(region.target==targets[i]&&region.offset==offsets[i]&&region.before.size()==length&&region.after.size()==length
            &&device_range(region.target?geometry.reserved.bytes:geometry.backup.bytes,region.offset,length),"Cleanup region differs from verified device/layout geometry");
    }
}
} // namespace vrp
