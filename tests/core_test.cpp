#include "../src/core.hpp"
#include <fstream>
#include <iostream>
using namespace vrp;
static Bytes load(const std::string& path){std::ifstream f(path,std::ios::binary);require(bool(f),"input missing");return Bytes(std::istreambuf_iterator<char>(f),{});}
static void save(const std::string& path,const Bytes& data){std::ofstream f(path,std::ios::binary);f.write(reinterpret_cast<const char*>(data.data()),std::streamsize(data.size()));require(bool(f),"output failure");}
template<class F>static void rejects(F f){bool failed=false;try{f();}catch(...){failed=true;}require(failed,"unsafe input was accepted");}
static const NvLayout fixtureLayout{2048,0x6c,0x20c,4096};
static const MountLogLayout fixtureLogLayout{0x52734a6c,1,512,16384,49152,8,{12,16},24,24,48,12,60,452,1,4,1};
static void selftest(){
    unsigned gateCalls=0,createCalls=0,removeCalls=0,checks=0;bool owned=false;
    std::string raw="mount state:0";
    ProcViewOps ops{[&]{++gateCalls;},[&]{return raw;},[&]{return owned;},
        [&]{++removeCalls;owned=false;},[&]{++createCalls;owned=true;},
        [&]{++checks;return !underlying_root(raw)||owned;}};
    // Repeated watcher passes and the cleanup guard share this same policy.
    for(unsigned i=0;i<10;++i)require(maintain_proc_view(ops)=="natural","zero state must retain natural view");
    require(gateCalls==10&&createCalls==0&&removeCalls==0,"zero state caused a mount operation");
    raw="mount state:1";require(maintain_proc_view(ops)=="masked"&&createCalls==1&&owned,"rooted state was not protected");
    raw="mount state:0";require(maintain_proc_view(ops)=="natural"&&!owned&&removeCalls==1&&createCalls==1,"owned zero-state mask not removed");
    // A transition after the first read must activate the fallback in the
    // same pass; a mismatch from an unknown reader must not trigger a mount.
    unsigned reads=0;raw="mount state:0";ops.readUnderlying=[&]{return ++reads==1?"mount state:0":"mount state:1";};
    require(maintain_proc_view(ops)=="masked"&&createCalls==2,"state-transition race missed");
    ops.readUnderlying=[&]{return raw;};owned=false;ops.readersSeeZero=[] {return false;};
    rejects([&]{maintain_proc_view(ops);});require(createCalls==2,"zero-state reader mismatch created a mount");
    raw="unexpected";rejects([&]{maintain_proc_view(ops);});require(createCalls==2,"unknown state created a mount");
    raw="mount state:1";ops.applyMasks=[] {throw std::runtime_error("injected SELinux/mount failure");};
    rejects([&]{maintain_proc_view(ops);});
    require(hex(md5({}))=="d41d8cd98f00b204e9800998ecf8427e","MD5 empty vector");
    require(hex(md5({'a','b','c'}))=="900150983cd24fb0d6963f7d28e17f72","MD5 abc vector");
    require(hex(sha256({}))=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","SHA256 empty vector");
    require(hex(sha256({'a','b','c'}))=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","SHA256 abc vector");
    Bytes nv(2048);for(size_t i=0;i<nv.size();++i)nv[i]=uint8_t(i*37+11);put32(nv.data()+0x6c,1);auto hash=md5(Bytes(nv.begin(),nv.begin()+0x20c));std::copy(hash.begin(),hash.end(),nv.begin()+0x20c);
    auto clean=clear_nv(nv,fixtureLayout);require(valid_nv(clean,fixtureLayout)&&le32(clean.data()+0x6c)==0,"clean NV invalid");
    for(size_t i=0;i<nv.size();++i)if(!(i>=0x6c&&i<0x70)&&!(i>=0x20c&&i<0x21c))require(clean[i]==nv[i],"unrelated NV byte changed");
    auto invalid=nv;invalid[0x40]^=1;rejects([&]{clear_nv(invalid,fixtureLayout);});rejects([&]{clear_nv(Bytes(2047),fixtureLayout);});
    const NvLayout changedLayout{4096,128,768,8192};Bytes changedNv(changedLayout.recordBytes,0x5a);
    put32(changedNv.data()+changedLayout.rootOffset,1);auto changedDigest=md5(Bytes(changedNv.begin(),changedNv.begin()+changedLayout.digestOffset));
    std::copy(changedDigest.begin(),changedDigest.end(),changedNv.begin()+changedLayout.digestOffset);
    auto changedClean=clear_nv(changedNv,changedLayout);require(valid_nv(changedClean,changedLayout)&&le32(changedClean.data()+128)==0,"changed native layout was not used");
    for(size_t i=0;i<changedNv.size();++i)if(!(i>=128&&i<132)&&!(i>=768&&i<784))require(changedNv[i]==changedClean[i],"changed-layout unrelated byte altered");
    require(!valid_nv(changedNv,fixtureLayout),"wrong discovered layout accepted");
    require(!valid_cleanup_geometry({8192,128,768,8192},fixtureLogLayout)&&!valid_nv_layout({2048,800,768,4096})
        &&!valid_nv_layout({2048,128,768,1024}),"invalid/oversized NV journal geometry accepted");
    Bytes log(16384);put32(log.data(),0x52734a6c);put32(log.data()+4,1);put32(log.data()+12,0xffffffff);put32(log.data()+16,0xffffffff);
    auto encode=[](Bytes& target,size_t offset,const std::string& text){for(size_t i=0;i<text.size();++i){uint8_t b=uint8_t(text[i])^uint8_t(1+i%4);target[offset+i]=uint8_t((b<<1)|(b>>7));}};
    for(const std::string version:{"PD2505_A_16.0.21.8.W10","PD2505_A_16.0.22.27.W10","PD2505_A_16.0.24.7.W10",
            "PD2505_A_16.0.30.14.W10","PD2505_A_17.0.0.31.W10","FutureBuild"}){
        auto fixture=log;put32(fixture.data()+8,1);put32(fixture.data()+512,0x52734a6c);put32(fixture.data()+516,1);
        encode(fixture,512+0x18,version);encode(fixture,512+0x30,"mnt");encode(fixture,512+0x3c,"/data/adb/ksu/bin/busybox:busybox");
        auto cleared=clear_log(fixture,fixtureLogLayout);require(le32(cleared.data()+8)==0&&std::all_of(cleared.begin()+512,cleared.end(),[](uint8_t b){return b==0;}),"valid log metadata was treated as a schema gate");
        auto unknown=fixture;put32(unknown.data()+516,2);rejects([&]{clear_log(unknown,fixtureLogLayout);});
        unknown=fixture;std::fill(unknown.begin()+512+0x30,unknown.begin()+512+0x3c,0);encode(unknown,512+0x30,"other");rejects([&]{clear_log(unknown,fixtureLogLayout);});
        std::fill(fixture.begin()+512+0x18,fixture.begin()+512+0x30,0);rejects([&]{clear_log(fixture,fixtureLogLayout);});
        encode(fixture,512+0x18,"   ");rejects([&]{clear_log(fixture,fixtureLogLayout);});
        encode(fixture,512+0x18,std::string(1,'\x1f'));rejects([&]{clear_log(fixture,fixtureLogLayout);});
    }
    const MountLogLayout changedLogLayout{0x736f6d65,4,1024,8192,65536,12,{16,20},32,32,64,16,80,944,2,3,3};
    require(valid_mount_log_layout(changedLogLayout),"Changed log layout rejected");
    Bytes changedLog(changedLogLayout.regionBytes);put32(changedLog.data(),changedLogLayout.magic);put32(changedLog.data()+4,changedLogLayout.marker);
    put32(changedLog.data()+changedLogLayout.counterOffset,5);
    for(auto offset:changedLogLayout.sentinelOffsets)put32(changedLog.data()+offset,0xffffffff);
    changedLog[27]=0xa7;
    auto encodeChanged=[&](size_t offset,const std::string& text){for(size_t i=0;i<text.size();++i){uint8_t byte=uint8_t(text[i])^uint8_t(changedLogLayout.xorSeed+i%changedLogLayout.xorPeriod);
        changedLog[offset+i]=uint8_t((byte<<changedLogLayout.rotateLeft)|(byte>>(8-changedLogLayout.rotateLeft)));}};
    for(unsigned slot:{1u,7u}){size_t at=size_t(slot)*changedLogLayout.recordBytes;
        put32(changedLog.data()+at,changedLogLayout.magic);put32(changedLog.data()+at+4,changedLogLayout.marker);put32(changedLog.data()+at+changedLogLayout.counterOffset,slot==1?0:4);
        encodeChanged(at+changedLogLayout.firmwareOffset,"future-model");encodeChanged(at+changedLogLayout.eventOffset,"mnt");encodeChanged(at+changedLogLayout.messageOffset,"changed geometry and text codec");}
    auto changedLogClean=clear_log(changedLog,changedLogLayout);
    require(le32(changedLogClean.data()+changedLogLayout.counterOffset)==0&&std::all_of(changedLogClean.begin()+changedLogLayout.recordBytes,changedLogClean.end(),[](uint8_t b){return b==0;}),"Changed log geometry/codec was not used");
    for(size_t i=0;i<changedLogLayout.recordBytes;++i)if(i<changedLogLayout.counterOffset||i>=changedLogLayout.counterOffset+4)
        require(changedLogClean[i]==changedLog[i],"Unrelated log header bytes changed");
    auto invalidLogLayout=changedLogLayout;invalidLogLayout.xorPeriod=0;rejects([&]{clear_log(changedLog,invalidLogLayout);});
    invalidLogLayout=changedLogLayout;invalidLogLayout.rotateLeft=8;rejects([&]{clear_log(changedLog,invalidLogLayout);});
    invalidLogLayout=changedLogLayout;invalidLogLayout.sentinelOffsets[1]=0xfffffffc;require(!valid_mount_log_layout(invalidLogLayout),"Overflowing sentinel accepted");
    invalidLogLayout=changedLogLayout;invalidLogLayout.xorSeed=UINT32_MAX;require(!valid_mount_log_layout(invalidLogLayout),"Overflowing text key accepted");
    auto dynamicRegions=std::vector<Region>{{0,changedLayout.copyStride,changedNv,changedClean},{0,0,changedNv,changedClean},
        {1,10485760-changedLogLayout.tailOffset,changedLog,changedLogClean}};
    auto dynamicJournal=journal(dynamicRegions);require(parse_journal(dynamicJournal,10485760,changedLayout,changedLogLayout).size()==3,"Dynamic log/NV journal parse failed");
    rejects([&]{parse_journal(dynamicJournal,10485760,changedLayout,fixtureLogLayout);});
    auto regions=std::vector<Region>{{0,4096,nv,clean},{0,0,nv,clean},{1,10485760-49152,log,clear_log(log,fixtureLogLayout)}};
    auto encoded=journal(regions);require(parse_journal(encoded,10485760,fixtureLayout,fixtureLogLayout).size()==3,"journal parse");
    auto changedRegions=std::vector<Region>{{0,changedLayout.copyStride,changedNv,changedClean},{0,0,changedNv,changedClean},{1,10485760-49152,log,clear_log(log,fixtureLogLayout)}};
    require(parse_journal(journal(changedRegions),10485760,changedLayout,fixtureLogLayout).size()==3,"changed-layout journal parse");
    rejects([&]{parse_journal(journal(changedRegions),10485760,fixtureLayout,fixtureLogLayout);});
    auto broken=encoded;broken.back()^=1;rejects([&]{parse_journal(broken,10485760,fixtureLayout,fixtureLogLayout);});
    auto forbidden=regions;forbidden[0].offset=8192;rejects([&]{parse_journal(journal(forbidden),10485760,fixtureLayout,fixtureLogLayout);});
    forbidden=regions;forbidden[0].after[10]^=1;rejects([&]{parse_journal(journal(forbidden),10485760,fixtureLayout,fixtureLogLayout);});
    auto memory=std::vector<Bytes>{nv,nv,log};
    auto index=[](const Region& r){return r.target?2u:(r.offset?0u:1u);};
    auto read=[&](const Region& r){return memory[index(r)];};
    auto write=[&](const Region& r,const Bytes& b){memory[index(r)]=b;};
    transact(regions,read,write,[]{});require(memory[0]==clean&&memory[1]==clean,"commit incorrect");
    transact(regions,read,write,[]{},true);require(memory[0]==nv&&memory[1]==nv,"restore incorrect");
    bool inject=true;
    auto partial=[&](const Region& r,const Bytes& b){if(inject&&r.offset==0&&r.target==0){inject=false;std::copy(b.begin(),b.begin()+200,memory[index(r)].begin());throw std::runtime_error("injected partial block write");}write(r,b);};
    rejects([&]{transact(regions,read,partial,[]{});});require(memory[0]==nv&&memory[1]==nv,"partial write rollback failed");
    memory[1][32]^=1;unsigned writes=0;rejects([&]{transact(regions,read,[&](const Region&,const Bytes&){++writes;},[]{});});require(writes==0,"concurrent change should prevent writes");
    auto badLog=log;badLog[512+7]=1;rejects([&]{clear_log(badLog,fixtureLogLayout);});
    rejects([&]{avb_names(Bytes(15));});
    std::cout<<"core tests passed: conditional proc view, races, mount refusal, crypto, NV preservation, journals, allowlist, commit/restore, partial-write rollback, concurrent-change refusal, log refusal\n";
}
int main(int argc,char** argv){try{if(argc==1){selftest();return 0;}require(argc>=3,"arguments");std::string cmd=argv[1];auto data=load(argv[2]);if(cmd=="hash")std::cout<<hex(md5(data))<<"\n"<<hex(sha256(data))<<"\n";else if(cmd=="clear-nv"&&argc==4)save(argv[3],clear_nv(data,fixtureLayout));else if(cmd=="clear-log"&&argc==4)save(argv[3],clear_log(data,fixtureLogLayout));else if(cmd=="avb"){
    require(data.size()>=256&&std::string(data.begin(),data.begin()+4)=="AVB0","AVB header");uint64_t at=256+be64(data.data()+12)+be64(data.data()+96),len=be64(data.data()+104);require(at<=data.size()&&len<=data.size()-at,"AVB bounds");for(auto& n:avb_names(Bytes(data.begin()+at,data.begin()+at+len)))std::cout<<n.name<<"\n";
    }else throw std::runtime_error("bad command");return 0;}catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}}
