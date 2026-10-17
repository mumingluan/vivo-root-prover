#define _GNU_SOURCE 1
#include "core.hpp"
#include "native_layout.hpp"
#include "kernel_log_layout.hpp"
#include "vendor_ramdisk.hpp"
#include "hal_contract.hpp"
#include "hal_process.hpp"
#include "block_geometry.hpp"
#include "watch_wait.hpp"
#include <cerrno>
#include <chrono>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <linux/fs.h>
#include <linux/magic.h>
#include <sched.h>
#include <set>
#include <signal.h>
#include <sstream>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>
#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif

using namespace vrp;
static const std::string STATE="/data/adb/vivo-root-prover";
static const char* NODE="/proc/isroot/isroot";
static const char* HAL="/vendor/bin/hw/vendor.factory.hardware.vivoem-service";
static const char* LIB="/vendor/lib64/hw/vendor.factory.hardware.vivoem-impl.so";
static const char* FACTORY="/vendor/lib64/libvivofactory.so";
struct HalSource {HalImageIdentity identity;std::string sha256;};
struct HalRuntime {HalDiscovery plan;std::vector<HalSource> images;};
struct KernelRuntime {KernelControlPlan control;KernelLogPlan log;std::string source,moduleSha256;};
static const KernelRuntime& kernelRuntime();
static void verifyKernelIdentity();

static volatile sig_atomic_t stopRequested=0;
static void stopSignal(int){stopRequested=1;}
static std::string error(const std::string& message){return message+": "+strerror(errno);}
struct FD {
    int fd=-1;
    explicit FD(int v=-1):fd(v){}
    ~FD(){if(fd>=0)close(fd);}
    FD(const FD&)=delete;FD& operator=(const FD&)=delete;
};
static Bytes readAt(int fd,uint64_t offset,size_t size) {
    require(size<=32*1024*1024&&file_range(offset,size),"read range exceeds bounds");Bytes out(size);size_t done=0;
    while(done<size){ssize_t n=pread(fd,out.data()+done,size-done,off_t(offset+done));if(n<0&&errno==EINTR)continue;require(n>0,error("short read"));done+=size_t(n);}return out;
}
static void writeAt(int fd,uint64_t offset,const Bytes& bytes) {
    require(file_range(offset,bytes.size()),"write range exceeds signed file offset space");
    size_t done=0;while(done<bytes.size()){ssize_t n=pwrite(fd,bytes.data()+done,bytes.size()-done,off_t(offset+done));if(n<0&&errno==EINTR)continue;require(n>0,error("short write"));done+=size_t(n);}
}
static std::string textFile(const std::string& path) {
    FD f(open(path.c_str(),O_RDONLY|O_CLOEXEC));require(f.fd>=0,error("open "+path));
    std::string out;char buf[4096];ssize_t n;
    while((n=read(f.fd,buf,sizeof(buf)))>0){require(out.size()+size_t(n)<=1024*1024,"text input too large");out.append(buf,size_t(n));}
    require(n==0,error("read "+path));return out;
}
static Bytes fileBytes(const std::string& path,size_t maximum) {
    FD f(open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW));require(f.fd>=0,error("open "+path));
    struct stat s{};require(fstat(f.fd,&s)==0&&S_ISREG(s.st_mode)&&s.st_size>=0&&uint64_t(s.st_size)<=maximum,"invalid regular file "+path);
    return readAt(f.fd,0,size_t(s.st_size));
}
static const NvLayout& nvLayout() {
    static const NvLayout layout=discover_factory_layout(fileBytes(FACTORY,16*1024*1024)).layout;
    require(valid_nv_layout(layout),"discovered NV layout failed range validation");return layout;
}
static std::pair<Bytes,HalSource> captureHalSource(const std::string& path,size_t maximum) {
    FD fd(open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW));require(fd.fd>=0,error("open HAL source "+path));struct stat info{};
    require(fstat(fd.fd,&info)==0&&S_ISREG(info.st_mode)&&info.st_size>0&&uint64_t(info.st_size)<=maximum,"Invalid HAL source file");
    auto bytes=readAt(fd.fd,0,size_t(info.st_size));HalSource source{{path,uint64_t(info.st_ino),uint32_t(major(info.st_dev)),uint32_t(minor(info.st_dev))},hex(sha256(bytes))};
    return {std::move(bytes),std::move(source)};
}
static const HalRuntime& halRuntime() {
    static const HalRuntime runtime=[](){
        auto service=captureHalSource(HAL,8*1024*1024),implementation=captureHalSource(LIB,32*1024*1024),factory=captureHalSource(FACTORY,16*1024*1024);
        HalRuntime result;result.plan=discover_hal_contract(service.first,implementation.first,factory.first,nvLayout());
        result.images={std::move(service.second),std::move(implementation.second),std::move(factory.second)};return result;
    }();return runtime;
}
static void verifyHalIdentity() {
    for(const auto& expected:halRuntime().images){auto current=captureHalSource(expected.identity.path,32*1024*1024);
        require(current.second.identity==expected.identity&&current.second.sha256==expected.sha256,"HAL/NV image changed after contract discovery");}
}
static void verifyHalProcessImages(pid_t pid) {
    std::vector<HalImageIdentity> expected;for(const auto& image:halRuntime().images)expected.push_back(image.identity);
    verify_hal_image_mappings(textFile("/proc/"+std::to_string(pid)+"/maps"),expected);
}
static std::string trim(std::string s){while(!s.empty()&&(s.back()=='\n'||s.back()=='\r'))s.pop_back();return s;}
static std::string jsonQuote(const std::string& s){std::string out="\"";for(unsigned char c:s){if(c=='"'||c=='\\'){out+='\\';out+=char(c);}else if(c=='\n')out+="\\n";else if(c>=32)out+=char(c);}return out+'"';}
static void secureDir(const std::string& path) {
    if(mkdir(path.c_str(),0700)<0)require(errno==EEXIST,error("mkdir "+path));
    struct stat s{};require(lstat(path.c_str(),&s)==0&&S_ISDIR(s.st_mode)&&s.st_uid==0,"unsafe state directory "+path);
    require(chmod(path.c_str(),0700)==0,error("chmod state"));
}
static void initState(){secureDir(STATE);secureDir(STATE+"/snapshots");}
static void saveExclusive(const std::string& path,const Bytes& bytes,mode_t mode=0400) {
    FD f(open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,mode));require(f.fd>=0,error("create "+path));
    writeAt(f.fd,0,bytes);require(fsync(f.fd)==0,error("sync snapshot"));
    FD parent(open(STATE.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC));require(parent.fd>=0&&fsync(parent.fd)==0,error("sync state directory"));
    FD snapshots(open((STATE+"/snapshots").c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC));require(snapshots.fd>=0&&fsync(snapshots.fd)==0,error("sync snapshots directory"));
}
static void profile() {
    require(geteuid()==0,"root required");struct utsname u{};require(uname(&u)==0,"uname failed");
    require(std::string(u.machine)=="aarch64","unsupported machine architecture");
    verifyKernelIdentity();
    verifyHalIdentity();
    require(valid_cleanup_geometry(nvLayout(),kernelRuntime().log.layout),"NV/log geometry exceeds transaction bounds");
    auto modules=textFile("/proc/modules");require(modules.rfind("vr ",0)==0||modules.find("\nvr ")!=std::string::npos,"vr kernel module not found");
}
static std::string property(const char* name) {
#ifdef __ANDROID__
    char value[PROP_VALUE_MAX]{};__system_property_get(name,value);return value;
#else
    (void)name;return "";
#endif
}
static bool setZeroProperty(const char* name) {
    if(property(name)=="0")return true;
    static const char* candidates[]={"/data/adb/ksu/bin/resetprop","/data/adb/magisk/resetprop"};
    for(auto path:candidates){if(access(path,X_OK))continue;pid_t p=fork();require(p>=0,"fork resetprop failed");
        if(p==0){execl(path,path,"-n",name,"0",static_cast<char*>(nullptr));_exit(127);}
        int s=0;while(waitpid(p,&s,0)<0&&errno==EINTR){}if(WIFEXITED(s)&&WEXITSTATUS(s)==0&&property(name)=="0")return true;
    }
    // Do not call blocking setprop from post-fs-data or directly edit persistent-property storage.
    return false;
}
static void zeroProperties(){require(setZeroProperty("persist.sys.is_root"),"resetprop unavailable or root property override failed");if(!property("recovery.state.root").empty())require(setZeroProperty("recovery.state.root"),"recovery property override failed");}
static std::string linkPath(const std::string& path){char b[4096];ssize_t n=readlink(path.c_str(),b,sizeof(b));return n<0?"":std::string(b,size_t(n));}
static bool isHalImage(const std::string& image){static const std::string deleted=std::string(HAL)+" (deleted)";return image==HAL||image==deleted;}
static void verifyHalPid(pid_t pid){require(isHalImage(linkPath("/proc/"+std::to_string(pid)+"/exe")),"HAL process changed during guard pass");}
static std::vector<pid_t> halPids(){std::vector<pid_t> pids;DIR* d=opendir("/proc");require(d,"open proc failed");while(auto ent=readdir(d)){char* end=nullptr;long p=strtol(ent->d_name,&end,10);if(!*ent->d_name||*end||p<=1)continue;auto image=linkPath(std::string("/proc/")+ent->d_name+"/exe");if(isHalImage(image))pids.push_back(pid_t(p));}closedir(d);std::sort(pids.begin(),pids.end());return pids;}
static void enterInitNamespace(){FD init(open("/proc/1/ns/mnt",O_RDONLY|O_CLOEXEC));require(init.fd>=0,error("open init mount namespace"));require(setns(init.fd,CLONE_NEWNS)==0,error("enter init mount namespace"));}
static bool ownMask(const std::string& target=NODE){struct stat a{},b{};return stat(target.c_str(),&a)==0&&stat((STATE+"/mount-state-zero").c_str(),&b)==0&&a.st_dev==b.st_dev&&a.st_ino==b.st_ino;}
static std::string nodeRead(int fd){require(lseek(fd,0,SEEK_SET)>=0,error("seek proc node"));char b[64]{};ssize_t n=read(fd,b,63);require(n>0,error("read proc node"));return std::string(b,size_t(n));}
static int originalNode() {
    if(!ownMask()){
        int fd=open(NODE,O_RDWR|O_CLOEXEC);require(fd>=0,error("open vr control node"));
        struct statfs fs{};if(fstatfs(fd,&fs)||fs.f_type!=PROC_SUPER_MAGIC){close(fd);throw std::runtime_error("proc node belongs to an unknown overlay");}return fd;
    }
    FD saved(open("/proc/self/ns/mnt",O_RDONLY|O_CLOEXEC));require(saved.fd>=0,"save namespace failed");
    require(unshare(CLONE_NEWNS)==0,error("private namespace for underlying proc"));
    int fd=-1;
    try{require(mount(nullptr,"/",nullptr,MS_REC|MS_PRIVATE,nullptr)==0,error("make temporary namespace private"));require(umount2(NODE,MNT_DETACH)==0,error("detach temporary mask"));fd=open(NODE,O_RDWR|O_CLOEXEC);require(fd>=0,error("open underlying proc"));struct statfs fs{};require(fstatfs(fd,&fs)==0&&fs.f_type==PROC_SUPER_MAGIC,"underlying node is not procfs");}
    catch(...){if(fd>=0)close(fd);if(setns(saved.fd,CLONE_NEWNS))_exit(70);throw;}
    if(setns(saved.fd,CLONE_NEWNS)){close(fd);_exit(70);}return fd;
}
static void gates(int fd){verifyKernelIdentity();auto value=trim(nodeRead(fd));require(value=="mount state:0"||value=="mount state:1","unknown proc control format");
    for(const auto& control:kernelRuntime().control.controls){std::string command=control.disable.command+'\n';
        require(write(fd,command.data(),command.size())==ssize_t(command.size()),error("vr control command rejected"));}}
static void makeMask(int original){auto path=STATE+"/mount-state-zero";if(access(path.c_str(),F_OK)!=0){Bytes b={'m','o','u','n','t',' ','s','t','a','t','e',':','0','\n'};saveExclusive(path,b,0444);}require(textFile(path)=="mount state:0\n","mask source changed");struct stat s{};require(lstat(path.c_str(),&s)==0&&S_ISREG(s.st_mode)&&s.st_uid==0,"unsafe mask source");require(chmod(path.c_str(),0444)==0,"mask chmod failed");
    // Copy the actual proc node's SELinux label to this /data file. Do not
    // make SELinux permissive or ship broad allow rules for vendor services.
    char label[512]{};ssize_t n=fgetxattr(original,"security.selinux",label,sizeof(label));require(n>0&&n<ssize_t(sizeof(label)),error("read original proc SELinux label"));
    FD source(open(path.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC));require(source.fd>=0,"open mask source failed");char current[512]{};ssize_t have=fgetxattr(source.fd,"security.selinux",current,sizeof(current));
    if(have!=n||memcmp(current,label,size_t(n)))require(fsetxattr(source.fd,"security.selinux",label,size_t(n),0)==0,error("set mask SELinux label"));
    memset(current,0,sizeof(current));have=fgetxattr(source.fd,"security.selinux",current,sizeof(current));require(have==n&&!memcmp(current,label,size_t(n)),"mask SELinux label readback mismatch");
}
static void mountMask(){if(ownMask())return;require(mount((STATE+"/mount-state-zero").c_str(),NODE,nullptr,MS_BIND,nullptr)==0,error("bind proc read view"));if(mount(nullptr,NODE,nullptr,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,nullptr)){int saved=errno;umount2(NODE,MNT_DETACH);errno=saved;throw std::runtime_error(error("remount proc view readonly"));}require(ownMask()&&trim(textFile(NODE))=="mount state:0","proc view verification failed");}
static bool halViewsZero(const std::vector<pid_t>& pids=halPids()){for(auto p:pids){try{verifyHalPid(p);if(trim(textFile("/proc/"+std::to_string(p)+"/root/proc/isroot/isroot"))!="mount state:0")return false;}catch(...){return false;}}return true;}
static void maskHalNamespaces(const std::vector<pid_t>& pids=halPids()){
    std::set<std::string> visited;visited.insert(linkPath("/proc/self/ns/mnt"));
    for(auto p:pids){
        verifyHalPid(p);
        auto ns="/proc/"+std::to_string(p)+"/ns/mnt";auto name=linkPath(ns);
        if(name.empty()||!visited.insert(name).second)continue;
        pid_t child=fork();require(child>=0,"fork namespace helper failed");
        if(!child){try{FD fd(open(ns.c_str(),O_RDONLY|O_CLOEXEC));require(fd.fd>=0&&setns(fd.fd,CLONE_NEWNS)==0,"HAL namespace unavailable");mountMask();_exit(0);}catch(...){_exit(1);}}
        int status=0;while(waitpid(child,&status,0)<0&&errno==EINTR){}
        require(WIFEXITED(status)&&WEXITSTATUS(status)==0,"HAL namespace mask failed");
    }
    require(halViewsZero(pids),"HAL still sees a root signal");
}
static bool hasOwnedMasks(const std::vector<pid_t>& pids=halPids()){
    if(ownMask())return true;
    for(auto pid:pids){verifyHalPid(pid);if(ownMask("/proc/"+std::to_string(pid)+"/root/proc/isroot/isroot"))return true;}
    return false;
}
static void removeOwnedMasks(const std::vector<pid_t>& pids=halPids()){
    if(ownMask())require(umount2(NODE,MNT_DETACH)==0,error("remove owned proc mask"));
    for(auto pid:pids){
        verifyHalPid(pid);
        auto view="/proc/"+std::to_string(pid)+"/root/proc/isroot/isroot";
        if(!ownMask(view))continue;
        FD ns(open(("/proc/"+std::to_string(pid)+"/ns/mnt").c_str(),O_RDONLY|O_CLOEXEC));
        require(ns.fd>=0&&setns(ns.fd,CLONE_NEWNS)==0,"enter HAL namespace for unmask failed");
        try{if(ownMask())require(umount2(NODE,MNT_DETACH)==0,"HAL unmask failed");}catch(...){enterInitNamespace();throw;}
        enterInitNamespace();
    }
}
static std::string guard(int fd,const std::vector<pid_t>& pids=halPids()){
    ProcViewOps ops{
        [&]{gates(fd);},[&]{return trim(nodeRead(fd));},
        [&]{return hasOwnedMasks(pids);},[&]{removeOwnedMasks(pids);},
        [&]{makeMask(fd);mountMask();maskHalNamespaces(pids);},
        [&]{return trim(textFile(NODE))=="mount state:0"&&halViewsZero(pids);}
    };
    auto mode=maintain_proc_view(ops);zeroProperties();return mode;
}
static uint64_t deviceSize(int fd){struct stat s{};require(fstat(fd,&s)==0&&S_ISBLK(s.st_mode),"target is not a block device");uint64_t size=0;require(ioctl(fd,BLKGETSIZE64,&size)==0,"block size ioctl failed");return size;}
static BlockGeometry observeDevice(int fd){
    struct stat info{};require(fstat(fd,&info)==0&&S_ISBLK(info.st_mode),"Cleanup target is not a block device");
    uint64_t size=0;int sector=0;require(ioctl(fd,BLKGETSIZE64,&size)==0&&ioctl(fd,BLKSSZGET,&sector)==0&&sector>0,"Cleanup block geometry ioctl failed");
    BlockGeometry value{size,uint32_t(sector),uint32_t(major(info.st_rdev)),uint32_t(minor(info.st_rdev))};validate_block_geometry(value);return value;
}
static int openDevice(const char* name,bool writable){std::string path="/dev/block/by-name/"+std::string(name);int f=open(path.c_str(),(writable?O_RDWR:O_RDONLY)|O_CLOEXEC);require(f>=0,error("open "+path));try{(void)deviceSize(f);}catch(...){close(f);throw;}return f;}
static Bytes loadedKernelNote(){auto value=textFile("/sys/module/vr/notes/.note.gnu.build-id");
    require(value.size()>=16&&value.size()<=128,"Loaded vr build-id note unavailable/invalid");return Bytes(value.begin(),value.end());}
static const KernelRuntime& kernelRuntime(){
    static const KernelRuntime runtime=[](){
        Bytes loaded=loadedKernelNote();
        auto discover=[&](Bytes bytes,const std::string& source){std::string digest=hex(sha256(bytes));KernelModule module(std::move(bytes));
            require(module.buildIdNote()==loaded,"vr module file does not match loaded build-id");
            KernelRuntime result;result.control=discoverKernelControls(module);result.log=discoverKernelLogLayout(module);result.source=source;result.moduleSha256=digest;return result;};
        std::string reason="No readable vr module file";
        for(const char* source:{"/lib/modules/vr.ko","/vendor/lib/modules/vr.ko","/vendor_dlkm/lib/modules/vr.ko"}){
            if(access(source,R_OK)!=0)continue;
            try{return discover(fileBytes(source,32*1024*1024),source);}catch(const std::exception& failure){reason=failure.what();}
        }
        try{std::string slot=property("ro.boot.slot_suffix");require(slot=="_a"||slot=="_b","Unknown active vendor_boot slot");
            std::string name="vendor_boot"+slot;FD image(openDevice(name.c_str(),false));
            auto module=vrModuleFromVendorBoot(deviceSize(image.fd),[&](uint64_t offset,size_t count){return readAt(image.fd,offset,count);});
            return discover(std::move(module),"/dev/block/by-name/"+name);
        }catch(const std::exception& failure){throw std::runtime_error("No verified loaded vr module: "+reason+"; "+failure.what());}
    }();return runtime;
}
static void verifyKernelIdentity(){require(kernelRuntime().control.buildIdNote==loadedKernelNote(),"Loaded vr module identity changed");}
// Parse the current AVB descriptor graph before enabling any block-device write.
static void avbWalk(const std::string& name,const std::string& slot,std::set<std::string>& visited,std::set<std::string>& partitions,unsigned depth){
    require(depth<24&&visited.size()<32,"AVB graph exceeds bound");if(!visited.insert(name).second)return;
    std::string path="/dev/block/by-name/"+name;FD fd(open(path.c_str(),O_RDONLY|O_CLOEXEC));require(fd.fd>=0,error("AVB chain partition missing "+name));uint64_t size=deviceSize(fd.fd),base=0;
    auto header=readAt(fd.fd,0,256);if(memcmp(header.data(),"AVB0",4)!=0){require(size>=64,"AVB partition too small");auto footer=readAt(fd.fd,size-64,64);require(memcmp(footer.data(),"AVBf",4)==0,"AVB footer missing "+name);base=be64(footer.data()+20);auto length=be64(footer.data()+28);require(length>=256&&length<=16*1024*1024&&base<=size-length,"AVB footer range invalid");header=readAt(fd.fd,base,256);}
    require(memcmp(header.data(),"AVB0",4)==0&&be32(header.data()+120)==0,"AVB metadata missing or verification disabled");
    uint64_t auth=be64(header.data()+12),aux=be64(header.data()+20),offset=be64(header.data()+96),length=be64(header.data()+104);
    require(auth<=16*1024*1024&&aux<=16*1024*1024&&offset<=aux&&length<=aux-offset&&base<=size-256&&auth<=size-base-256&&aux<=size-base-256-auth,"AVB descriptor range invalid");
    auto descriptors=readAt(fd.fd,base+256+auth+offset,size_t(length));
    for(const auto& descriptor:avb_names(descriptors)){
        const auto& partition=descriptor.name;partitions.insert(partition);
        if(descriptor.tag==4){std::string next=partition+slot;if(access(("/dev/block/by-name/"+next).c_str(),F_OK)!=0)next=partition;avbWalk(next,slot,visited,partitions,depth+1);}
    }
}
static void verifyAvb(){auto slot=property("ro.boot.slot_suffix");require(slot=="_a"||slot=="_b","unknown active slot");std::set<std::string> visited,partitions;avbWalk("vbmeta"+slot,slot,visited,partitions,0);require(visited.size()>=4&&partitions.count("boot")&&partitions.count("system")&&partitions.count("vendor_boot"),"AVB graph incomplete");for(auto name:{"backup","reserved","backup_a","backup_b","reserved_a","reserved_b"})require(!partitions.count(name),"cleanup target is AVB protected");}
struct PausedHal {
    std::vector<int> fds;
    std::vector<pid_t> captured;
    int watchdogPipe=-1;pid_t watchdogPid=-1;
    PausedHal(){try{captured=halPids();for(auto pid:captured){verifyHalProcessImages(pid);auto state=textFile("/proc/"+std::to_string(pid)+"/status");require(state.find("\nState:\tT")==std::string::npos&&state.find("\nState:\tt")==std::string::npos,"HAL already externally stopped");int fd=int(syscall(SYS_pidfd_open,pid,0));require(fd>=0,error("pidfd_open HAL"));if(syscall(SYS_pidfd_send_signal,fd,SIGSTOP,nullptr,0)){close(fd);throw std::runtime_error(error("pause HAL"));}fds.push_back(fd);bool stopped=false;for(int i=0;i<50;++i){auto status=textFile("/proc/"+std::to_string(pid)+"/status");if(status.find("\nState:\tT")!=std::string::npos){stopped=true;break;}usleep(2000);}require(stopped,"HAL pause timed out");}
        if(!fds.empty()){int pipefd[2];require(pipe2(pipefd,O_CLOEXEC)==0,"create HAL recovery watchdog failed");watchdogPid=fork();if(watchdogPid<0){close(pipefd[0]);close(pipefd[1]);throw std::runtime_error("fork HAL recovery watchdog failed");}
            if(watchdogPid==0){close(pipefd[1]);char done=0;ssize_t n;do{n=read(pipefd[0],&done,1);}while(n<0&&errno==EINTR);if(n!=1||done!='D')for(auto fd:fds)syscall(SYS_pidfd_send_signal,fd,SIGCONT,nullptr,0);_exit(0);}
            close(pipefd[0]);watchdogPipe=pipefd[1];}
    }catch(...){resume();throw;}}
    void verifyStable(){require(captured==halPids()&&captured.size()==fds.size(),"HAL process set changed before transaction");
        for(size_t i=0;i<captured.size();i++){require(syscall(SYS_pidfd_send_signal,fds[i],0,nullptr,0)==0,"Paused HAL exited before transaction");
            auto status=textFile("/proc/"+std::to_string(captured[i])+"/status");require(status.find("\nState:\tT")!=std::string::npos,"HAL resumed before transaction");verifyHalProcessImages(captured[i]);}}
    void resume(){for(auto fd:fds){syscall(SYS_pidfd_send_signal,fd,SIGCONT,nullptr,0);close(fd);}fds.clear();if(watchdogPipe>=0){char done='D';(void)write(watchdogPipe,&done,1);close(watchdogPipe);watchdogPipe=-1;}if(watchdogPid>0){int status=0;while(waitpid(watchdogPid,&status,0)<0&&errno==EINTR){}watchdogPid=-1;}}
    ~PausedHal(){resume();}
};
static void cleanup(const std::string& restoreName,bool recover=false){profile();verifyAvb();enterInitNamespace();initState();FD lock(open((STATE+"/transaction.lock").c_str(),O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600));require(lock.fd>=0&&flock(lock.fd,LOCK_EX|LOCK_NB)==0,"another cleanup is running");FD node(originalNode());guard(node.fd);const auto& layout=nvLayout();const auto& logLayout=kernelRuntime().log.layout;
    require(trim(textFile(NODE))=="mount state:0"&&halViewsZero()&&
            (!underlying_root(trim(nodeRead(node.fd)))||ownMask()),
            "cleanup requires verified zero proc and HAL views");
    // Give a detector that read the old signal before masking time to finish.
    // This is a bounded quiescence check, not proof that every unknown OEM
    // writer has been intercepted. Never auto-clean records during boot.
    FD backup(openDevice("backup",false)),reserved(openDevice("reserved",false));
    const auto geometry=cleanup_geometry(observeDevice(backup.fd),observeDevice(reserved.fd),layout,logLayout);
    auto verifyReadGeometry=[&](){verify_geometry_stable(geometry,observeDevice(backup.fd),observeDevice(reserved.fd));};
    {auto a=readAt(backup.fd,geometry.primaryOffset,geometry.nvBytes),b=readAt(backup.fd,geometry.secondaryOffset,geometry.nvBytes);
        std::cout<<"stage=waiting_for_NV_quiescence\n"<<std::flush;
        for(unsigned i=0;i<3;++i){sleep(2);require(!stopRequested,"cleanup cancelled before device writes");require(halViewsZero(),"HAL root view changed during quiescence");verifyReadGeometry();auto nextA=readAt(backup.fd,geometry.primaryOffset,geometry.nvBytes),nextB=readAt(backup.fd,geometry.secondaryOffset,geometry.nvBytes);require(a==nextA&&b==nextB,"NV changed during quiescence; retry after reviewing status");}}
    PausedHal pause;
    verifyReadGeometry();
    std::vector<Region> regions;
    std::string snapshot;
    if(restoreName.empty()){
        auto primary=readAt(backup.fd,geometry.primaryOffset,geometry.nvBytes),secondary=readAt(backup.fd,geometry.secondaryOffset,geometry.nvBytes);
        require(primary==secondary,"NV copies disagree: manual review required");auto p=clear_nv(primary,layout),s=clear_nv(secondary,layout);
        auto before=readAt(reserved.fd,geometry.logOffset,geometry.logBytes),after=clear_log(before,logLayout);
        regions={{0,geometry.secondaryOffset,secondary,s},{0,geometry.primaryOffset,primary,p},{1,geometry.logOffset,before,after}};
        validate_cleanup_regions(geometry,regions);
        auto ticks=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();snapshot="snapshot-"+std::to_string(ticks)+".vrpj";saveExclusive(STATE+"/snapshots/"+snapshot,journal(regions));
    }else{
        require(restoreName.size()<80&&restoreName.rfind("snapshot-",0)==0&&restoreName.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-.")==std::string::npos&&restoreName.find("..") ==std::string::npos,"invalid snapshot name");snapshot=restoreName;regions=parse_journal(fileBytes(STATE+"/snapshots/"+snapshot,65535),geometry.reserved.bytes,layout,logLayout);
    }
    validate_cleanup_regions(geometry,regions);
    // No writable device is opened until the profile, descriptor graph, all
    // formats, masks and durable journal have been checked.
    require(!stopRequested,"cleanup cancelled before device writes");verifyKernelIdentity();verifyHalIdentity();pause.verifyStable();verifyReadGeometry();
    FD writeBackup(openDevice("backup",true)),writeReserved(openDevice("reserved",true));
    auto verifyWriteGeometry=[&](){verifyReadGeometry();verify_geometry_stable(geometry,observeDevice(writeBackup.fd),observeDevice(writeReserved.fd));};
    verifyWriteGeometry();
    auto read=[&](const Region& r){verifyWriteGeometry();return readAt(r.target?writeReserved.fd:writeBackup.fd,r.offset,r.before.size());};
    auto write=[&](const Region& r,const Bytes& bytes){verifyWriteGeometry();writeAt(r.target?writeReserved.fd:writeBackup.fd,r.offset,bytes);};
    auto sync=[&](){require(fdatasync(writeBackup.fd)==0&&fdatasync(writeReserved.fd)==0,error("sync devices"));};
    std::cout<<"snapshot="<<snapshot<<"\nstage=prepared\n"<<std::flush;
    if(recover){
        for(auto& r:regions){auto current=read(r);for(size_t i=0;i<current.size();++i)require(current[i]==r.before[i]||current[i]==r.after[i],"recovery found unrelated data changes; refusing overwrite");r.after=r.before;r.before=current;}
        transact(regions,read,write,sync);
    }else transact(regions,read,write,sync,!restoreName.empty());
    pause.resume();zeroProperties();std::cout<<"operation="<<(recover?"recover":restoreName.empty()?"clean":"restore")<<"\nresult=verified\n";
}
static void status(){bool supported=false;std::string reason;try{profile();supported=true;}catch(const std::exception& e){reason=e.what();}
    std::cout<<"{\n  \"profile_supported\": "<<(supported?"true":"false")<<",\n  \"profile_reason\": "<<jsonQuote(reason)<<",\n";
    auto report=[](const char* key,const std::string& path){std::string value;try{value=trim(textFile(path));}catch(const std::exception& e){value=e.what();}std::cout<<"  "<<jsonQuote(key)<<": "<<jsonQuote(value)<<",\n";};
    report("proc_visible",NODE);report("guard_state",STATE+"/guard-status.txt");std::cout<<"  \"proc_mask_owned\": "<<(ownMask()?"true":"false")<<",\n  \"persist.sys.is_root\": "<<jsonQuote(property("persist.sys.is_root"))<<",\n  \"recovery.state.root\": "<<jsonQuote(property("recovery.state.root"))<<",\n";
    try{const auto& layout=nvLayout();std::cout<<"  \"nv_layout\": {\"record_bytes\":"<<layout.recordBytes<<",\"root_offset\":"<<layout.rootOffset<<",\"digest_offset\":"<<layout.digestOffset<<",\"copy_stride\":"<<layout.copyStride<<"},\n";
        FD f(openDevice("backup",false));auto a=readAt(f.fd,0,layout.recordBytes),b=readAt(f.fd,layout.copyStride,layout.recordBytes);std::cout<<"  \"nv_root\": ["<<le32(a.data()+layout.rootOffset)<<","<<le32(b.data()+layout.rootOffset)<<"],\n  \"nv_checksums_valid\": "<<(valid_nv(a,layout)&&valid_nv(b,layout)?"true":"false")<<",\n";}catch(const std::exception& e){std::cout<<"  \"nv_error\": "<<jsonQuote(e.what())<<",\n";}
    try{const auto& kernel=kernelRuntime();const auto& layout=kernel.log.layout;
        std::cout<<"  \"kernel_module_source\": "<<jsonQuote(kernel.source)<<",\n  \"kernel_module_sha256\": "<<jsonQuote(kernel.moduleSha256)<<",\n"
            <<"  \"mount_log_layout\": {\"record_bytes\":"<<layout.recordBytes<<",\"region_bytes\":"<<layout.regionBytes<<",\"tail_offset\":"<<layout.tailOffset<<"},\n";
        FD f(openDevice("reserved",false));auto size=deviceSize(f.fd);require(size>=layout.tailOffset,"reserved too small");
        auto region=readAt(f.fd,size-layout.tailOffset,layout.regionBytes);(void)clear_log(region,layout);std::cout<<"  \"mount_log_count\": "<<le32(region.data()+layout.counterOffset)<<",\n";
    }catch(const std::exception& e){std::cout<<"  \"mount_log_error\": "<<jsonQuote(e.what())<<",\n";}
    try{const auto& hal=halRuntime();std::cout<<"  \"hal_contract\": {\"root_offset\":"<<hal.plan.rootOffset<<",\"payload_bytes\":"<<hal.plan.bufferBytes<<",\"target_hash_whitelist\":false},\n";
        for(size_t i=0;i<hal.images.size();i++)std::cout<<"  \"hal_source_sha256_"<<i<<"\": "<<jsonQuote(hal.images[i].sha256)<<",\n";
    }catch(const std::exception& e){std::cout<<"  \"hal_contract_error\": "<<jsonQuote(e.what())<<",\n";}
    std::cout<<"  \"status_command_phone_writes\": false\n}\n";
}
static void watch(const std::string& module){profile();initState();FD lock(open((STATE+"/guard.lock").c_str(),O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600));require(lock.fd>=0,"open guard lock failed");if(flock(lock.fd,LOCK_EX|LOCK_NB))return;require(module.rfind("/data/adb/modules/",0)==0&&module.find("..") ==std::string::npos,"unexpected module path");
    FD pidFile(open((STATE+"/guard.pid").c_str(),O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600));require(pidFile.fd>=0,"write guard PID failed");auto pidText=std::to_string(getpid())+"\n";writeAt(pidFile.fd,0,Bytes(pidText.begin(),pidText.end()));
    enterInitNamespace();FD node(originalNode());signal(SIGTERM,stopSignal);signal(SIGINT,stopSignal);unsigned step=0;
    std::string writtenStatus;bool statusWritten=false;const auto statusPath=STATE+"/guard-status.txt";
    while(!stopRequested&&access((module+"/disable").c_str(),F_OK)&&access((module+"/remove").c_str(),F_OK)){
        // A fresh PID snapshot for every pass; never retain it across intervals.
        std::string result;try{const auto pids=halPids();auto mode=guard(node.fd,pids);result="protection=active\nproc_view_mode="+mode+"\ngates=commands_accepted_not_independently_observable\nunderlying_proc="+trim(nodeRead(node.fd))+"\nvisible_proc="+trim(textFile(NODE))+"\nHAL_views_zero="+(halViewsZero(pids)?"true":"false")+"\n";}catch(const std::exception& e){result="protection=degraded\nreason="+std::string(e.what())+"\n";}
        // Stable state needs no disk write. Recreate a removed status file.
        if(!statusWritten||result!=writtenStatus||access(statusPath.c_str(),F_OK)!=0){
            FD f(open(statusPath.c_str(),O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600));
            if(f.fd>=0){Bytes b(result.begin(),result.end());writeAt(f.fd,0,b);writtenStatus=result;statusWritten=true;}
        }
        if(step++%20==0)std::cout<<result<<std::flush;
        wait_guard_interval(stopRequested,std::chrono::seconds(3));
    }
}
static void unmask(){profile();enterInitNamespace();removeOwnedMasks();}
static void stopWatch(const std::string& module){require(geteuid()==0&&module.rfind("/data/adb/modules/",0)==0&&module.find("..") ==std::string::npos,"invalid module path");FD lock(open((STATE+"/guard.lock").c_str(),O_RDWR|O_CLOEXEC|O_NOFOLLOW));if(lock.fd<0)return;if(flock(lock.fd,LOCK_EX|LOCK_NB)==0)return;
    auto value=trim(textFile(STATE+"/guard.pid"));require(!value.empty()&&value.find_first_not_of("0123456789")==std::string::npos,"invalid watcher PID");long pid=std::stol(value);require(pid>1,"invalid watcher PID");FD process(int(syscall(SYS_pidfd_open,pid,0)));require(process.fd>=0,"watcher no longer exists");require(linkPath("/proc/"+value+"/exe")==module+"/bin/prover","watcher executable identity mismatch");auto cmd=textFile("/proc/"+value+"/cmdline");require(cmd.find(std::string("\0watch\0",7))!=std::string::npos,"watcher command mismatch");require(syscall(SYS_pidfd_send_signal,process.fd,SIGTERM,nullptr,0)==0,"stop watcher failed");bool ended=false;for(unsigned i=0;i<100;++i){if(flock(lock.fd,LOCK_EX|LOCK_NB)==0){ended=true;break;}usleep(50000);}require(ended,"watcher did not stop: masks retained");}
int main(int argc,char** argv){try{umask(0077);signal(SIGTERM,stopSignal);signal(SIGINT,stopSignal);signal(SIGHUP,stopSignal);signal(SIGPIPE,SIG_IGN);require(argc>=2,"usage: prover status | gate | watch MODDIR | clean --confirm-device-write | restore/recover SNAPSHOT --confirm-device-write | stop MODDIR | unmask");std::string command=argv[1];
    if(command=="status"&&argc==2)status();
    else if(command=="gate"&&argc==2){profile();enterInitNamespace();FD fd(originalNode());gates(fd.fd);std::cout<<"vr_commands=accepted; internal gates not independently observed\n";}
    else if(command=="watch"&&argc==3)watch(argv[2]);
    else if(command=="clean"&&argc==3&&std::string(argv[2])=="--confirm-device-write")cleanup("");
    else if(command=="restore"&&argc==4&&std::string(argv[3])=="--confirm-device-write")cleanup(argv[2]);
    else if(command=="recover"&&argc==4&&std::string(argv[3])=="--confirm-device-write")cleanup(argv[2],true);
    else if(command=="stop"&&argc==3)stopWatch(argv[2]);
    else if(command=="unmask"&&argc==2)unmask();
    else throw std::runtime_error("invalid command or missing explicit device-write option");return 0;
}catch(const std::exception& e){std::cerr<<"vivo Root Prover: "<<e.what()<<"\n";return 1;}}
