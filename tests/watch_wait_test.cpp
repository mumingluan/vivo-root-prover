// Android/POSIX integration test; no device records or module state are opened.
#include "../src/watch_wait.hpp"
#include <cassert>
#include <cstdio>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t stopped=0;
static volatile sig_atomic_t unrelated=0;
static void stop(int){stopped=1;}
static void other(int){++unrelated;}
static double elapsed(std::chrono::steady_clock::time_point start){
    return std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();
}
int main(){
    for(int s:{SIGTERM,SIGINT,SIGHUP})signal(s,stop);
    signal(SIGUSR1,other);
    auto start=std::chrono::steady_clock::now();
    vrp::wait_guard_interval(stopped,std::chrono::milliseconds(150));
    assert(!stopped&&elapsed(start)>=0.13&&elapsed(start)<2);
    for(int s:{SIGTERM,SIGINT,SIGHUP}){
        stopped=0;pid_t parent=getpid(),child=fork();assert(child>=0);
        if(child==0){usleep(50000);kill(parent,s);_exit(0);}
        start=std::chrono::steady_clock::now();
        vrp::wait_guard_interval(stopped,std::chrono::seconds(3));
        assert(stopped&&elapsed(start)<1);int status=0;waitpid(child,&status,0);assert(WIFEXITED(status));
    }
    // Pending stop signals are consumed atomically and the previous mask is restored.
    sigset_t blocked,previous,actual;sigemptyset(&blocked);sigaddset(&blocked,SIGTERM);
    assert(sigprocmask(SIG_BLOCK,&blocked,&previous)==0);
    stopped=0;kill(getpid(),SIGTERM);start=std::chrono::steady_clock::now();
    vrp::wait_guard_interval(stopped,std::chrono::seconds(3));
    assert(stopped&&elapsed(start)<0.5);
    assert(sigprocmask(SIG_SETMASK,nullptr,&actual)==0&&sigismember(&actual,SIGTERM)==1);
    sigprocmask(SIG_SETMASK,&previous,nullptr);
    // Unrelated signals cannot reset the interval or request a stop.
    stopped=0;pid_t parent=getpid(),child=fork();assert(child>=0);
    if(child==0){usleep(20000);kill(parent,SIGUSR1);usleep(20000);kill(parent,SIGUSR1);_exit(0);}
    start=std::chrono::steady_clock::now();vrp::wait_guard_interval(stopped,std::chrono::milliseconds(150));
    assert(!stopped&&unrelated==2&&elapsed(start)>=0.13&&elapsed(start)<1);
    int status=0;waitpid(child,&status,0);
    stopped=1;start=std::chrono::steady_clock::now();
    vrp::wait_guard_interval(stopped,std::chrono::seconds(3));assert(elapsed(start)<0.5);
    std::puts("PASS timeout, TERM/INT/HUP, pending stop, mask restoration, unrelated signals and pre-set stop");
}
