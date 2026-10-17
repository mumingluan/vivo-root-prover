#pragma once
#include <cerrno>
#include <chrono>
#include <csignal>
#include <initializer_list>
#include <system_error>
#include <time.h>

namespace vrp {
// Block stop signals before testing the flag, then wait atomically for one.
// A signal arriving just before the wait cannot turn into a lost wakeup.
inline void wait_guard_interval(volatile sig_atomic_t& stop,
                                std::chrono::nanoseconds duration) {
    sigset_t signals, previous;
    sigemptyset(&signals);
    for(int signal:{SIGTERM,SIGINT,SIGHUP})sigaddset(&signals,signal);
    if(sigprocmask(SIG_BLOCK,&signals,&previous))
        throw std::system_error(errno,std::generic_category(),"block watcher stop signals");
    struct Restore {
        const sigset_t& mask;
        ~Restore(){sigprocmask(SIG_SETMASK,&mask,nullptr);}
    } restore{previous};
    const auto deadline=std::chrono::steady_clock::now()+duration;
    while(!stop) {
        auto remaining=std::chrono::duration_cast<std::chrono::nanoseconds>(
            deadline-std::chrono::steady_clock::now());
        if(remaining.count()<=0)break;
        timespec timeout{time_t(remaining.count()/1000000000),long(remaining.count()%1000000000)};
        int received=sigtimedwait(&signals,nullptr,&timeout);
        if(received>=0){stop=1;break;}
        if(errno==EAGAIN)break;
        if(errno!=EINTR)throw std::system_error(errno,std::generic_category(),"wait for watcher interval");
    }
}
} // namespace vrp
