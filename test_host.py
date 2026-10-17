from pathlib import Path
import os, shutil, subprocess
root=Path(__file__).resolve().parent
compiler=os.environ.get('CXX') or shutil.which('g++') or shutil.which('clang++')
if not compiler:raise SystemExit('Set CXX to a host C++17 compiler')
out=root/'build/host-tests';out.mkdir(parents=True,exist_ok=True)
tests=['core_test','hal_process_test']
if os.name!='nt':tests.append('watch_wait_test')
for name in tests:
    exe=out/(name+('.exe' if os.name=='nt' else ''))
    subprocess.run([compiler,'-std=c++17','-O2','-Wall','-Wextra','-Werror',str(root/'tests'/(name+'.cpp')),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
