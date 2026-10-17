from _build_support import *
import json
KIND='root'
if KIND=='netlink':
    tools=llvm(ndk('29.0.14206865'))
    compiler=tools/('aarch64-linux-android33-clang.cmd' if WINDOWS else 'aarch64-linux-android33-clang')
    out=ROOT/'module/bin/netlink-privacy-guard';out.parent.mkdir(exist_ok=True)
    run(compiler,ROOT/'src/guard.c','-o',out,'-std=c17','-O2','-Wall','-Wextra','-Werror','-Wl,-z,max-page-size=16384','-ldl')
    run(tools/('llvm-strip.exe' if WINDOWS else 'llvm-strip'),'--strip-all',out)
    package_module('android-netlink-privacy-fix-v1.1.0-arm64.zip')
elif KIND=='shader':
    n=ndk('29.0.14206865')
    for folder in ['java','dex','generated']:(BUILD/folder).mkdir(exist_ok=True)
    run(java_tool('javac'),'--release','8','-Xlint:-options','-encoding','UTF-8','-d',BUILD/'java',*sorted((ROOT/'src').glob('*.java')))
    compiled=BUILD/'hook-classes.jar'
    with zipfile.ZipFile(compiled,'w',zipfile.ZIP_DEFLATED) as z:
        for f in sorted((BUILD/'java').rglob('*.class')):z.write(f,f.relative_to(BUILD/'java').as_posix())
    run(tool('36.0.0','d8'),'--release','--min-api','33','--output',BUILD/'dex',compiled)
    data=(BUILD/'dex/classes.dex').read_bytes()
    (BUILD/'generated/hook_dex.h').write_text('static const unsigned char hook_dex[] = {'+','.join(map(str,data))+'};\n',encoding='ascii')
    run('cmake','-S',ROOT,'-B',BUILD,'-G','Ninja','-DCMAKE_TOOLCHAIN_FILE='+str(n/'build/cmake/android.toolchain.cmake'),'-DANDROID_ABI=arm64-v8a','-DANDROID_PLATFORM=android-33','-DANDROID_STL=c++_static','-DCMAKE_BUILD_TYPE=Release')
    run('cmake','--build',BUILD,'-j','8')
    target=ROOT/'module/zygisk/arm64-v8a.so';target.parent.mkdir(exist_ok=True)
    shutil.copy2(BUILD/'libvivo_miuix_shader_fix.so',target)
    run(llvm(n)/('llvm-strip.exe' if WINDOWS else 'llvm-strip'),'--strip-all',target)
    package_module('vivo-miuix-shader-fix-v1.3.0-arm64.zip')
elif KIND=='root':
    n=ndk('27.2.12479018');source=ROOT/'vendor/capstone-5.0.7'
    origin=json.loads((ROOT/'vendor/capstone-origin.json').read_text('utf-8'))
    for name,digest in origin['filesSha256'].items():
        if hashlib.sha256((source/name).read_bytes()).hexdigest()!=digest:raise RuntimeError('Capstone source mismatch: '+name)
    decoder=BUILD/'capstone-android'
    run('cmake','-S',source,'-B',decoder,'-G','Ninja','-DCMAKE_TOOLCHAIN_FILE='+str(n/'build/cmake/android.toolchain.cmake'),'-DANDROID_ABI=arm64-v8a','-DANDROID_PLATFORM=android-26','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_ARM64_SUPPORT=ON','-DCAPSTONE_BUILD_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_INSTALL=OFF','-DBUILD_SHARED_LIBS=OFF','-DBUILD_STATIC_LIBS=ON','-DCMAKE_POSITION_INDEPENDENT_CODE=ON')
    run('cmake','--build',decoder,'--target','capstone_static','-j','4')
    compiler=llvm(n)/('clang++.exe' if WINDOWS else 'clang++');target=ROOT/'module/bin/prover';target.parent.mkdir(exist_ok=True)
    run(compiler,'-ffile-prefix-map='+str(ROOT)+'=.','--target=aarch64-linux-android26','-std=c++17','-O2','-Wall','-Wextra','-Werror','-fPIE','-pie','-fstack-protector-strong','-D_FORTIFY_SOURCE=2','-Wl,-z,relro,-z,now','-static-libstdc++','-I',source/'include',ROOT/'src/prover.cpp',decoder/'libcapstone.a','-o',target)
    run(llvm(n)/('llvm-strip.exe' if WINDOWS else 'llvm-strip'),'--strip-all',target)
    package_module('vivo-root-prover-0.3.3.zip')
else:
    package_module('vivo-extra-dim-range-v1.0.zip')
