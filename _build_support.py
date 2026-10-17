from pathlib import Path
import os, shutil, subprocess, urllib.request, hashlib, zipfile

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / 'build'
DIST = ROOT / 'dist'
BUILD.mkdir(exist_ok=True)
DIST.mkdir(exist_ok=True)
SDK = Path(os.environ.get('ANDROID_HOME', os.environ.get('ANDROID_SDK_ROOT', str(Path.home()/'AppData/Local/Android/Sdk'))))
WINDOWS = os.name == 'nt'

def run(*args):
    subprocess.run([str(x) for x in args], cwd=ROOT, check=True)

def java_tool(name):
    exe = name + ('.exe' if WINDOWS else '')
    configured = os.environ.get('JAVA_HOME')
    result = str(Path(configured)/'bin'/exe) if configured else shutil.which(exe)
    if not result: raise RuntimeError('Set JAVA_HOME to JDK 21')
    return Path(result)

def tool(version, name):
    suffix = '.bat' if WINDOWS and name in ('d8','apksigner') else ('.exe' if WINDOWS else '')
    return SDK/'build-tools'/version/(name+suffix)

def xposed():
    target = BUILD/'xposed-api-82.jar'
    digest = 'f48c635f1c7469fdec0e00ad2ea0b7a6b2f5b55065784a35b7ca3a84615e8e25'
    if not target.exists():
        target.write_bytes(urllib.request.urlopen('https://api.xposed.info/de/robv/android/xposed/api/82/api-82.jar',timeout=60).read())
    if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
        raise RuntimeError('Xposed API checksum mismatch')
    return target

def ndk(version):
    path=Path(os.environ.get('ANDROID_NDK_HOME', str(SDK/'ndk'/version)))
    if not (path/'build/cmake/android.toolchain.cmake').is_file(): raise RuntimeError('Set ANDROID_NDK_HOME to the requested Android NDK')
    return path

def llvm(path):
    host='windows-x86_64' if WINDOWS else ('darwin-x86_64' if __import__('sys').platform=='darwin' else 'linux-x86_64')
    return path/'toolchains/llvm/prebuilt'/host/'bin'

def package_module(name):
    target=DIST/name
    with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for f in sorted((ROOT/'module').rglob('*')):
            if not f.is_file(): continue
            rel=f.relative_to(ROOT/'module').as_posix()
            info=zipfile.ZipInfo(rel);info.create_system=3;info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=(0o100755 if f.suffix=='.sh' or rel.startswith('bin/') else 0o100644)<<16
            z.writestr(info,f.read_bytes())
    with zipfile.ZipFile(target) as z: assert z.testzip() is None
    print(target)
    return target

def sign(unsigned, version, name):
    aligned=BUILD/'aligned.apk'
    run(tool(version,'zipalign'),'-f','4',unsigned,aligned)
    key=Path.home()/'.android/debug.keystore'
    if not key.is_file(): raise RuntimeError('Create your own ~/.android/debug.keystore with alias androiddebugkey before building')
    target=DIST/name
    run(tool(version,'apksigner'),'sign','--ks',key,'--ks-key-alias','androiddebugkey','--ks-pass','pass:android','--key-pass','pass:android','--v4-signing-enabled','false','--out',target,aligned)
    run(tool(version,'apksigner'),'verify',target)
    print(target)
    return target
