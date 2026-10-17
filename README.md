# vivo Root Prover

管理已识别的 vivo 挂载 root 记录链：关闭运行期记录开关、检查工程 HAL 读取视图，并提供显式的 NV / 挂载日志清理与恢复工具。

## 使用

需要 ARM64、root 和支持模块脚本的管理器。安装 ZIP 后，自动部分仅运行保护服务。模块的操作按钮只检查状态，不清理持久记录。

保护检查间隔为 3 秒。每轮使用一份新扫描的 HAL 进程列表，等待期间阻塞至超时或退出信号，状态文件只在内容变化或被删除时写入。

```sh
su -c 'sh /data/adb/modules/vivo-root-prover/proverctl.sh status'
```

清理、恢复与快照说明见 [USAGE.md](USAGE.md)。清理会写入经过识别的设备记录区域，需要显式参数确认。快照包含设备 NV 数据，请保存在本地，不要上传到 issue。

## 限制

识别依赖实际内核模块、工厂库、HAL 控制流、块设备身份与几何信息。缺失、歧义、校验失败或设备发生变化时停止操作。跨分区写入不能保证断电原子性；卸载不会自动恢复已经清理的记录。

主要环境为 PD2505 / OriginOS 6。21.8、24.7、30.14、17.0.0.31 做过离线布局与异常路径检查，新增清理路径没有完成四版本实机验证。此版本以预发布形式提供。

## 构建

Windows、Python 3、Android NDK 27、CMake、Ninja。设置 `ANDROID_NDK_HOME`，运行 `python build.py`。构建只编译打包，不连接手机、不执行清理。Capstone 固定来源和原许可证保留在 `vendor/`。

`tests/` 包含主机测试源码，`python test_host.py` 可运行不依赖固件文件的核心和 HAL 映射测试，POSIX 主机还会运行等待与退出信号测试。信号测试也可使用 NDK 编译后在 Android 终端运行。需要真实固件输入的测试要由使用者自行提供对应样本；仓库不分发固件或设备快照。

## 许可证

原有代码采用 GPL-3.0-only，Copyright (C) 2026 Axuan。第三方代码遵循各自许可证，见 [THIRD_PARTY.md](THIRD_PARTY.md)。

版本 `0.3.3`，包名 / 模块 ID：`vivo-root-prover`。
