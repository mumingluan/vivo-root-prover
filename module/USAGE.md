# 保护、清理与恢复

自动保护
post-fs-data 阶段向真实 proc 节点发送两个关闭挂载记录的命令。
service 阶段运行单实例守护程序，每 3 秒重申关闭开关。
每轮重新扫描 HAL 进程，并在该轮复用扫描结果；不跨轮缓存 PID。
等待使用可被退出信号打断的单次阻塞。状态文件仅在内容改变或丢失时更新，文件修改时间不是心跳。
原始状态为 0 时保留自然 proc 视图，不创建覆盖文件、不设置文件标签、不增加挂载。
原始状态为 1 时才建立只读零值覆盖，并核对工程 HAL 的读取视图。
判断使用一直保留的原始 proc FD，不使用可能已被覆盖的可见读数。
如果原始状态为 0 且发现本模块自己的旧覆盖，移除这些覆盖；不移除其他模块的挂载。
通过 resetprop -n 覆盖 Android root 属性；状态报告的 proc_view_mode 为 natural 或 masked。
proc 覆盖文件采用原节点的 SELinux 标签；无法正确设置标签时拒绝覆盖。
原始内核状态仍保留，报告同时列出 underlying_proc 和 visible_proc。
不会自动清理 NV、历史日志，或直接修改内核代码、厂商库、AVB 镜像。

使用状态工具
su -c 'sh /data/adb/modules/vivo-root-prover/proverctl.sh status'
管理器的“操作/Action”按钮只显示状态，不清理设备记录。

显式清理两份 NV root 字段及已识别的 reserved 挂载日志
su -c 'sh /data/adb/modules/vivo-root-prover/proverctl.sh clean --confirm-device-write'

清理先检查当前 AVB 描述符图，拒绝目标出现在受保护分区列表的情况。
清理要求 init/HAL 的读取视图均为 0；自然零值视图也满足条件，不强制创建 proc 覆盖。
NV 两副本必须完全一致，root 字段为 0/1；字段位置、记录大小、副本间距和 MD5 覆盖范围从实际库推导并验证。
日志必须符合已核对的二进制结构、格式 marker 和 mnt 事件；未知记录或损坏字段会拒绝清理。
记录里的固件名称是非空可打印元数据，不作为版本白名单。HAL 契约、文件身份和事务写入限制仍保留。
修改仅限 backup 两份已验证记录中的 root 字段和 MD5，
以及从内核写入代码推导出的 reserved 挂载日志区；不清空分区。
先等待 6 秒 NV 静默窗口，再短暂停住已识别的工程 HAL 完成事务，随后恢复运行。
静默窗口不能证明所有未知写入者都被拦截；安装执行时序和实机并发仍需验证。

快照保存在 /data/adb/vivo-root-prover/snapshots，目录 0700、文件 0400。
快照包含设备 NV 数据，请自行妥善保存，勿公开上传。
清理前快照已落盘并同步目录；每个写入区均同步和读回比对。
发生写入异常时尝试回滚；跨分区事务不能保证断电原子性。
清理阶段处理普通取消信号；暂停 HAL 后建立子进程监护，事务进程异常退出时尝试恢复 HAL。
这些异常恢复措施尚未实机验证，不能代替断电后的快照恢复核验。
不匹配、权限被拒或并发变化不会被伪装成成功。

正常恢复（只在当前数据仍与该次清理结果一致时接受）
su -c 'sh /data/adb/modules/vivo-root-prover/proverctl.sh restore snapshot-实际编号.vrpj --confirm-device-write'

中断恢复（接受快照前后值的局部混合，拒绝其他设备数据变化）
su -c 'sh /data/adb/modules/vivo-root-prover/proverctl.sh recover snapshot-实际编号.vrpj --confirm-device-write'

恢复会恢复原来的 NV 标志和日志，可能重新使 Recovery 显示“已 root”。
快照不会随卸载自动删除。卸载不自动恢复持久记录。

限制
新增清理路径尚未完成实机验证。KSU 模块运行早晚仍可能错过首次挂载事件。
开关接受写入不代表独立验证了内部开关；守护程序明确报告这一点。
mask 只改变读取视图，不会把已经锁存的内核字节清零。
没有关闭 SELinux，没有修改 boot/init_boot/vendor_boot/system/vendor/recovery/vbmeta。
Recovery 不运行本模块；其 root 显示只有在 NV 清理有效后才可能改变。
本模块处理目前确认的挂载记录链，不能承诺隐藏所有 root 特征或拦截所有厂商检测。
禁用或卸载后建议重启，以恢复厂商默认开关和消除运行时覆盖。
