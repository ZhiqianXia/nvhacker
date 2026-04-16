
## nvhacker

nvhacker 是一个面向 NVIDIA 指令实验的可视化工具：可以在 ELF/cubin 中按指令定位、按 bit 修改、写回并验证反汇编变化。

## 项目作用

- 把原本分散在 `nvdisasm`、十六进制编辑器、脚本里的流程，统一成一个可交互工作流。
- 支持按 section / index 快速定位目标指令，直接在位级别做可控修改。
- 修改后可写回新的 ELF，便于继续跑性能实验、功能验证或微架构行为观察。

## 项目价值

- 降低实验门槛：不需要手写大量 patch 脚本，新人也能快速上手指令位域实验。
- 提升迭代速度：从“定位指令 -> 翻位 -> 反汇编对照 -> 写回”形成闭环，减少重复操作。
- 支持研究与教学：可视化展示指令编码和行为变化，适合做架构探索、逆向分析和内部培训。
- 可扩展：核心逻辑与 TUI 分层，后续可继续扩展新架构、新字段解码和批量 sweep 实验。

## CUDA 工具依赖

运行本项目时，核心依赖不是 CUDA Runtime，而是 CUDA Toolkit 里的反汇编与编译工具。

- 必需：nvdisasm
	- 用途：反汇编指令、bit 翻转后对照变化。
	- 常见路径：/usr/local/cuda/bin/nvdisasm 或加入 PATH。
- 必需：readelf
	- 用途：解析 ELF section 信息并定位指令偏移。
	- 常见来源：binutils 包。
- 可选：nvcc
	- 用途：从 .cu 编译生成测试用 cubin。
	- 如果你只分析已有 cubin，可以不装。

推荐环境：

- CUDA Toolkit 13.x（项目当前验证环境为 13.2）
- Linux + Python 3.10+

快速自检：

```bash
nvdisasm --version
readelf --version
nvcc --version
```

说明：

- 无 GPU 驱动也可以做离线分析和 ELF patch。
- 只有在你要实际运行 kernel 做性能/行为验证时，才需要可用的 NVIDIA 驱动与设备。

## 界面预览


<img width="1174" height="780" alt="image" src="https://github.com/user-attachments/assets/ed77a448-9ddb-413f-9489-55ff0e316a40" />
<img width="1186" height="532" alt="image" src="https://github.com/user-attachments/assets/7833f551-ed95-4609-8da6-4d9eb26fcbe2" />
