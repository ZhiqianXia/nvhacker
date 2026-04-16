# nvhacker 架构说明

> 面向新人的代码地图 — 重点说明扩展指令支持时需要改哪里

---

## 项目目标

可视化修改 CUDA ELF cubin 里的指令比特位，写回 ELF 后重新运行，观察对微架构的影响。

---

## 目录结构

```
nvhacker/
├── core/                  # 纯逻辑库，无 TUI 依赖
│   ├── instruction.py     # 128-bit 指令模型
│   ├── disassembler.py    # nvdisasm 包装器 + 解析
│   ├── bitfield.py        # 探针引擎：128 路翻位 → 分组
│   └── elf_patch.py       # ELF 读写：按 index 读/写指令
├── tui/                   # Textual TUI 前端
│   ├── app.py             # 主 App，绑定快捷键
│   ├── bitgrid.py         # 128-bit 可点击 grid widget
│   ├── asm_view.py        # 汇编文本显示
│   ├── hex_view.py        # 十六进制显示 + 编辑
│   └── probe_panel.py     # 探针结果面板
├── __main__.py            # CLI 入口
└── pyproject.toml
```

---

## 模块依赖图

```
__main__.py  ──┐
               ├──▶ core/instruction.py   (被所有模块导入)
               ├──▶ core/disassembler.py  ──▶ nvdisasm 进程
               ├──▶ core/bitfield.py      ──▶ disassembler
               ├──▶ core/elf_patch.py     ──▶ readelf 进程
               └──▶ tui/app.py            ──▶ 所有 tui widgets
                                          ──▶ core/* (只读引用)
```

`core/` 对 `tui/` **零依赖**，可独立测试。

---

## 核心数据流

```
ELF cubin
   │ elf_patch.read_instruction(elf, section, index)
   ▼
Instruction          ← 128-bit little-endian 字节数组
   │ disassembler.disassemble(insn, arch)
   ▼
DisasmResult         ← mnemonic / modifiers / operands / predicate
   │ bitfield.probe_all(insn, arch)
   ▼
ProbeReport          ← opcode_bits / predicate_bits / modifier_bits / operand_bits
   │ (用户在 TUI/CLI 翻位)
   ▼
Instruction (patched)
   │ elf_patch.write_instruction(orig_elf, section, index, insn, out_elf)
   ▼
patched ELF  ──▶ cuobjdump / ncu / 自定义 runner
```

---

## 各模块详解

### `core/instruction.py` — `Instruction`

128-bit 指令的容器，**小端字节序**（`bits_le[0]` = 第 0 字节最低位）。

| 方法 | 说明 |
|------|------|
| `from_hex(hexstr)` | 解析 32 字符十六进制字符串 |
| `get_bit(i)` / `set_bit(i, v)` / `flip_bit(i)` | 按位操作，`i` 从 0 开始 |
| `get_field(lo, hi)` | 提取 `[lo, hi)` 位段（返回 int） |
| `set_field(lo, hi, val)` | 写入位段 |
| `to_bytes()` / `to_hex()` | 序列化 |
| `copy()` | 深拷贝 |

**扩展点**：如果需要支持 32-bit 或 64-bit 指令（如 Maxwell/Pascal），在此文件增加 `from_bytes_64()` 或子类即可，其余模块通过 `to_bytes()` 统一处理。

---

### `core/disassembler.py` — nvdisasm 包装器

**关键数据结构**

```python
@dataclass
class DisasmResult:
    mnemonic:   str        # e.g. "LDL"
    modifiers:  list[str]  # e.g. [".64"]
    operands:   list[str]  # e.g. ["R2", "[R1]"]
    predicate:  str | None # e.g. "@P6", "@!PT"
    raw:        str        # nvdisasm 原始行
```

**关键正则**（修改时注意）

```python
_ASM_LINE_RE  # 匹配 nvdisasm -hex 输出行，含前导空格和 /* 0x... */ 注释
_PRED_RE      # 剥离 @P6 / @!PT 谓词
```

**nvdisasm 查找顺序**

`/usr/local/cuda/bin/nvdisasm` → `/usr/local/cuda-13.2/...` → `PATH`

**扩展点**

- 新架构：在 `ARCH_SM_MAP` 字典添加 `"SM120": "sm_120"` 映射。
- 解析新指令格式：修改 `_ASM_LINE_RE` 或在 `parse_asm_line()` 增加候补分支。
- 切换反汇编后端（如 `cuobjdump`）：实现相同签名的替代函数并在 `disassemble()` 内切换。

---

### `core/bitfield.py` — 探针引擎

对 128 个比特逐一翻转，重新反汇编，比对差异，归类为：

| 分组 | 含义 |
|------|------|
| `opcode` | mnemonic 改变 |
| `predicate` | 谓词改变 |
| `modifier` | 修饰符列表改变 |
| `operand` | 操作数改变 |
| `unused` | 翻转前后完全相同 |
| `error` | nvdisasm 报错 |

**关键类**

```python
BitProbeResult(bit, changed, asm_before, asm_after,
               mnemonic_changed, modifier_changed,
               operand_changed, predicate_changed)

ProbeReport(results: list[BitProbeResult])
    .opcode_bits    → list[int]
    .predicate_bits → list[int]
    .modifier_bits  → list[int]
    .operand_bits   → list[int]
```

**扩展点**

- 增加新差异维度（如 `immediate_changed`）：在 `BitProbeResult` 加字段，在 `_compare()` 函数里检测，然后在 `ProbeReport` 的对应 property 里过滤。

---

### `core/elf_patch.py` — ELF 读写

使用 `readelf -W -S` 解析 section 表，通过文件偏移直接读写指令字节。

**关键函数**

```python
list_executable_sections(elf_path) → list[SectionInfo]
    # SectionInfo: name, vaddr, file_offset, size, insn_count

read_instruction(elf_path, section, index) → ElfInstructionRef
    # ElfInstructionRef: insn(Instruction), section, index, file_offset

write_instruction(orig_elf, section, index, new_insn, out_elf) → None
    # 复制 ELF 后在 out_elf 对应偏移写入新字节

flip_bits_in_instruction(orig_elf, section, index, bits, out_elf) → Instruction
    # 便捷包装：翻转指定 bit 列表后写回
```

**扩展点**

- 支持更多 ELF 变体（如 32-bit ELF）：修改 `_parse_sections()` 的正则或增加 `readelf` 参数。
- 支持直接操作 PTX / SASS 文本：在此模块并列添加 `write_sass_line()` 等函数。

---

### `tui/` — 前端 widgets

| 文件 | Widget 类 | 职责 |
|------|-----------|------|
| `bitgrid.py` | `BitGrid` | 128 个可点击按钮，颜色标注分组 |
| `asm_view.py` | `AsmView` | 实时显示当前指令的反汇编文本 |
| `hex_view.py` | `HexView` | 十六进制显示，可直接编辑字节 |
| `probe_panel.py` | `ProbePanel` | 显示 ProbeReport，列出各分组比特 |
| `app.py` | `NVHackerApp` | 组合上述 widgets，管理状态，处理快捷键 |

**快捷键**

| 键 | 动作 |
|----|------|
| 点击 bit | 翻转该位，即时反汇编更新 |
| `Ctrl+P` | 探针所有 128 位，给 grid 上色 |
| `Ctrl+S` | 显示 ProbeReport 摘要 |
| `Ctrl+R` | 重置到原始指令 |
| `Ctrl+W` | 写回 ELF（ELF 模式下生效） |
| `Ctrl+A` | 切换目标架构 |
| `Ctrl+Q` | 退出 |

**扩展点**

- 增加新 widget：在 `tui/` 创建文件，在 `app.py` 的 `compose()` 方法里挂载。
- 增加新快捷键：在 `app.py` 的 `BINDINGS` 列表添加绑定，实现对应 `action_*` 方法。

---

## CLI 使用速查

```bash
python3 -m nvhacker --elf nvhacker/test/branch_32_loop.sm100.cubin --section .text.branch_32_loop --out-elf ./test.man.bin --arch SM100
```

---

## 新人扩展指令支持 Checklist

新指令通常只需修改 `core/disassembler.py`：

1. **确认 nvdisasm 能正确输出**：直接跑 `nvdisasm -hex` 人工看输出格式。
2. **检查 `_ASM_LINE_RE`**：是否能匹配新指令行（含特殊前缀/注释）。
3. **检查谓词剥离 `_PRED_RE`**：新格式的谓词是否被正确提取。
4. **运行探针**：`python3 -m nvhacker --probe <hex> --arch SM100`，验证各 bit 分组合理。
5. **TUI 验证**：在 bitgrid 点击 modifier_bits 里的某位，确认 AsmView 文字实时变化。

如果要支持新架构（如 SM120）：
- 在 `disassembler.py` 的 `ARCH_SM_MAP` 添加映射。
- 用该架构编译一个测试 kernel，走上述第 1-5 步验证。
