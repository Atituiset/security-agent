# 保留集冻结记录（held-out corpus）

- 集版本：`benchmarks/corpus-heldout.json` version 1，split `held-out`。
- 冻结日期：2026-09-27。
- corpus sha256：`2ea6ab3dd7038296f2cc53c2c53507c0177893cc9e1217d63c0c9b48e35c1b36`
- 规模：15 例（H001–H015）：CONFIRMED 6、REJECTED 5、UNKNOWN 4；其中多文件案例 8 例
  （H001–H007、H014，正/反/未知 = 3/3/2）。
- 与开发集的关系：开发集 `benchmarks/corpus.json`（C001–C010）允许用于规则诊断与调参；
  本保留集不用于规则修改，仅用于最终对照评估。

## 冻结规则

1. 标签与依据在本记录写入时固定，先于任何对照结果生成。模型运行时不接收 sink 或预期结论；
   rationale 只存在于本文件与 corpus json，不进入案例目录。
2. 模型失误后不得删除困难样例、不得修改标签迎合输出；发现标签错误时，记录勘误并新增
   案例版本（version+1），保留原标签与原始运行结果可溯源。
3. 任何对案例目录源码的修改都会改变 `load_corpus` 计算的 sources 哈希，使既有运行记录
   失效；此类修改视为重新冻结，必须更新版本号与本文件的 sha256。
4. 排除条件：案例不包含开发集已有机制（直接空值、单文件 guard、无条件跨文件返回、
   简单别名、重赋值、内置短路、单纯缺失定义、重载运算符）作为唯一陷阱；每例至少叠加一种
   组合机制（部分路径 guard、跨 TU 谓词 guard、头文件内联包装、函数指针选择、容器元素、
   智能指针 get()、宏展开、条件编译遮蔽）。

## 逐案标签依据

| id | expected | 依据（一两句，可核验） |
|----|----------|------------------------|
| H001 | CONFIRMED | provider.cpp 中 `acquire(mode)` 在 `mode > 0` 分支返回 nullptr；main.cpp 传常量 1 并无条件解引用。 |
| H002 | REJECTED | guard.cpp 的 `usable` 即 `p != nullptr`；main.cpp 提前返回覆盖解引用，guard 在另一个翻译单元。 |
| H003 | REJECTED | util.h 内联 `with_fallback` 对 null 实参返回活静态对象地址，返回值不可能为空。 |
| H004 | CONFIRMED | registry.cpp 文件静态指针初始化为 nullptr；main.cpp 复制到别名 q 并解引用。 |
| H005 | UNKNOWN | 仅有 provider.h 声明，无定义无 stub；返回契约是缺失事实。 |
| H006 | CONFIRMED | store.cpp 的容器以 `{nullptr}` 初始化；main.cpp 无条件解引用 `front()`。 |
| H007 | UNKNOWN | 唯一定义被未定义的构建宏 `ENABLE_PROVIDER` 遮蔽；是否链入定义是编译期事实，源码内不可得。 |
| H008 | CONFIRMED | 两个 guard 只覆盖 `mode > 0` 路径；`mode <= 0` 时 null 落到解引用。 |
| H009 | CONFIRMED | `kind == 0` 路径上函数指针选中返回 null 的 producer，结果无条件解引用。 |
| H010 | REJECTED | 条件赋值可产生 null，但随后的 guard 用活 fallback 修复该分支，解引用前必非空。 |
| H011 | CONFIRMED | 默认构造的 `unique_ptr` 持空，`get()` 为 nullptr 且无 guard 解引用。 |
| H012 | UNKNOWN | 解引用藏在宏 `READ` 内，操作数是无定义 extern callee；返回契约缺失。 |
| H013 | UNKNOWN | 回调指针 `active_producer` 定义在未提供的 TU；其指向与目标返回契约均未知。 |
| H014 | REJECTED | 真实项目提取，见下节；`ctx` 在 `ctx->tmsi` 前有 `== nullptr` 提前返回。 |
| H015 | REJECTED | 真实项目提取，见下节；三个可空来源（null 字面量 + 两次 find 回退）汇于最终 `d != nullptr` guard。 |

## 真实项目案例来源

两个案例提取自本机真实仓库 **AetherStack**（`/home/atituiset/Projects/AetherStack`，
commit `ed126a8ed87fefd2698affe928c875e52b663d0d`，LTE 协议栈演示项目，C++17）。
提取方式为保留原函数体逐字逻辑、仅将类成员扁平化为自由函数并裁减无关依赖；
标签由逐行人工读码确定，非历史模型结论。该仓历史中不存在空指针修复提交，
故两例均为人工确认的守卫覆盖（REJECTED），未虚构真实 bug。

- **H014**：`BsNode::crnti_for_imsi`（`stack/core/src/bs_node.cpp:1196-1201`）调用
  `NasBs::find_ue_by_imsi`（`stack/nas/src/nas_bs.cpp:220-224`，未命中返回 nullptr）。
  原代码 `if (ctx == nullptr) return 0;` 先于 `ctx->tmsi`（bs_node.cpp:1198-1199）。
  提取后跨文件结构（nas.cpp / node.cpp）与原仓跨 TU 关系一致。
- **H015**：`UeNode::end_call`（`stack/core/src/ue_node.cpp:1111-1118`）与
  `find_dialog_by_kind`（同文件 :867-876，两轮查找失败返回 nullptr）。
  原代码三个可空来源最终由 `if (d != nullptr) end_dialog(*d);` 收口。
