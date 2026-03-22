# Agent Bootstrap Issues

## 1. RAG 没有真正生效

### 现象

- agent 运行时显示 `docs=0`
- 检索函数被调用了，但实际上没有任何可用文档
- 运行效果主要依赖模型本身和 shell 工具输出

### 根因

- `.env` 中 `OPENAI_EMBED_MODEL` 被填成聊天模型
- embedding 接口不支持该模型
- 索引文件没有成功构建

### 解决

- 在 `blackbox-kb/rag/common.py` 的 `embed_texts()` 中增加 embedding fallback：
  - `text-embedding-3-small`
  - `text-embedding-3-large`
  - `text-embedding-ada-002`
- 在 `blackbox-kb/scripts/build_rag_index.sh` 中：
  - 清理代理变量
  - 使用无缓冲输出
  - 限制首轮构建规模

### 当前状态

- 已修复
- 已成功构建 `600` chunks 的索引
- agent 运行时已显示 `docs=600`

## 2. 入口识别过宽，导致假参数污染

### 现象

- agent 把 HTML 中的 `meta name="renderer"`、`author` 等误识别为可攻击参数
- 后续大量动作围绕假参数展开
- 真正入口被延迟发现或被覆盖

### 根因

- 早期参数提取规则过于宽泛
- 只要出现 `name="..."` 就记为参数

### 解决

- 在 `blackbox-kb/rag/cmd_agent.py` 中收紧参数发现：
  - 仅从 `<form>...</form>` 内的 `input|textarea|select` 提取
  - 从实际执行命令中的 URL query 提取
- 将入口事实拆分为：
  - `entrypoint.candidate.*`
  - `entrypoint.confirmed.*`

### 当前状态

- 已修复
- from-zero 运行中可稳定识别 `questionid`

## 3. 缺少通用阶段控制，导致反复 recon

### 现象

- 已发现入口参数后，agent 仍然重复读取首页
- 侦察与利用阶段来回打转

### 根因

- 没有对“当前阶段”做显式约束
- 模型只按局部上下文行动，没有硬性流转规则

### 解决

- 在 `blackbox-kb/rag/cmd_agent.py` 中引入通用阶段机：
  - `recon`
  - `probe`
  - `exploit`
  - `extract`
  - `verify`
- 使用 `derive_phase_state()` 根据 memory facts 推导当前应处阶段
- 使用 `validate_action()` 阻止低信息增益或阶段倒退的动作

### 当前状态

- 已修复
- agent 已能从首页推进到 probe/exploit

## 4. 缺少持久化策略记忆

### 现象

- agent 记住了最近输出，但记不住长期结论
- 多轮后仍会重复做已经被证伪或低收益的动作

### 根因

- 没有结构化、可查询、跨步骤的记忆层

### 解决

- 在 `blackbox-kb/rag/cmd_agent.py` 中加入 `MemoryStore`
- 使用 sqlite 持久化：
  - `facts`
  - `events`

### 当前状态

- 已落地
- 记忆中可稳定保存：
  - 参数
  - DBMS
  - 当前数据库
  - 漏洞信号
  - 技术路线

## 5. 缺少真正的自反思

### 现象

- 失败后会重试，但不会总结失败原因
- 会继续重复同一类高成本动作
- 例如 time-based SQLi 的全表枚举多次超时后，仍主要停留在相近策略附近

### 根因

- 没有显式 `reflect` 阶段
- 没有失败归因分类
- 没有把失败结论写回策略层

### 需要的解决方式

- 增加独立 `reflect()`：
  - 输入：目标、阶段、命令、结果、预期、实际、新事实
  - 输出：
    - `judgment`
    - `failure_reason`
    - `strategy_update`
    - `next_action_constraints`
- 将反思结果写入 memory
- planner 下轮必须读取这些反思约束

### 当前状态

- 未修复
- 这是当前最大缺口

## 6. 工具调用还不够“自主发现”

### 现象

- agent 目前有工具发现能力，但仍然偏静态
- 还没有真正做到：
  - 根据场景判断需要什么工具
  - 在环境中搜可用工具
  - 根据工具能力切换策略

### 根因

- `discover_tools()` 只是列出命令，不包含能力画像
- planner 还没有基于工具能力做严格决策

### 需要的解决方式

- 将工具抽象成：
  - `name`
  - `path`
  - `capabilities`
  - `cost`
  - `stability`
- planner 不直接决定命令，而是先决定“能力需求”，再映射到工具

### 当前状态

- 部分完成
- 仍需继续演进

## 7. 缺少假设管理

### 现象

- agent 会在多个漏洞方向之间来回跳
- 某条路线即使多轮无增益，也不容易被淘汰
- 没有明确区分“已证伪”和“尚未验证”

### 根因

- 没有显式维护 hypothesis 生命周期

### 需要的解决方式

- 维护：
  - `candidate hypothesis`
  - `confirmed hypothesis`
  - `rejected hypothesis`
  - `stale hypothesis`
- 每轮根据新信号升降级

### 当前状态

- 未修复
- 这是自反思之前的必要基础

## 8. 缺少信息增益驱动

### 现象

- 有些命令技术上正确，但执行后对下一步帮助很小
- agent 会在低收益动作上消耗较多步数

### 根因

- 动作选择没有统一的信息增益评价机制

### 需要的解决方式

- 为每个动作定义：
  - 预期新信号
  - 成本
  - 成功后可推进的阶段
- 低信息增益动作要被拦截或降权

### 当前状态

- 部分修复
- 已有 `info_gain_score()`，但还不足以驱动 planner

## 9. 缺少 baseline 与 diff 机制

### 现象

- 看到响应了，但不知道变化是否有意义
- 时延、状态码、正文长度等信号没有统一对照

### 根因

- 没有把 baseline 作为所有 probe 的默认前置条件

### 需要的解决方式

- 建立统一差分观测：
  - `status_diff`
  - `length_diff`
  - `body_diff`
  - `time_diff`
- 结果必须与 baseline 对照后再进入 memory

### 当前状态

- 未修复
- 这是 probe 稳定性的关键缺口

## 10. 缺少不确定性管理

### 现象

- 模型一旦走上某条路线，容易表现得过于确定
- 错误事实会长期占据决策中心

### 根因

- 虽然 facts 有 confidence，但没有真正参与策略决策

### 需要的解决方式

- 对事实、假设、工具选择都显式打置信度
- 低置信度事实不能直接推动阶段升级

### 当前状态

- 部分完成
- 数据层有置信度，控制层尚未充分使用

## 11. 缺少停止条件与预算控制

### 现象

- 某条路线即使连续超时，也会持续消耗运行预算
- exploitation 阶段容易被慢路径拖死

### 根因

- 没有为每个假设和工具路线定义停止条件

### 需要的解决方式

- 为路线定义：
  - 最大超时次数
  - 最大无增益次数
  - 最大动作预算
- 达到阈值后自动切策略或终止

### 当前状态

- 未修复
- 这是慢盲注场景下的主要痛点

## 12. 缺少轨迹学习闭环

### 现象

- 每轮运行都更像一次性尝试
- 成功链路和失败模式没有真正变成未来资产

### 根因

- 运行日志虽然存在，但没有转化为训练或策略数据

### 需要的解决方式

- 从轨迹中提炼：
  - 成功模板
  - 失败模式
  - 典型阶段迁移
  - 反思结果

### 当前状态

- 未修复
- 长期看这比继续堆知识更重要

## 13. 环境建模不足

### 现象

- 代理、证书、权限、网络限制会反复影响结果
- agent 经常把环境问题误判为目标行为

### 根因

- 系统没有单独建模运行环境健康状态

### 需要的解决方式

- 先做 environment preflight：
  - 网络通达性
  - 代理变量
  - TLS 行为
  - 工具可用性
  - 权限限制

### 当前状态

- 部分修复
- 已做局部规避，但还不是一等公民

## 14. 题目完成失败不等于系统不可用

### 说明

当前系统已经证明以下能力成立：

- RAG 可成功构建并被 agent 加载
- from-zero 能发现真实入口参数
- 能确认 SQLi、识别 DBMS、抽取当前数据库
- 能进入 extraction 阶段

当前没有稳定完成的主要原因是：

- exploitation 后期的慢路径优化不够好
- 没有自反思闭环
- 还没有建立“失败后的策略降载机制”

这说明问题在 agent 控制层，不在基础链路本身。

## 15. 缺少题意解释层会导致路线漂移

### 现象

- 题面已经明确提示 `SQL injection`
- agent 仍会因为弱信号或噪声把精力分散到其他漏洞方向

### 根因

- `objective/hint` 只是普通 prompt 文本
- 没有被提升为高优先级结构化先验

### 解决

- 新增 `task_interpreter`
- 将题面、提示、观测信息转成：
  - `task_prior.primary.*`
  - `task_prior.secondary.*`
  - `task_prior.deprioritized.*`
  - `task_prior.chain.*`
- solver 读取这些先验并限制偏航

### 当前状态

- 已修复为双层架构
- 但语义信号抽取精度还需继续提高
