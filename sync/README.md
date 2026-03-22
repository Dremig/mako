# Sync Notes

这个目录记录黑盒 CTF agent 从零搭建过程中暴露出的通用问题、根因、修复方式与当前剩余缺口。

目标不是记录某一道题怎么做，而是记录这类 agent 为什么会失败、如何持续进步。

## 文档导航

- 问题清单：
  - `agent_bootstrap_issues.md`
- 研究笔记：
  - `agent_evolution_principles.md`

## 当前结论

- 已完成：
  - 黑盒知识库拉取与本地整理
  - 最小 RAG 链路
  - Interpreter + Solver 双层 agent
  - sqlite 持久化记忆
  - 通用阶段机
  - 参数发现收紧
  - RAG 构建链路修复
  - 反思机制
  - 假设生命周期管理
- 未完成：
  - 通用工具发现与动态编排
  - 针对慢盲注场景的稳定 extraction policy
  - 更高精度的语义信号抽取

## 当前系统结构

- 知识检索：
  - `blackbox-kb/rag/index.py`
  - `blackbox-kb/rag/query.py`
  - `blackbox-kb/rag/common.py`
- 命令式 agent：
  - `blackbox-kb/rag/cmd_agent.py`
- 解释层：
  - `blackbox-kb/rag/task_interpreter.py`
- 共享控制层：
  - `blackbox-kb/rag/solver_shared.py`
- 启动脚本：
  - `blackbox-kb/scripts/build_rag_index.sh`
  - `blackbox-kb/scripts/run_web_agent.sh`
- 数据：
  - `blackbox-kb/rag_data/index.jsonl`
  - `blackbox-kb/logs/agent_memory.sqlite`

## 已验证的有效设计

1. 结构化记忆比原始日志回灌更重要
2. 阶段机比“自由规划”更稳
3. RAG 只能增强，不会替代状态管理
4. 参数发现必须保守，否则会产生灾难性误导
5. 对工具输出做净化和摘要是必要条件

## 推动 Agent 进步的高层问题

这些问题比单题表现更重要，它们决定整个系统的上限。

1. 通用阶段控制缺失
2. 真正的自反思缺失
3. 假设管理缺失
4. 信息增益驱动不足
5. 可控性确认不足
6. 事实抽取不够保守
7. 策略记忆缺失
8. 工具编排能力不足
9. baseline 与 diff 机制薄弱
10. 动作粒度控制不稳定
11. RAG 只参与检索，没有深度参与决策
12. 不确定性管理缺失
13. 停止条件缺失
14. 轨迹学习闭环缺失
15. 环境建模不足

## 推荐优先级

如果只能优先做少数几件事，顺序建议如下：

1. 自反思闭环
2. 假设管理
3. 信息增益驱动
4. 工具能力建模
5. baseline/diff 统一机制

## 当前主要短板

1. 漏洞信号抽取还不够精确
2. 工具能力建模仍然偏弱
3. exploitation 慢路径的预算控制还不够硬
4. 多漏洞链的阶段切换仍然偏启发式

## 下一步建议

1. 在 `cmd_agent.py` 中加入 `reflect()`，输出 `failure_reason / strategy_update / next_action_constraints`
2. 将反思结果写入 sqlite，并强制 planner 读取
3. 区分 `candidate hypothesis`、`confirmed hypothesis`、`rejected hypothesis`
4. 把工具选择做成能力表，而不是只靠模型自然语言决定
