# 入廊审批时效（time-bounded approval）

把"批了就长期有效"改成**带有效期、过期自动失效、撤销即收回放行**。审批状态、
舱门状态、审计流水三者读**同一份**只追加事件流，重启重放一致。

## 两个必须拍板的语义

### 1. 有效期起算点：首次放行（first-release anchored）

- 窗口 `valid_for_seconds` 从**首次真正放行/进入**起算，不是审批时刻。
- 提前申请时，等待的时间不消耗有效期，对申请人公平。
- 但未使用的票不能永远躺着：再加一个**激活截止期** `activate_by`
  （审批时刻 + `activation_window_seconds`），逾期未激活自动失效。

结果（提前申请）：

| 策略 | 提前 3 小时申请、1 小时窗口 |
|------|------------------------------|
| 审批时刻起算（未采用） | 还没进门票就快到期 |
| 首次放行起算（采用） | 进门后完整享有 1 小时；超过激活截止期未用才失效 |

实现上区分两个事件：`door_opened`（门已开、票可用，但**不锚点**）与
`door_released`（首次进入，写入 `first_release_at`，计算 `expires_at`）。

### 2. 撤销时人在舱内：出来再封（exit-first）

- 撤销立即落盘 `approval_revoked`，票当场失效，门转**只出不进**（exit-only）。
- 物理门**不就地封**，等 `cabin_exited` 落盘后由对账器自动 `door_sealed`。
- 撤销售不能再进入（即便门还开着）。
- 紧急情况提供显式旁路 `force_seal=true` 立即封门；默认路径永不把人封在里面。
- 过期时人仍在舱内，同样按 exit-first 处理。

## 状态机

```
pending request
   │ grant/approve
   ▼
active ──(有效期到期 或 激活截止期)──▶ expired ─┐
   │                                            ├─▶ door_seal_requested
   └──revoke──────────────────────▶ revoked ───┘
                                                     │
                              人在舱内? ──是──▶ exit-only，等 cabin_exited
                                                     │ 否（或已退出）
                                                     ▼
                                              door_sealed（物理封门）
```

状态读取：`active` / `expired` / `revoked` / `*_pending_seal`。
撤销售在物理封门完成前显示 `revoked_pending_seal`，可观测到"权限已收回、门待封"。

## 时序依赖、失败恢复与幂等

撤销是"**先落盘事实，再驱动硬件**"（write-ahead into event log）：

1. `approval_revoked` 先写盘——即使随后进程崩溃，权限也已收回；
2. 再写 `door_seal_requested`（封门意图）；
3. 调物理门：
   - 成功 → 追加 `door_sealed`；
   - 失败 → 追加 `door_seal_failed`，意图保持 pending，物理门如实上报仍开，
     `reconcile()` 与服务启动时自动重试，**部分失败可恢复**；
4. 崩溃在 `seal_requested` 之后、`sealed` 之前：重放时检测到门还物理开着、
   该舱无有效票且无人，自动补封。

幂等：

- 每个命令带 idempotency key（`open:`/`release:`/`enter:`/`exit:`/`sealed:` 等）。
- 重复撤销：票已非 active 时返回 `already=true`，HTTP 200，不重复封门；
  撤销**不存在**的票才是 404。
- 重复进入/退出按 key 去重，进出记录不重复计数。

不可改写：

- 事件按 `seq` 一文件只追加，重放按序归并；已发生的进出/审批/撤销事实
  **永不更新或删除**，纠正只能追加新事件（`store.save` 为原子替换，但
  `EventLog.append` 对已占用 seq 直接报错）。
- 撤销/过期后审批文档**保留**（status 置位），供审计追溯，而不是删掉。

## 单一事实来源

`s/store/accesslog.py` 的 `EventLog` 是唯一事实源；
`access/projection.py` 用纯函数 `replay(events)` 归并出：

- 审批生命周期（`ApprovalState`）
- 每舱物理门 / 逻辑放行 / exit-only / 占用名单（`CabinAccess`）
- 审计流水（同一份事件，按类型可统计）

三者不可能彼此不一致。`tunnelnet/store/approval.py` 落盘的审批文档是
该流的物化快照，便于既有 store 导出与控制台展示。

## HTTP

- `POST /api/access/approve`（含 `valid_for_seconds`、`activation_window_seconds`）
- `POST /api/access/enter` / `POST /api/access/exit`
- `POST /api/access/revoke`（`reason`、`force_seal`，重复撤销幂等 200）
- `POST /api/access/expire`（过期扫描）
- `POST /api/access/reconcile`（重试待封门）
- `GET  /api/access/events`（持久化事件流/审计）

时间来源可在 `AccessService(store, doors, clock=...)` 注入，测试用可控时钟。
