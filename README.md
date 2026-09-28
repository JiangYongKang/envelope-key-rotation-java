# 本地信封加密与密钥轮换（envelope-key-rotation-java）

基于 Spring Boot 3.4 / Java 21 的**纯本地**信封加密与密钥轮换能力：
密钥材料全部来自进程内 `SecureRandom`，**不依赖任何外部 KMS**。
加密、解密、轮换在各类异常下都给出确定、可区分、可解释的拒绝结果，
底层加密库异常不会透出到调用方。

---

## 1. 信封加密结构

每次加密随机生成一次性 256 位数据密钥 DEK（用后即弃、内存清零）：

| 层 | 算法 | 密钥 | 说明 |
|---|---|---|---|
| 数据层 | AES-256-GCM | 一次性 DEK | 加密明文，`payload` 内含 128 位认证标签 |
| 包装层 | AES-256-GCM | 当前 KEK 版本 | 包装 DEK，AAD 绑定魔数与密钥版本号 |

密文为自描述二进制（小端序），携带加密时的 KEK 版本号：

```
magic "ENV1" | keyVersion(int32)
| wrappedDekLen | wrappedDek = kekNonce(12) || GCM(DEK, AAD=版本绑定)
| nonceLen      | nonce   = 数据层随机 nonce(12)
| ciphertextLen | payload = GCM(明文)（含认证标签）
```

因为密文自带版本号，解密时按版本取对应 KEK，无需调用方记住版本。

## 2. 密钥生命周期

| 状态 | 加密 | 解密 | 说明 |
|---|---|---|---|
| `ACTIVE` | ✅ | ✅ | 全局只有一个当前版本，轮换前由它加密新数据 |
| `RETIRED` | ❌ | ✅ | 轮换后的历史版本，仅保留用于解开历史密文 |

- 初始版本为 `v1`（进程启动时本地随机生成）。
- 轮换 = 本地生成新 256 位 KEK → 版本号严格 `+1`、新版本入库存为 `ACTIVE`
  → 旧 `ACTIVE` 原子置为 `RETIRED`。整个过程在同一把锁内完成，
  **新旧版本共存**：并发读不到“中间态”，加密始终能取到一个 ACTIVE 版本。
- 历史版本不会被删除，历史密文可一直解密；但任何 RETIRED 版本都不能再加密。
- 密钥材料只存在于内存，`ManagedKey` 进出密钥库均做防御性拷贝。
  本地演示语义：进程重启会生成新的初始密钥（不做持久化）。

## 3. 版本兼容规则

- 当前版本加密的数据：正常还原。
- 轮换后用旧版本加密的历史密文：仍按密文内版本号取 RETIRED 密钥正确解开。
- 密文中的 AAD 绑定了版本号，把密文挪到别的版本/别的密钥下解密会认证失败。

## 4. 异常拒绝原因（可区分，不透出底层异常）

| 场景 | 领域异常 | HTTP 状态 / errorCode |
|---|---|---|
| 密文声明的版本在密钥库不存在 | `UnknownKeyVersionException` | 422 / `UNKNOWN_KEY_VERSION` |
| 用 RETIRED 版本加密 | `KeyRetiredException` | 409 / `KEY_RETIRED` |
| 同版本下 KEK nonce 被复用 | `NonceReuseException` | 409 / `NONCE_REUSE_DETECTED` |
| 密文格式非法 / magic 错 / 截断 | `CiphertextTamperedException` | 400 / `CIPHERTEXT_REJECTED` |
| 密钥对不上、密文或标签被篡改 | `CiphertextTamperedException`（认证失败） | 400 / `CIPHERTEXT_REJECTED` |
| 角色不足 | `AccessDeniedException` | 403 / `ACCESS_DENIED` |

JCE 的 `AEADBadTagException` 等底层异常在服务层即被捕获转换，
不会出现在对外消息中。

### nonce 复用检测

每个 KEK 版本维护已使用的包装 nonce 集合（按版本隔离）。
加密在保留 nonce 成功后才继续——并发加密或并发轮换期间，
同一密钥版本下**一旦发现 nonce 重复，本次加密立即拒绝**，
而不是照常产出密文，并写一条 `NONCE_REUSE_REJECTED` 审计。
DEK 每条消息独立随机，因此数据层 nonce 无需跨消息追踪。

## 5. 权限约束

通过请求头表达调用方（本地演示，不接外部 IAM）：

- `X-Caller-Id`：调用方标识；
- `X-Caller-Roles`：逗号分隔角色，未知角色标记忽略。

| 操作 | 所需角色 |
|---|---|
| 加密 `POST /api/encrypt` | `ENCRYPTOR` |
| 解密 `POST /api/decrypt` | `DECRYPTOR` |
| 轮换 `POST /api/rotate` | `KEY_ADMIN` |
| 审计查询 `GET /api/audit` | 不限 |

鉴权在业务逻辑之前执行，越权直接 403 拒绝并留痕（`*_DENIED`）。

## 6. 操作留痕

每次轮换、加密、解密成功/失败、越权拒绝、nonce 复用拒绝都写一条
不可变审计记录（`InMemoryAuditLog`，线程安全）：

```
time | action | callerId | keyVersion | success | reason
```

记录只含元数据（版本号、字节长度、判定原因），
**不包含任何明文密钥材料、DEK、明文数据**；轮换记录中的密钥字段固定打码。

## 7. HTTP API

请求/响应均为 JSON，明文与密文用 Base64 文本承载：

```bash
# 加密
curl -s -X POST localhost:8080/api/encrypt \
  -H 'X-Caller-Id: svc' -H 'X-Caller-Roles: ENCRYPTOR' \
  -H 'Content-Type: application/json' \
  -d '{"plaintext":"aGVsbG8="}'
# -> {"keyVersion":1,"ciphertext":"...."}

# 解密
curl -s -X POST localhost:8080/api/decrypt \
  -H 'X-Caller-Id: svc' -H 'X-Caller-Roles: DECRYPTOR' \
  -H 'Content-Type: application/json' \
  -d '{"ciphertext":"...."}'

# 轮换（需要 KEY_ADMIN）
curl -s -X POST localhost:8080/api/rotate \
  -H 'X-Caller-Id: admin' -H 'X-Caller-Roles: KEY_ADMIN'

# 审计记录
curl -s localhost:8080/api/audit
```

## 8. 本地验证

前置：JDK 21、Maven 3.9+。

```bash
mvn test
```

测试覆盖（共 21 个用例，日志打印关键输入与判定依据）：

| 测试类 | 覆盖场景 |
|---|---|
| `EnvelopeCipherServiceTest` | 当前版本往返；轮换后历史密文兼容；版本不存在；密钥对不上；密文篡改；非法信封；越权；nonce 复用拒绝；审计不含密钥材料 |
| `ConcurrentRotationTest` | 16 线程 × 50 次并发加密 nonce 全局唯一且全部可解；20 次并发轮换版本号唯一且连续、仅一个 ACTIVE；加密与轮换同时进行时密文跨版本且全部可解；非管理员轮换被拒 |
| `CryptoControllerIntegrationTest` | HTTP 全链路加密-轮换-解密、越权 403、篡改 400、审计可查 |
| `KeyLifecycleTest` | ACTIVE/RETIRED 状态流转、停用版本仅解密、密钥材料防御性拷贝、空密钥拒绝 |

手工验证：`mvn spring-boot:run` 后按第 7 节的 curl 执行，
先加密、再轮换、再分别解密新旧密文即可观察版本兼容。
