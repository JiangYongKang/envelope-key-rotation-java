# 本地信封加密与密钥轮换（envelope-key-rotation-java）

不依赖任何外部 KMS / 网络服务的**本地信封加密 + 密钥轮换 + 权限留痕**能力。
所有密钥材料（KEK / DEK）与随机数均来自本地 `SecureRandom`，只保存在进程内存中。
所有异常路径都给出**可区分、可解释的领域拒绝原因**，底层加密库异常不直接透出。

---

## 1. 总体结构

```
envelope/
├─ model/        领域模型：KeyVersion / EnvelopeCiphertext / Caller / AuditEvent / 枚举
├─ error/        RejectReason（拒绝原因枚举）+ EnvelopeException（唯一对外异常）
├─ crypto/       AES-GCM 原语、本地密钥材料源、nonce 生成与复用检测、密文格式
├─ store/        内存密钥库（版本状态 + 轮换串行化）
├─ auth/         角色权限校验
├─ audit/        敏感操作留痕（内存事件 + 脱敏日志）
├─ web/          本地演示用 REST 门面与全局异常映射
├─ EnvelopeService / DefaultEnvelopeService   应用门面
└─ EnvelopeConfiguration                      Spring 装配
```

信封结构（标准两层）：

- **DEK**（Data Encryption Key）：每次加密临时生成的一次性 AES-256，用 AES-GCM 加密业务数据；
- **KEK**（Key Encryption Key）：按版本管理的主密钥 AES-256，用 AES-GCM 包装 DEK；
- 密文中只保存 `KEK版本号 + 被包装的DEK + 两个nonce + 数据密文`，不保存任何明文密钥。

### 密文二进制格式（大端、自描述）

```
MAGIC(4)="ENV1" | kekVersion(int) |
wrappedDekLen(int) | wrappedDek(含128bit GCM tag) |
dekNonceLen(int)  | dekNonce(12B) |
dataCipherLen(int)| dataCipher(含128bit GCM tag) |
dataNonceLen(int) | dataNonce(12B)
```

每条密文都能对应回加密时使用的 KEK 版本，因此轮换后历史密文仍能定位密钥并解开。

---

## 2. 密钥生命周期

| 状态 | 含义 | 可加密 | 可解密 |
|------|------|:------:|:------:|
| `ACTIVE` | 当前唯一在用版本 | 是 | 是 |
| `DISABLED` | 轮换后保留的历史版本（不删除） | **否** | 是 |

规则：

1. 服务启动时自动生成版本 **1（ACTIVE）**，保证总有可加密版本；
2. 轮换 = 新版本号（最大版本号 + 1）置 `ACTIVE`，旧 `ACTIVE` 置 `DISABLED`；
3. 轮换**串行化**：在密钥库同一把锁内完成“读现状 → 生成新版本 → 停用旧版本”。
   并发轮换不会出现版本号重复或两个 ACTIVE 并存；
4. `DISABLED` 版本长期保留，仅用于解开历史密文（读取兼容），不能再产出新密文；
5. 加密永远取当前 `ACTIVE` 版本，因此轮换后所有新数据自动走新版本。

---

## 3. 版本兼容规则

- **当前版本数据**：正常加密、正常解密；
- **历史版本数据**：密文内嵌版本号 → 按版本号取对应 KEK → 解包 DEK → 解数据。
  即使该版本已 `DISABLED` 也照样可解；
- **版本不存在**：密文指向的版本号在密钥库中不存在 → `VERSION_NOT_FOUND`（422）；
- **密钥对不上**：版本号存在但 KEK 不匹配（例如换了一个独立密钥库）→
  GCM 标签校验失败 → `AUTH_TAG_MISMATCH`（422），不会解出乱码；
- **密文被篡改**：改动任何密文段 / nonce / tag → `AUTH_TAG_MISMATCH`；
- **格式损坏**：魔数不符、截断、负长度等无法解析 → `CIPHERTEXT_MALFORMED`（422）。

> 说明：在 AES-GCM 语义下，“密钥不对”与“密文被篡改”都表现为认证标签失败，
> 密码学上不可进一步区分，统一报 `AUTH_TAG_MISMATCH`；
> 它与“版本不存在”“格式损坏”是明确可区分的。

---

## 4. 加密随机数（nonce）复用防护

GCM 在**同一把密钥**下复用 nonce 会破坏认证安全，因此：

- 每次加密生成两个 96bit 本地随机 nonce：数据包 nonce 与 KEK 包装 nonce；
- 按 `(KEK版本, 包装nonce)` 维度在内存集合中登记；
- 登记依赖并发集合 `add` 的**原子返回值**：同一版本并发提交相同 nonce，
  恰有 1 个成功，其余立即得到“复用”结论 → 拒绝加密（`NONCE_REUSE_DETECTED`，422），
  **绝不照常产出密文**；
- 轮换产生新版本后，新版本是一把全新 KEK，nonce 空间重新开始计数，互不影响。

---

## 5. 权限约束（RBAC）

| 角色 | encrypt | decrypt | rotate |
|------|:-------:|:-------:|:------:|
| `ENCRYPTOR` | ✅ | ❌ | ❌ |
| `DECRYPTOR` | ❌ | ✅ | ❌ |
| `ROTATOR`   | ❌ | ❌ | ✅ |

- 角色可叠加（一个 Caller 可持多个角色）；
- 匿名 / 无身份调用一律 `ACCESS_DENIED`（HTTP 403）；
- 越权操作在触碰任何密钥材料**之前**就被拒绝，并且同样写一条拒绝留痕。

> HTTP 门面里的角色来自请求体，仅用于**本地演示与验证**；
> 接入真实系统时应替换为服务端签发并校验的身份凭证。

---

## 6. 操作留痕（Audit）

对 `ENCRYPT / DECRYPT / KEY_ROTATE / ACCESS_DENIED` 记录事件（内存列表 + INFO 日志），字段：

```
timestamp | caller | action | success | keyVersion | reason | detail
```

- `detail` 只含**元数据**（长度、版本、状态），例如 `plaintextLen=12, ciphertextLen=77`；
- **红线**：留痕与日志中不出现明文数据、KEK/DEK 材料或 nonce 值；
  `KeyVersion.toString()` 已脱敏（只打印版本/状态/密钥长度）。

### 拒绝原因对照表

| reason | 触发场景 | HTTP |
|--------|----------|------|
| `ACCESS_DENIED` | 匿名或角色不足 | 403 |
| `VERSION_NOT_FOUND` | 密文引用的密钥版本不存在 | 422 |
| `CIPHERTEXT_MALFORMED` | 密文无法解析 / 截断 / 魔数错 | 422 |
| `AUTH_TAG_MISMATCH` | 密钥对不上或密文/标签被篡改 | 422 |
| `NONCE_REUSE_DETECTED` | 同版本 nonce 复用 | 422 |
| `KEY_DISABLED_FOR_ENCRYPT` | 用已停用版本加密 | 422 |
| `ROTATION_CONFLICT` | 轮换未能一致完成 | 422 |
| `INVALID_ARGUMENT` | 入参为空等 | 422 |
| `NONCE_GENERATION_FAILED` / `INTERNAL_CRYPTO_ERROR` | 本地配置/随机源问题 | 500 |

---

## 7. 本地验证方法

### 7.1 运行测试（推荐，结果可复现）

```bash
mvn test
```

覆盖场景（共 20 个用例，均带关键输入与判定依据日志）：

| 测试类 | 覆盖内容 |
|--------|----------|
| `EnvelopeRoundTripTest` | 加解密往返；轮换后历史密文可读；多次轮换全历史可读；停用版本状态 |
| `EnvelopeFailureTest` | 数据段/包装DEK篡改、版本号伪造为不存在版本、垃圾/截断字节、跨密钥库密钥不匹配 |
| `EnvelopeAccessControlTest` | 三种角色越权矩阵、匿名拒绝、越权必留痕、留痕无明文 |
| `EnvelopeConcurrencyTest` | 4线程轮换+8线程加密并发一致性；确定性 nonce 复用被拒且不产出密文 |
| `NonceTrackerTest` | 16线程并发提交相同 nonce，恰 1 个接受 |
| `EnvelopeWebTest` | HTTP 端到端：加密→轮换→历史解密、403 越权、422 篡改 |

查看带判定依据的日志：

```bash
mvn test -Dtest=EnvelopeFailureTest   # 关键行前缀 [TEST-INPUT] / [TEST-JUDGE]
mvn test -Dtest=EnvelopeConcurrencyTest
```

### 7.2 启动服务后用 HTTP 手工验证

```bash
mvn spring-boot:run
```

```bash
# 1) 用 v1 加密（明文先 Base64）
curl -s -X POST localhost:8080/api/envelope/encrypt -H 'Content-Type: application/json' -d '{
  "caller":"app1","roles":["ENCRYPTOR"],
  "plaintextBase64":"'$(printf 'hello-local' | base64)'"
}'

# 2) 轮换（仅 ROTATOR）
curl -s -X POST localhost:8080/api/envelope/rotate -H 'Content-Type: application/json' -d '{
  "caller":"ops1","roles":["ROTATOR"]
}'

# 3) 用上一步返回的 ciphertext base64 解密（历史 v1 密文仍可解）
curl -s -X POST localhost:8080/api/envelope/decrypt -H 'Content-Type: application/json' -d '{
  "caller":"ro1","roles":["DECRYPTOR"],"ciphertextBase64":"<粘贴base64>"
}'

# 4) 查看版本元数据（不含密钥材料）
curl -s localhost:8080/api/envelope/versions

# 5) 越权：ENCRYPTOR 尝试轮换 -> 403 ACCESS_DENIED
curl -i -X POST localhost:8080/api/envelope/rotate -H 'Content-Type: application/json' -d '{
  "caller":"app1","roles":["ENCRYPTOR"]
}'
```

> 注意 `application.properties` 中 `server.port=0` 表示随机端口；
> 若要固定 8080，请改为 `server.port=8080`。

---

## 8. 安全说明与边界

- 本实现是**进程内、内存态**能力：重启后旧 KEK 丢失，历史密文将无法解开
  （演示用途）。生产持久化应把 KEK 存入受控的本地密钥库/文件并做访问控制；
- 密钥材料不写日志、不进审计、不进异常消息；DEK 用完立即在字节数组上清零；
- 密文未额外绑定 AAD（如调用方/租户）。如需更强的上下文绑定，可在 GCM
  seal/open 中加入 AAD，鉴权失败同样归入 `AUTH_TAG_MISMATCH`；
- HTTP 层的角色声明仅用于本地验证，不构成真实认证。
