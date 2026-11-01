# 发布流程

Agent 只接受用离线私钥签名的程序。私钥不进入管理中心、CI 或代码仓库：管理中心或 GitHub 账号被攻破时，
攻击者能下发升级指令，但 Agent 会拒绝，也不会执行未签名的程序。

## 第一次：生成密钥

在离线电脑上执行一次，保存到加密 U 盘并做一份异地备份：

```bash
go build -o safe-sign ./cmd/sign
./safe-sign keygen /Volumes/加密U盘/intranet-guard-key
```

- `release.key` 是私钥，只保存在离线介质上，不要复制到其他地方。
- `release.pub` 是公钥，复制到仓库根目录并提交。

再次运行 `keygen` 不会覆盖已有的私钥。

## 每次发布

```bash
SAFE_SIGN_KEY=/Volumes/加密U盘/intranet-guard-key/release.key make release VERSION=x.y.z
```

只在需要发版时接入 U 盘，完成后立即移除。私钥与 `release.pub` 不匹配时构建会失败。

## 更换或丢失密钥

- **计划更换**：先发布一个同时内置新旧公钥（`RELEASE_PUBKEY=旧公钥,新公钥`）、用旧私钥签名的版本，等 Agent 升级后，再改用新私钥。
- **私钥丢失**：已安装的 Agent 无法再在线升级，需要用一行安装命令重新安装到内置新公钥的版本。
- **私钥泄露**：攻击者还需要控制管理中心才能下发。立即按更换流程处理；已泄露的公钥要从新版本中去掉。

## 从未内置公钥的版本过渡

v0.9.1 及更早的 Agent 不验证签名。第一次升级到内置公钥的版本后，后续升级才受到保护。
