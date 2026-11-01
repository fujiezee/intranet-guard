# Windows Agent 端到端测试：在真实 Windows Server（GitHub Actions）上启动管理中心，用控制台给出的一行命令
# 安装 Agent，制造真实的安全事件，核对告警、自检、处置、停止感知、升级与卸载。
# 需要管理员权限；会修改本机审计策略、防火墙规则、账户和服务，只应在一次性的测试机上运行。
# 用法：powershell -ExecutionPolicy Bypass -File scripts\e2e-windows.ps1 -Dir <含 safe-server.exe 与 downloads\ 的目录>
param([string]$Dir = 'e2e')
$ErrorActionPreference = 'Stop'
$Dir = (Resolve-Path $Dir).Path
$Console = 'http://127.0.0.1:18080'
$Password = 'e2e-admin-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$StateDir = Join-Path $env:ProgramData 'safe-agent'
$WebRoot = 'C:\inetpub\wwwroot'
$script:Passed = 0
$script:Failed = 0
$script:Token = $null

function Step([string]$m) { Write-Host ''; Write-Host "== $m" -ForegroundColor Cyan }
function Ok([string]$m) { Write-Host "  [OK] $m" -ForegroundColor Green; $script:Passed++ }
function Fail([string]$m) { Write-Host "  [FAIL] $m" -ForegroundColor Red; $script:Failed++ }
function Check([string]$m, [scriptblock]$cond) {
	$r = $false
	try { $r = [bool](& $cond) } catch { Write-Host "    $($_.Exception.Message)" }
	if ($r) { Ok $m } else { Fail $m }
}
function WaitFor([string]$m, [int]$secs, [scriptblock]$cond) {
	$start = Get-Date
	while (((Get-Date) - $start).TotalSeconds -lt $secs) {
		try { if (& $cond) { Ok "$m（$([int]((Get-Date) - $start).TotalSeconds) 秒）"; return } } catch {}
		Start-Sleep -Seconds 2
	}
	Fail "$m（超过 $secs 秒）"
}

# 调用管理中心 API。响应按 UTF-8 解码（Windows PowerShell 5.1 默认按 ISO-8859-1 解码，中文会乱码）
function Api([string]$method, [string]$path, $body = $null) {
	$headers = @{}
	if ($script:Token) { $headers['Authorization'] = "Bearer $($script:Token)" }
	$p = @{ Method = $method; Uri = "$Console/api/v1$path"; Headers = $headers; UseBasicParsing = $true }
	if ($null -ne $body) {
		$p.Body = [Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json -Depth 5 -Compress))
		$p.ContentType = 'application/json; charset=utf-8'
	}
	$r = Invoke-WebRequest @p
	$text = [Text.Encoding]::UTF8.GetString($r.RawContentStream.ToArray())
	if ($text) { return ($text | ConvertFrom-Json) }
}
function Alerts([string]$type) { @(Api GET '/alerts') | Where-Object { $_.type -eq $type } }
function Agent { @(Api GET '/agents') | Where-Object { $_.id -eq $script:AgentId } }
function ActionStatus([string]$id) { (@(Api GET '/actions') | Where-Object { $_.id -eq $id }).status }
function Quiet([string]$cmdline) { cmd.exe /c "$cmdline >nul 2>&1" | Out-Null }

# 在新的 Windows PowerShell 5.1 进程中执行控制台给出的命令（与管理员粘贴执行相同）
function RunInstallCommand([string]$cmd) {
	$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
	& powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc
	return $LASTEXITCODE
}

$server = $null
try {
	Step '启动管理中心'
	New-Item -ItemType Directory -Force (Join-Path $Dir 'data') | Out-Null
	New-Item -ItemType Directory -Force $WebRoot | Out-Null
	$env:SAFE_INIT_ADMIN_PASSWORD = $Password
	$server = Start-Process -FilePath (Join-Path $Dir 'safe-server.exe') -PassThru -WindowStyle Hidden `
		-RedirectStandardError (Join-Path $Dir 'server.log') -RedirectStandardOutput (Join-Path $Dir 'server.out') `
		-ArgumentList @('-addr=127.0.0.1:18080', '-node-addr=:8443', "-db=$Dir\data\safe.db", "-pki-dir=$Dir\data\pki",
			'-web=', "-dist-dir=$Dir\downloads")
	WaitFor '管理中心启动并可登录' 60 {
		$script:Token = (Api POST '/auth/login' @{ username = 'admin'; password = $Password }).token
		[bool]$script:Token
	}

	Step '控制台给出的一行命令安装 Agent'
	$info = Api GET '/install-info'
	Check '提供 Windows Agent 下载' { @($info.available) -contains 'safe-agent-windows-amd64.exe' }
	Check '生成 Windows 安装命令' { $info.windows_command -like '*install/agent.ps1*' }
	$token = (Api POST '/enroll-tokens' @{ kind = 'agent'; max_uses = 1; ttl_hours = 1 }).token
	# 测试中把上报周期缩短为 5 秒
	$cmd = "`$env:SAFE_AGENT_EXTRA='-interval 5s'; " + $info.windows_command.Replace('__TOKEN__', $token)
	Check '安装命令执行成功' { (RunInstallCommand $cmd) -eq 0 }
	Check '服务以 LocalSystem 运行' {
		(Get-Service safe-agent).Status -eq 'Running' -and
		(Get-CimInstance Win32_Service -Filter "Name='safe-agent'").StartName -eq 'LocalSystem'
	}
	Check '状态目录只允许 SYSTEM 和 Administrators 访问' {
		$sids = (Get-Acl $StateDir).Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
		@($sids | Where-Object { $_ -ne 'S-1-5-18' -and $_ -ne 'S-1-5-32-544' }).Count -eq 0
	}
	WaitFor 'Agent 在线' 60 {
		$script:AgentId = (@(Api GET '/agents') | Where-Object { $_.os -like 'windows*' -and $_.status -eq 'online' } | Select-Object -First 1).id
		[bool]$script:AgentId
	}
	Write-Host "    Agent ID：$script:AgentId"
	WaitFor '命令审计生效（收到进程创建事件 4688）' 60 { @((Agent).capabilities) -contains 'exec_monitor' }

	Step '真实安全事件 → 告警'
	1..12 | ForEach-Object { Quiet 'net use \\127.0.0.1\IPC$ /user:safe-e2e-nouser Wr0ngPass!1' }
	WaitFor '连续登录失败 → 暴力破解告警' 60 { @(Alerts 'ssh_bruteforce' | Where-Object { $_.message -like '*暴力破解*' }).Count -ge 1 }

	$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output safe-e2e'))
	& powershell.exe -NoProfile -EncodedCommand $enc | Out-Null
	Quiet 'wevtutil cl Microsoft-Windows-PowerShell/Operational'
	WaitFor '编码的 PowerShell → 中危告警' 60 { @(Alerts 'suspicious_command' | Where-Object { $_.message -like '*编码的 PowerShell*' -and $_.severity -eq 'medium' }).Count -ge 1 }
	WaitFor '清除事件日志 → 高危告警' 60 { @(Alerts 'suspicious_command' | Where-Object { $_.message -like '*清除日志*' -and $_.severity -eq 'high' }).Count -ge 1 }

	$userPw = 'Aa1!' + [guid]::NewGuid().ToString('N').Substring(0, 12)
	Quiet "net user safe-e2e-u $userPw /add"
	Quiet 'net localgroup Administrators safe-e2e-u /add'
	WaitFor '新建账户 → 中危告警' 60 { @(Alerts 'account_change' | Where-Object { $_.message -like '*新建账户*safe-e2e-u*' }).Count -ge 1 }
	WaitFor '加入 Administrators → 高危告警' 60 { @(Alerts 'account_change' | Where-Object { $_.message -like '*Administrators*' -and $_.severity -eq 'high' }).Count -ge 1 }
	Quiet 'net user safe-e2e-u /delete'

	sc.exe create safe-e2e-svc 'binPath=' 'cmd.exe /c echo safe-e2e' | Out-Null
	WaitFor '用 cmd 启动的新服务 → 高危告警' 60 { @(Alerts 'suspicious_command' | Where-Object { $_.message -like '*可疑服务*safe-e2e-svc*' }).Count -ge 1 }
	sc.exe delete safe-e2e-svc | Out-Null

	WaitFor '同一主机的入侵类告警归为一个事件' 30 {
		$inc = @(Api GET '/incidents') | Where-Object { @($_.stages) -contains 'credential' -and @($_.stages) -contains 'persistence' }
		@($inc).Count -ge 1
	}

	Step '攻击模拟自检'
	$sims = @(Api POST '/simulations' @{ agent_id = $script:AgentId; scenarios = @('download_exec', 'webshell', 'fim', 'process') })
	Check '创建 4 个自检' { $sims.Count -eq 4 }
	WaitFor '下载并执行、Webshell 落地两个场景检出' 120 {
		@(Api GET '/simulations' | Where-Object { $_.status -eq 'passed' -and ($_.scenario -eq 'download_exec' -or $_.scenario -eq 'webshell') }).Count -eq 2
	}
	WaitFor 'Windows 上不支持的场景如实报告“不适用”' 30 {
		@(Api GET '/simulations' | Where-Object { $_.status -eq 'not_applicable' -and ($_.scenario -eq 'fim' -or $_.scenario -eq 'process') }).Count -eq 2
	}
	WaitFor '自检产物已清理' 150 { -not (Get-ChildItem $WebRoot -Filter 'safe-sim-*' -ErrorAction SilentlyContinue) }

	Step '处置'
	$a = Api POST '/actions' @{ agent_id = $script:AgentId; type = 'block_ip'; params = @{ ip = '10.250.0.9'; duration = '600' }; reason = 'e2e' }
	WaitFor '封禁 IP 完成' 60 { (ActionStatus $a.id) -eq 'done' }
	Check 'Windows 防火墙中有入站和出站阻止规则' { @(Get-NetFirewallRule -DisplayName 'safe-block 10.250.0.9' -ErrorAction SilentlyContinue).Count -eq 2 }
	$u = Api POST "/actions/$($a.id)/rollback" @{ reason = 'e2e' }
	WaitFor '撤销封禁完成' 60 { (ActionStatus $u.id) -eq 'done' }
	Check '防火墙规则已删除' { @(Get-NetFirewallRule -DisplayName 'safe-block 10.250.0.9' -ErrorAction SilentlyContinue).Count -eq 0 }

	$ping = Start-Process -FilePath "$env:SystemRoot\System32\PING.EXE" -ArgumentList '-n', '600', '127.0.0.1' -PassThru -WindowStyle Hidden
	Start-Sleep -Seconds 1
	$a = Api POST '/actions' @{ agent_id = $script:AgentId; type = 'kill_process'; params = @{ pid = "$($ping.Id)"; exe = $ping.Path }; reason = 'e2e' }
	WaitFor '结束进程完成' 60 { (ActionStatus $a.id) -eq 'done' }
	Check "进程 $($ping.Id) 已结束" { $ping.Refresh(); $ping.HasExited }

	$evil = Join-Path $WebRoot 'e2e-upload.aspx'
	Set-Content -Path $evil -Value '<% Response.Write("e2e") %>' -Encoding ASCII
	$a = Api POST '/actions' @{ agent_id = $script:AgentId; type = 'quarantine_file'; params = @{ path = $evil }; reason = 'e2e' }
	WaitFor '隔离文件完成' 60 { (ActionStatus $a.id) -eq 'done' }
	Check '文件已移入隔离区' { -not (Test-Path $evil) -and (Test-Path (Join-Path $StateDir "quarantine\$($a.id)\file")) }
	$u = Api POST "/actions/$($a.id)/rollback" @{ reason = 'e2e' }
	WaitFor '恢复文件完成' 60 { (ActionStatus $u.id) -eq 'done' }
	Check '文件已恢复' { (Get-Content $evil) -like '*e2e*' }
	Remove-Item $evil -Force

	Api POST '/users' @{ username = 'admin2'; password = 'second-admin-pw'; role = 'admin' } | Out-Null
	$a = Api POST '/actions' @{ agent_id = $script:AgentId; type = 'isolate_host'; reason = 'e2e' }
	$first = $script:Token
	$script:Token = (Api POST '/auth/login' @{ username = 'admin2'; password = 'second-admin-pw' }).token
	Api POST "/actions/$($a.id)/approve" | Out-Null
	$script:Token = $first
	WaitFor '隔离主机在 Windows 上明确报告不支持（不会部分执行）' 60 {
		$x = @(Api GET '/actions') | Where-Object { $_.id -eq $a.id }
		$x.status -eq 'failed' -and $x.result -like '*Windows 暂不支持*'
	}

	Step 'Agent 停止感知'
	Stop-Service safe-agent
	WaitFor '停止服务 → “Agent 被停止”告警，状态为已停止' 30 { @(Alerts 'agent_stopped').Count -ge 1 -and (Agent).status -eq 'stopped' }
	Start-Service safe-agent
	WaitFor '重新启动后恢复在线' 60 { (Agent).status -eq 'online' }

	Step '升级（再次执行同一命令，令牌已用完）'
	Check '升级成功' { (RunInstallCommand $cmd) -eq 0 }
	WaitFor '升级后以同一 ID 在线' 60 { (Agent).status -eq 'online' -and @(Api GET '/agents' | Where-Object { $_.os -like 'windows*' }).Count -eq 1 }

	Step '卸载'
	Check '卸载成功' { (RunInstallCommand ("`$env:SAFE_ACTION='uninstall'; " + $info.windows_command.Replace('__TOKEN__', ''))) -eq 0 }
	Check '服务和程序已删除，证书与状态保留' {
		-not (Get-Service safe-agent -ErrorAction SilentlyContinue) -and -not (Test-Path "$env:ProgramFiles\safe-agent") -and
		(Test-Path (Join-Path $StateDir 'node.crt'))
	}
} catch {
	Fail "脚本异常：$($_.Exception.Message) $($_.InvocationInfo.PositionMessage)"
} finally {
	if ($server) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
}

Write-Host ''
Write-Host "通过 $script:Passed 项，失败 $script:Failed 项"
if ($script:Failed -gt 0) { exit 1 }
