@docker-exec @poc-runner
你是"本地复现总控 Agent"。严格遵守项目规则：00-orchestrator.mdc / 25-docker-executor.mdc / 20-poc-runner.mdc。先用 Sequential Thinking 生成计划（目标、证据、风险、步骤、回退、产物），再按计划执行。

【目标与上下文】
- 项目：parse-community/parse-server
- 漏洞：CVE-2022-39313（接收包含非法字节范围的文件下载请求时可触发崩溃导致拒绝服务；受影响：<4.10.17 或 5.0.0≤版本<5.2.8；修复：4.10.17、5.2.8）
- 范围：仅在本地容器内执行**安全模式的版本检查**。通过读取 `package.json` 文件判断版本号是否落入已知受影响范围；不执行实际攻击，不对外联网。
- 产物：相对路径 `.\artifacts\parseserver\` 下的 `result.json` / `decision.json` / `notes.txt`

【执行规范（必须遵守，防错）】
- 只执行**简短的离散命令**，每条命令一个职责；不要在同一条里混合变量赋值/管道/重定向/条件。
- **不创建 internal 网络**（本任务不需要网络通信），避免"network not found"类错误。
- **不使用 heredoc/多行内联脚本**；统一将 PoC 脚本作为文件挂载到容器：`-v "<repo>\harness\poc:/poc:ro"`，在容器内执行检查脚本。
- 所有产物写入**当前工作区**相对目录：`.\artifacts\parseserver\`，避免使用绝对盘符路径。
- Runner 判定口径：stdout 末行必须是 `VULNERABLE` 或 `SAFE`；`exit_code==0` 且 stdout 末行命中 `VULNERABLE` 视为 `vulnerable=true`。

【优先级决策树（必须遵守并记录在 decision.json）】
P1. **官方镜像优先**：尝试一个明确的受影响版本，如 `parseplatform/parse-server:4.10.16`；若不可用，则在 Docker Hub 中搜索其他 `4.10.x` 且小于 `4.10.17` 的镜像。
P2. 若 P1 不可行：基于 `https://github.com/parse-community/parse-server.git#4.10.16` 的**git 远程上下文**构建本地镜像。如果使用 MCP 工具克隆项目，克隆到 `recipes` 目录中，并且不允许对该项目做任何修改。
P3. 若 P2 也不行：在 `.\_workspace\parseserver\generated\` 生成最小 Dockerfile 并本地构建（仅用于版本检查）。

【准备与证据（先思考后执行）】
- 用 Sequential Thinking 列出并核对证据来源（NVD/MITRE、GHSA-h423-w6qv-2wj3、Parse Server 文档与 Releases、Docker Hub Tags），并把链接与要点写入 `.\artifacts\parseserver\notes.txt`。
- 选择版本与镜像标签，写入 `.\artifacts\parseserver\decision.json`（包含 chosen=P1/P2/P3、尝试顺序、成功/失败原因、最终镜像 Repo:Tag）。

【PoC 脚本（已提供）】
- **脚本路径**：`.\harness\poc\parseserver_cve_2022_39313_check.js`
- **脚本功能**：该脚本通过在容器文件系统中查找 `parse-server` 的 `package.json` 文件来确定其版本。然后，它将检测到的版本与已知的 CVE-2022-39313 拒绝服务漏洞影响范围（`<4.10.17` 或 `>=5.0.0` 且 `<5.2.8`）进行比较，并在标准输出的末行打印 `VULNERABLE` 或 `SAFE`。

【执行步骤（分别下发，不要链式合并）】
1) 创建产物目录（相对路径）：
   - `mkdir .\artifacts\parseserver`（已存在则忽略）

2) P1 流程（官方镜像）：
   2.1 `docker pull parseplatform/parse-server:4.10.16`（失败则记录并进入 P2）
   2.2 用 `docker image inspect parseplatform/parse-server:4.10.16 --format "{{json .RepoDigests}}"` 记录 digest。
   2.3 执行容器内**安全模式的版本检查**（**无网络、挂载 PoC**）：
       - `docker run --rm --name parseserver-vuln-check `
         `--entrypoint="" `
         `--read-only --cap-drop ALL --security-opt no-new-privileges `
         `--user 65532:65532 --tmpfs /tmp:rw,nosuid,nodev,noexec `
         `--network none `
         `-v ".\\harness\\poc:/poc:ro" `
         `parseplatform/parse-server:4.10.16 `
         `node /poc/parseserver_cve_2022_39313_check.js --mode check`
   2.4 捕获 stdout/stderr 与退出码，供 `result.json` 使用。
   2.5 若 2.1~2.4 任一步失败，记录原因并进入 P2。

【Active 模式（可选，受控 DoS 主动验证）】
- 仅在本地容器内启用，默认关闭；需同时设置：
  - 环境变量：`LUREX_ALLOW_ACTIVE=1` 且注入 `LUREX_TARGET_URL`、`LUREX_RANGE_HEADER`（可选 `LUREX_HEALTH_URL`、`LUREX_HEALTH_DELAY_MS`）。
- 运行命令（示例）：
  - `docker run --rm --name parseserver-dos-check `
    `--entrypoint="" `
    `--read-only --cap-drop ALL --security-opt no-new-privileges `
    `--user 65532:65532 --tmpfs /tmp:rw,nosuid,nodev,noexec --network none `
    `-e LUREX_ALLOW_ACTIVE=1 -e LUREX_TARGET_URL=<http://127.0.0.1:1337/files/test.bin> `
    `-e LUREX_RANGE_HEADER="bytes=999999999-0" `
    `-v ".\\harness\\poc:/poc:ro" parseplatform/parse-server:4.10.16 `
    `node /poc/parseserver_cve_2022_39313_check.js --mode dos-active`
- 判定：若探测发现服务异常退出/连接被拒绝，则 `VULNERABLE`（退出码0），否则 `SAFE`（退出码1）。

3) P2 流程（仓库构建，git 远程上下文）：
   3.1 `docker build -t local/parseserver:4.10.16 "https://github.com/parse-community/parse-server.git#4.10.16"`
   3.2 `docker image inspect local/parseserver:4.10.16 --format "{{json .RepoDigests}}"`
   3.3 `docker run --rm ... local/parseserver:4.10.16 node /poc/parseserver_cve_2022_39313_check.js --mode check`
   3.4 捕获输出与退出码，若失败进入 P3。

4) P3 流程（生成 Dockerfile）：
   4.1 在 `.\_workspace\parseserver\generated\` 写入最小 Dockerfile（基于 Node.js，仅复制 `package.json` 和 `main.js` 以供版本检查）
   4.2 构建 `local/parseserver:generated` → 运行检查 → 捕获输出

5) 统一产物：
   - 写入 `.\artifacts\parseserver\decision.json`（包含：chosen 优先级、镜像 tag、digest、执行命令、检测到的版本号等）
   - 按 20-poc-runner 口径写入 `.\artifacts\parseserver\result.json`（包含 `vulnerable`、`cmd`、`exit_code`、`duration_seconds`、`stdout_tail`、`stderr_tail`）
   - `notes.txt` 已包含所有引用与要点

【判定口径】
- 判定完全依赖 PoC 脚本的输出：
  - 当 `.\harness\poc\parseserver_cve_2022_39313_check.js` 脚本的 stdout 末行为 `VULNERABLE` 且退出码为 0 时，判定为 **VULNERABLE**。
  - 否则判定为 **SAFE**。

【最后输出】
- 在会话中给出：结论（VULNERABLE/SAFE）、镜像信息（Repo:Tag, Digest）、`result.json` 核心字段与 `decision.json` 摘要。
- 清理：删除容器（`--rm` 已处理）。如无必要，不删镜像以便复用。

【重要提示】
- Parse Server 镜像的默认 entrypoint 是启动服务器，检查时必须通过 `--entrypoint=""` 或直接覆盖命令来绕过它，以执行我们的检查脚本。
- 安全约束必须严格执行：非 root、只读根 FS、无网络、cap_drop ALL。

