# dsh-secret-guard

Plugin cho [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (`dsh`), giúp agent DeepSeek làm việc an toàn hơn trên máy của bạn. Plugin làm 4 việc:
- **che secret** trong output của tool trước khi output tới model;
- **giới hạn tool file** của dsh (`read`, `write`, `edit`, `grep`, `glob`…) trong phạm vi workspace;
- **chặn `web_fetch`** tới mạng nội bộ và VPN;
- **dừng dsh** nếu chính plugin không hoạt động được (fail-closed).

Plugin đi kèm một **gate dùng chung** (`gate/secret_gate.py`), viết theo chuẩn hook của Claude Code. Gate này dùng được cả trong plugin lẫn làm hook trực tiếp cho Claude Code.

Thường không cần cài tay: [deepseek-worker](https://github.com/devtdq1701/deepseek-worker) có lệnh `dsw setup` tự cài và cấu hình plugin này. Hướng dẫn cài đặt đầy đủ, từ Node, dsh tới API key, nằm ở README của deepseek-worker.

> **Trạng thái: thử nghiệm.** Đã kiểm với dsh `0.2.2-rc.3` và Node 24.

## Plugin làm gì

| Điểm chặn của dsh | Việc |
|---|---|
| `tools.guard()` | Chặn lệnh mà gate từ chối, hoặc gate muốn hỏi (chế độ headless không có người để hỏi, nên coi như từ chối). Chặn mọi lệnh nhắc tới file đã bị **taint**, tức file từng có secret bị che (khớp theo đường dẫn hoặc tên file, nên `cd` sang thư mục khác rồi gọi đường dẫn tương đối vẫn bị chặn; glob như `*.ini` thì không bắt được) |
| `tools/pre-execute` | **Giới hạn tool file:** resolve realpath theo cwd của session. Không đọc được `$HOME` ngoài workspace hay `homeAllow`; không ghi hay `cd` ra ngoài workspace; cấm `..`, `~user`, `/proc`, `/sys`, `/dev`, `sensitivePaths`; root của `grep`/`glob` không được chứa `$HOME`. **Chặn `web_fetch`/`read_url`:** tên nội bộ (`localhost`, `*.internal`, `*.corp`…), IP không public (kể cả các dạng IPv6 nhúng IPv4: mapped, NAT64, 6to4, Teredo), địa chỉ thuộc route cụ thể của máy (VPN, cluster, văn phòng), host không resolve được |
| `tools/post-execute` | Thay secret trong output (và trong feedback khi tool bị block) bằng `<REDACTED:loại>` |
| `tools/ptc-dispatch-log` | Che tương tự cho log của chế độ PTC |

**Fail-closed:**
- Khi khởi động, plugin tự test với một token giả. Nếu token đó không bị che, plugin không kích hoạt.
- Patch của `dsw setup` cho entry bắt buộc `agent-loop` inject service `secretGuard`, nên thiếu plugin thì dsh báo `startup failed` và dừng.
- Khi đang chạy, gate lỗi thì lệnh bị chặn hoặc output bị giữ lại.

## Gate dùng chung

`gate/secret_gate.py` (Python ≥ 3.9, chỉ dùng thư viện chuẩn) đọc JSON hook trên stdin và ghi kết quả JSON ra stdout:

| Sự kiện | Hành vi |
|---|---|
| `PreToolUse` | **Từ chối:** tham số chứa credential; `sudo`/`su`/`doas`; `mkfs`; `dd of=/dev/…`; `rm -rf` ở `/`, `~` hay thư mục cha; `curl … \| sh`; tắt hoặc khởi động lại máy. **Hỏi:** `git push --force`, `git reset --hard`, `kubectl`/`helm`/`terraform` thay đổi hạ tầng, `docker … prune/rm`, SQL `DROP`/`TRUNCATE`, đọc file secret (`.env`, `id_rsa`, `*.pem`, `*.key`…), in toàn bộ env |
| `PostToolUse` | Che secret: các key dạng `sk-`, Anthropic/OpenAI, Google, GitHub, GitLab, Slack, Stripe, npm, Hugging Face, AWS, private key, JWT, token Telegram, mật khẩu trong URL, `Basic`/`Bearer`, cặp `password=`/`token=`… |
| `UserPromptSubmit` | Chặn prompt có chứa credential (thêm `[MOCK]` vào prompt để cho qua) |

Dùng làm hook cho chính Claude Code, thêm vào `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "python3 ~/src/dsh-secret-guard/gate/secret_gate.py" }] }],
    "PostToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "python3 ~/src/dsh-secret-guard/gate/secret_gate.py" }] }],
    "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "python3 ~/src/dsh-secret-guard/gate/secret_gate.py" }] }]
  }
}
```

Muốn dùng gate riêng (luật chặt hơn, có các ngoại lệ của máy mình), chỉ cần gate đó theo cùng giao thức hook của Claude Code. Sau đó khai báo `gate = "..."` trong `~/.config/dsw/config.toml` rồi chạy `dsw setup`, hoặc đặt `gatePath` khi cài tay.

## Cài tay (không qua dsw)

```bash
git clone https://github.com/devtdq1701/dsh-secret-guard.git ~/src/dsh-secret-guard
dsh plugin --profile headless add link:$HOME/src/dsh-secret-guard
```

Thêm vào `~/.dsh/profiles/headless/cordis.patch.yml`:

```yaml
- insert:
    - id: secret-guard
      name: 'dsh-secret-guard'
      config:
        # gatePath: /path/to/gate.py        # mặc định: gate/secret_gate.py đi kèm
        # sensitivePaths: ['~/.ssh', ...]   # mặc định: DEFAULT_SENSITIVE trong index.js
        # homeAllow: ['~/.nvm', ...]        # toolchain được đọc; mặc định: DEFAULT_HOME_ALLOW
        # workspaceRoot: /path/to/repo      # mặc định: cwd đầu tiên của mỗi session
        # python: python3
        # timeoutMs: 10000
- id: agent-loop
  inject: [secretGuard]                     # bắt buộc: thiếu plugin thì dsh không khởi động
```

Kiểm tra cấu hình:

```bash
dsh --profile headless --dump-config | grep -A3 'id: secret-guard'
```

Kết quả phải có dòng `name: dsh-secret-guard`.

Plugin chỉ giới hạn **tool file** của dsh. Tool bash phải được giới hạn bằng sandbox, ví dụ `sandbox/dsw-bwrap` của deepseek-worker: `$HOME` rỗng, không `/run`, không mạng.

## Kiểm thử

```bash
npm test
```

Kết quả mong đợi gồm 2 phần:
- test của plugin (Node): `# pass 13`, `# fail 0`;
- test của gate (Python): `Ran 6 tests` rồi `OK`.

Token giả trong test được ghép từ nhiều mảnh lúc chạy, nên repo không chứa secret dạng nguyên văn.

## Giới hạn

- Che theo pattern chỉ là best effort. Secret định dạng lạ, hoặc bị worker copy rồi biến đổi trong workspace, sẽ không bị che. Không để credential thật trong workspace.
- `web_fetch` có thể bị DNS rebinding giữa lúc plugin kiểm tra và lúc dsh fetch.
- Với hub (`dsh web`), workspace được lấy theo cwd đầu tiên của mỗi session.
- Mỗi tool call chạy gate 2 lần (trước và sau), mỗi lần khoảng 50–100 ms.
- Các thông điệp `additionalContexts` do plugin khác thêm vào, và `value` nội bộ của chế độ PTC, không được che. Output in ra từ các giá trị đó thì vẫn được che.

## Giấy phép

MIT. Xem [LICENSE](LICENSE).
