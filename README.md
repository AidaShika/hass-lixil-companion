# LIXIL Companion for Home Assistant

**[中文](#中文) | [日本語](#日本語) | [English](#english)**

An unofficial companion integration that makes it much easier to add LIXIL residential cameras (Dahua OEM) to Home Assistant via [ha-dahua](https://github.com/rroller/dahua): LAN discovery, a QR-code setup wizard, and automatic IP-drift healing.

> Unofficial community project. Not affiliated with LIXIL or Life Assist2.

---

<a id="中文"></a>
## 中文

### 这是什么

LIXIL 的住宅摄像头（如 Life Assist2 生态的 LS279）大多是大华 OEM，本身可以被 ha-dahua 集成直连，但手动添加要自己找 IP、翻说明书找安全码，IP 漂移后还会断线。本集成不重写接入，只补上这三段体验：

- **发现与识别**：扫描局域网，按端口、协议指纹和 MAC 厂商前缀判断哪台是大华系摄像头。
- **二维码向导**：把说明书二维码的解码文本粘贴进来，自动提取安全码（SC），并登录设备读取真实序列号与二维码里的 SN 交叉校验；校验通过后在后台驱动 ha-dahua 完成添加。
- **IP 自愈守护**：添加后每小时（以及启动 60 秒后）按 MAC 核查摄像头 IP；发现漂移就自动更新 ha-dahua 条目的地址并重载。作者实测：IP 从 .15 变为 .115 后，约 90 秒自动恢复，快照正常。守护状态看得见：设备页有当前 IP、上次检查时间、已修复次数三个实体，外加一个“立即重新扫描”按钮。
- **自动发现**：带大华 MAC 前缀的新设备拿到 DHCP 地址时，HA 会主动弹出发现提示，点一下就进向导（会先指纹确认，门铃/NVR 等其他大华设备不会误触发）。

### 要求

- Home Assistant 2024.6 或更高
- 已安装 [ha-dahua](https://github.com/rroller/dahua) 集成
- 摄像头与 HA 在同一局域网
- 已验证机型：**LS279**（固件 2.800.1E8C000.0.R，2026-10-24 实测）。其他大华 OEM 的 LIXIL 机型理论上可用，未逐一验证。

### 安装

**HACS（推荐）**：HACS → 集成 → 右上角菜单 → 自定义仓库，填入本仓库地址 `https://github.com/AidaShika/hass-lixil-companion`，类别选 Integration，添加后下载 “LIXIL Companion”，重启 HA。

**手动**：把 `custom_components/lixil_companion` 整个文件夹拷到 HA 的 `config/custom_components/` 下，重启 HA。

### 使用

1. 设置 → 设备与服务 → 添加集成 → 搜索 “LIXIL Companion”
2. 填摄像头 IP（向导会先探测确认设备可达且像大华系）
3. 用手机扫说明书上的二维码，把解码文本粘贴进来（形如 `{SN:…, SC:…, PID:…}`，其中 SC 就是设备密码）
4. 确认名称，完成。向导会校验序列号、驱动 ha-dahua 建好条目，并抓一张快照验证真的通了

### 隐私与安全

- 伴侣集成**从不存储安全码**：SC 只在向导内存中过手，交给 ha-dahua 的条目保管。
- 伴侣条目只保存 IP、MAC、序列号、机型与关联的 ha-dahua 条目 ID，用于守护巡检。

### 已知限制

- 二维码目前只支持粘贴解码文本，图片识别/实时扫码在规划中。
- 事件、灯光等实体由 ha-dahua 提供，本集成不重复实现。
- 若 MAC 未能取得，守护会退化为“全网段指纹扫描 + 唯一候选”模式定位设备。

### 状态

v0.2.0，2026-10-24 在作者家 LS279 上完成端到端实测（发现 → 向导添加 → IP 漂移自愈）。

---

<a id="日本語"></a>
## 日本語

### これは何か

LIXIL の住宅用カメラ（Life Assist2 の LS279 など）の多くは大華（Dahua）OEM で、ha-dahua 統合から直接接続できます。ただし手動追加では IP を探し、説明書のセキュリティコードを探し、IP が変わると切断されてしまいます。本統合は接続そのものは書き直さず、次の 3 点だけを補います。

- **検出と判定**：LAN をスキャンし、ポート・プロトコルの指紋と MAC のベンダープレフィックスから Dahua 系カメラを判定。
- **QR ウィザード**：説明書 QR コードのデコード済みテキストを貼るだけでセキュリティコード（SC）を自動抽出。デバイスにログインして実シリアル番号を読み、QR の SN と照合してから、裏側で ha-dahua の追加フローを駆動します。
- **IP 自己修復ガーディアン**：追加後は 1 時間ごと（と起動 60 秒後）に MAC で IP を確認し、変わっていれば ha-dahua のアドレスを自動更新して再読み込みします。実測：IP が .15 → .115 に変わった際、約 90 秒で自動復旧しスナップショットも正常に戻りました。ガーディアンの状態はデバイスページで見えます（現在の IP・前回確認時刻・修復回数のエンティティ＋「今すぐ再スキャン」ボタン）。
- **自動検出**：Dahua の MAC プレフィックスを持つ新しいデバイスが DHCP でアドレスを取得すると、HA が検出を通知し、タップひとつでウィザードが始まります（指紋確認を通るため、インターホンや NVR など他の Dahua 機器では誤作動しません）。

### 要件

- Home Assistant 2024.6 以上
- [ha-dahua](https://github.com/rroller/dahua) 統合がインストール済みであること
- カメラと HA が同一 LAN 内にあること
- 対応確認済み機種：**LS279**（ファームウェア 2.800.1E8C000.0.R、2026-10-24 実測）。他の Dahua OEM の LIXIL 機種は理論上動作しますが未検証です。

### インストール

**HACS（推奨）**：HACS → 統合 → 右上メニュー → カスタムリポジトリに `https://github.com/AidaShika/hass-lixil-companion` を追加（カテゴリ：Integration）、「LIXIL Companion」をダウンロードして HA を再起動。

**手動**：`custom_components/lixil_companion` フォルダを HA の `config/custom_components/` にコピーし、HA を再起動。

### 使い方

1. 設定 → デバイスとサービス → 統合を追加 → 「LIXIL Companion」を検索
2. カメラの IP を入力（到達可能性と Dahua 系かどうかの指紋を確認します）
3. スマホで説明書の QR を読み取り、デコード済みテキストを貼り付け（`{SN:…, SC:…, PID:…}` 形式。SC がデバイスのパスワードです）
4. 名前を確認して完了。シリアル照合 → ha-dahua のエントリ作成 → スナップショット取得まで自動で検証します

### プライバシーとセキュリティ

- 本統合は**セキュリティコードを保存しません**。SC はウィザードのメモリ内だけを通り、保管は ha-dahua のエントリに委ねます。
- 本統合のエントリが保存するのは IP・MAC・シリアル番号・機種・連携先 ha-dahua エントリ ID のみ（ガーディアンの巡回用）。

### 既知の制限

- QR は現在デコード済みテキストの貼り付けのみ対応。画像読み取り／リアルタイムスキャンは今後の予定です。
- イベントや照明などのエンティティは ha-dahua が提供します（本統合では再実装しません）。
- MAC が取得できなかった場合、ガーディアンは「サブネット指紋スキャン＋候補が 1 台だけ」のフォールバックで特定します。

### 状態

v0.2.0。2026-10-24 に作者宅の LS279 でエンドツーエンド実測済み（検出 → ウィザード追加 → IP 変動の自己修復）。

---

<a id="english"></a>
## English

### What is this?

Many LIXIL residential cameras (e.g. the Life Assist2 LS279) are Dahua OEM devices that the ha-dahua integration can talk to directly. Adding one by hand still means hunting for its IP, digging the security code out of the manual, and fixing the entry every time its IP drifts. This integration does not re-implement the camera connection — it fills exactly those three gaps:

- **Discovery & fingerprinting**: scans the LAN and identifies Dahua-based cameras by open ports, protocol fingerprints, and MAC vendor prefixes.
- **QR setup wizard**: paste the decoded text of the QR code printed in the manual; the wizard extracts the security code (SC), logs in to the device to read its real serial number, cross-checks it against the QR's SN, then drives the ha-dahua config flow for you.
- **IP guardian**: after setup, it checks the camera's IP by MAC every hour (and 60 s after start). If the address drifted, it updates the ha-dahua entry and reloads it. Measured on the author's camera: after an IP change from .15 to .115, the camera recovered automatically in about 90 seconds, snapshots included. The guardian is visible on the device page: current IP, last check time, repairs count, plus a Rescan now button.
- **Auto-discovery**: when a new device with a Dahua MAC prefix takes a DHCP lease, Home Assistant offers setup proactively — and the wizard still fingerprint-checks it first, so Dahua intercoms or NVRs do not trigger false positives.

### Requirements

- Home Assistant 2024.6 or newer
- The [ha-dahua](https://github.com/rroller/dahua) integration installed
- Camera and Home Assistant on the same LAN
- Verified device: **LS279** (firmware 2.800.1E8C000.0.R, tested 2026-10-24). Other Dahua-OEM LIXIL models should work but are unverified.

### Installation

**HACS (recommended)**: HACS → Integrations → top-right menu → Custom repositories → add `https://github.com/AidaShika/hass-lixil-companion` as an Integration, download “LIXIL Companion”, then restart Home Assistant.

**Manual**: copy the `custom_components/lixil_companion` folder into your HA `config/custom_components/` directory and restart Home Assistant.

### Usage

1. Settings → Devices & services → Add integration → search “LIXIL Companion”
2. Enter the camera's IP (the wizard probes it and checks the Dahua fingerprint)
3. Scan the QR code in the manual with your phone and paste the decoded text (format `{SN:…, SC:…, PID:…}` — the SC is the device password)
4. Confirm the name. The wizard verifies the serial number, creates the ha-dahua entry, and takes a snapshot to prove the camera really works

### Privacy & security

- This integration **never stores the security code**. The SC only passes through the wizard's memory; credential storage is left to the ha-dahua entry.
- The companion entry stores only the IP, MAC, serial number, device type, and the linked ha-dahua entry ID, which the guardian needs for its checks.

### Known limitations

- QR input is paste-the-decoded-text for now; image decoding / live scanning is planned.
- Event, light, and other entities are provided by ha-dahua and are not re-implemented here.
- If no MAC could be captured, the guardian falls back to a subnet fingerprint scan and only acts when there is exactly one candidate.

### Status

v0.2.0. End-to-end tested on the author's LS279 on 2026-10-24 (discovery → wizard setup → IP-drift self-healing).

---

## License

MIT — see [LICENSE](LICENSE).

Design notes and the full test log live in [SPEC.md](SPEC.md) (Chinese).
