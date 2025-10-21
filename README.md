# Claude Code 安全測試範例庫

## 專案簡介

此儲存庫包含用於測試和展示 Claude Code 安全審查功能的範例程式碼。專案主要用於驗證 Claude Code 的 CodeGuard 安全審查工具能否有效識別常見的安全漏洞。

## 專案結構

```
claude-code-notes/
├── .claude/
│   └── commands/
│       └── codeguard-reviewer.md    # CodeGuard 安全審查自訂指令
├── example_report/
│   └── SecurityReviewReport.md      # 完整安全審查報告
├── src/
│   └── flawed_code_exmaple.py       # 包含漏洞的範例程式碼
├── 2025-10-20-command-messagecodeguard-reviewer-is-runningc.txt
└── README.md                         # 專案說明文件
```

## 儲存庫內容

### 程式碼範例

- **src/flawed_code_exmaple.py** - 包含多個安全漏洞的 Python 範例程式碼，用於測試安全審查工具的檢測能力
  - SQL 注入漏洞
  - 明文密碼儲存
  - 不安全的資料庫連線
  - 不當的 Session 管理
  - 缺乏錯誤處理

### 安全審查報告

- **example_report/SecurityReviewReport.md** - 完整的安全審查報告，包含：
  - 5 個關鍵漏洞的詳細分析
  - 每個漏洞的影響評估
  - 修復建議與安全實作範例
  - 完整的安全參考實作程式碼

### Claude Code 配置

- **.claude/commands/** - Claude Code 自訂指令目錄
  - `codeguard-reviewer.md` - CodeGuard 安全審查 slash 指令

## 主要發現

安全審查識別出 **5 個關鍵級別** 的安全漏洞：

1. **SQL 注入** (CWE-89) - 使用字串格式化構建 SQL 查詢
2. **明文密碼** (CWE-256) - 密碼未經雜湊處理
3. **不安全的資料庫連線** (CWE-306) - 缺乏身份驗證與 TLS 加密
4. **不當的 Session 管理** (CWE-384) - 使用不安全的字典式 Session 儲存
5. **缺乏錯誤處理** (CWE-755) - 無錯誤處理與資源管理

## 使用目的

此儲存庫主要用於：

- 測試 Claude Code 的安全審查功能
- 展示常見的程式碼安全漏洞
- 提供安全編碼的參考實作
- 學習如何識別和修復安全問題

## 重要提醒

⚠️ **警告**：`flawed_code_exmaple.py` 中的程式碼包含嚴重的安全漏洞，僅供測試與學習用途。請勿在生產環境中使用。

## 安全等級

**整體風險等級：🔴 關鍵**

所有關鍵漏洞都需要立即處理。詳細的修復指南和安全實作範例請參閱 `example_report/SecurityReviewReport.md`。

## 相關資源

- [Claude Code 文件](https://docs.claude.com/en/docs/claude-code)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE 常見漏洞列表](https://cwe.mitre.org/)

## 授權

此專案僅供教育與測試用途。
