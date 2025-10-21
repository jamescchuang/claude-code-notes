# Claude Code 測試範例庫

## 專案簡介

此儲存庫包含用於測試和展示 Claude Code 之客製命令(slash commands)、代理人(subagents) 的範例程式碼應用及產出。

## 儲存庫內容

```
claude-code-notes/
├── .claude/
│   └── commands/
│       └── codeguard-reviewer.md    # CodeGuard 安全審查自訂命令
├── example_report/
│   └── SecurityReviewReport.md      # 範例安全審查報告
├── src/
│   └── flawed_code_exmaple.py       # 包含漏洞的範例程式碼
└── README.md                         # 專案說明文件

```

## 重要提醒

⚠️ **警告**：`flawed_code_exmaple.py` 中的程式碼包含嚴重的安全漏洞，僅供測試與學習用途。請勿在生產環境中使用。


## 相關資源

- [Claude Code 文件](https://docs.claude.com/en/docs/claude-code)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE 常見漏洞列表](https://cwe.mitre.org/)

## 授權

此專案僅供教育與測試用途。
