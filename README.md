# Claude Code 測試範例庫

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

## 相關資源

- [Claude Code 文件](https://docs.claude.com/en/docs/claude-code)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE 常見漏洞列表](https://cwe.mitre.org/)

## 授權

此專案僅供教育與測試用途。
