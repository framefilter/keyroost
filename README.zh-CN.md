# keyroost - 中文版

基于 [framefilter/keyroost](https://github.com/framefilter/keyroost) 原仓库 `main` 分支创建的完整中文翻译版本。

其功能未作完整测试,目前仅进行简体中文翻译,如遇bug会尝试修复

## 本分支更改内容

### 1. 完整中文本地化
- **界面翻译**: 所有菜单、标签、按钮、提示信息
- **对话框翻译**: 所有弹窗标题、内容、按钮
- **状态消息**: 操作反馈、错误提示
- **帮助文本**: 所有帮助主题

### 2. i18n 国际化系统
- `crates/keyroost/locales/app.yml` - 主翻译文件 (YAML格式)
- `crates/keyroost/locales/zh-CN.json` - 中文翻译 (JSON格式)
- `crates/keyroost/locales/en.json` - 英文翻译 (JSON格式)
- 使用 rust-i18n 框架，支持运行时语言切换

### 3. 翻译覆盖模块
- **FIDO2**: 通行密钥、指纹、设置、存储
- **OpenPGP**: 卡片详情、密钥槽位、对话框
- **PIV**: 插槽标签、对话框、证书管理
- **OATH**: 验证码、凭证管理
- **OTP**: 设备端 OTP 管理

### 4. UI 优化
- 统一对话框外观 (使用 `modal_window` 辅助函数)
- 统一按钮样式 (使用 `theme::button` 函数)
- 修复花括号占位符显示问题

## 使用方法

### 设置中文语言
程序启动后，在设置界面选择「简体中文」即可。

或通过环境变量：
```bash
set KEYROOST_LANG=zh-CN
```

## 下载

从 [Releases](https://github.com/Yvhany/keyroost/releases) 页面下载：
- `keyroost.exe` - Windows x64 中文版

## 编译

### 环境要求
- Rust 工具链 (MSRV 1.92)
- Windows: `libpcsclite-dev` (可选，用于 PC/SC 支持)

### 编译命令
```bash
# 编译 release 版本
cargo build --release --package keyroost

# 输出位置
target/release/keyroost.exe
```

### 交叉编译 (Windows)
```bash
# 在 Linux 上编译 Windows 版本
cargo build --release --package keyroost --target x86_64-pc-windows-msvc
```

## 项目结构

```
keyroost-zh-CN/
├── crates/
│   ├── keyroost/           # 主 GUI 应用
│   │   ├── src/
│   │   │   ├── main.rs     # 主代码
│   │   │   ├── locales.rs  # 翻译模块
│   │   │   └── settings.rs # 设置模块
│   │   └── locales/        # 翻译文件
│   │       ├── app.yml     # 主翻译文件
│   │       ├── zh-CN.json  # 中文翻译
│   │       └── en.json     # 英文翻译
│   ├── keyroost-piv/       # PIV 模块
│   ├── keyroost-transport/ # 传输层
│   ├── keyroost-ctap/      # FIDO2/CTAP 模块
│   └── ...
└── docs/                   # 文档
```

## 翻译键命名规范

- 使用蛇形命名法 (snake_case)
- 语义化命名 (如 `reset_wipes_all`)
- 保持与英文键名一致
- 技术术语保持英文 (FIDO2, PIV, OpenPGP 等)

## 如何添加新翻译

1. 在 `locales/app.yml` 中添加新键：
```yaml
new_key:
  en: "New English text"
  zh-CN: "新的中文文本"
```

2. 在 `locales/en.json` 中添加：
```json
"new_key": "New English text"
```

3. 在 `locales/zh-CN.json` 中添加：
```json
"new_key": "新的中文文本"
```

4. 在代码中使用：
```rust
let text = t!("new_key").to_string();
```

## 许可证

与原项目相同：Apache-2.0 / MIT 双许可

---

*基于 framefilter/keyroost v0.7.6，由 Mimo V2.5 与人工审查完成中文本地化*
