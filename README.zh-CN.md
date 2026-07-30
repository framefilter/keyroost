# keyroost - 中文翻译分支

基于 [framefilter/keyroost](https://github.com/framefilter/keyroost) 原仓库 `main` 分支创建的中文翻译版本。

## 本分支更改内容

### 1. 文档翻译
- `README.zh-CN.md` - 项目说明文件的中文版本

### 2. i18n 国际化系统
- `crates/keyroost/src/locales.rs` - 新增翻译模块，包含英文和中文翻译
- 支持 25 个帮助主题的完整中文翻译
- 支持 UI 字符串翻译（"Learn how to use this"、"What's this?" 等）

### 3. 语言设置支持
- `crates/keyroost/src/settings.rs` - 新增 `LanguageSetting` 枚举
- 支持在 `settings.json` 中持久化语言偏好
- 支持通过环境变量 `KEYROOST_LANG` 或 `LANG` 自动检测语言

### 4. 代码集成
- `crates/keyroost/src/main.rs` - 集成翻译系统
- `crates/keyroost/src/ui/help.rs` - 帮助文本使用翻译系统
- `crates/keyroost/src/ui/mod.rs` - UI 组件使用翻译

## 使用方法

### 设置中文语言
```bash
set KEYROOST_LANG=zh-cn
```
或在 `settings.json` 中设置：
```json
{
  "language": "zh-cn"
}
```

## 下载

从 [Releases](https://github.com/Yvhany/keyroost/releases) 页面下载：
- `keyroost-x86_64-pc-windows-msvc.zip` - Windows x64
- `keyroost-i686-pc-windows-msvc.zip` - Windows x86
- `keyroost-source.tar.gz` - 源码包

## 编译

如需自行编译，请参考原项目文档安装 Rust 工具链，然后：
```bash
cargo build --release
```

## 许可证

与原项目相同：Apache-2.0 / MIT 双许可

---

*基于 framefilter/keyroost v0.7.6，由 AI 翻译生成*
