// crates/keyroost/src/locales.rs
//
// Simple i18n module for keyroost GUI translations.

use std::collections::HashMap;

/// Supported languages
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    #[default]
    En,
    #[serde(rename = "zh-cn")]
    ZhCn,
}

impl Language {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "en" | "english" => Some(Self::En),
            "zh-cn" | "zh" | "chinese" | "中文" => Some(Self::ZhCn),
            _ => None,
        }
    }

    pub fn display_name(&self) -> &str {
        match self {
            Self::En => "English",
            Self::ZhCn => "简体中文",
        }
    }
}

/// Translation keys for help topics
pub struct Translations {
    help_titles: HashMap<&'static str, String>,
    help_bodies: HashMap<&'static str, String>,
    ui_strings: HashMap<&'static str, String>,
}

impl Default for Translations {
    fn default() -> Self {
        Self::english()
    }
}

impl Translations {
    pub fn new(lang: Language) -> Self {
        match lang {
            Language::En => Self::english(),
            Language::ZhCn => Self::chinese(),
        }
    }

    fn english() -> Self {
        let mut help_titles = HashMap::new();
        help_titles.insert("device", "Your security key".to_string());
        help_titles.insert("fido2", "Passkeys & FIDO2".to_string());
        help_titles.insert("pin", "The key's PIN".to_string());
        help_titles.insert("passkeys", "Resident passkeys".to_string());
        help_titles.insert("unlock", "Unlocking the key".to_string());
        help_titles.insert("oath", "Authenticator codes (OATH)".to_string());
        help_titles.insert("otp", "On-device OTP".to_string());
        help_titles.insert("mds", "Device metadata (FIDO MDS)".to_string());
        help_titles.insert("fingerprint", "Fingerprints (biometric enrollment)".to_string());
        help_titles.insert("touch-hotp", "HID-HOTP (HOTP-on-touch)".to_string());
        help_titles.insert("pgp", "OpenPGP".to_string());
        help_titles.insert("pgp-keys", "Generate or import a key".to_string());
        help_titles.insert("pgp-card-details", "Cardholder name & URL".to_string());
        help_titles.insert("piv", "PIV smart card".to_string());
        help_titles.insert("piv-generate", "Generate a key".to_string());
        help_titles.insert("piv-certificate", "Create a certificate".to_string());
        help_titles.insert("piv-import", "Import a certificate".to_string());
        help_titles.insert("piv-export", "Export the certificate".to_string());
        help_titles.insert("piv-delete", "Delete from the slot".to_string());
        help_titles.insert("piv-admin", "Card administration".to_string());
        help_titles.insert("molto", "Programmable TOTP token".to_string());
        help_titles.insert("custkey", "Customer key".to_string());
        help_titles.insert("reset", "Resetting a key".to_string());
        help_titles.insert("settings", "Security policy".to_string());
        help_titles.insert("large_blobs", "Large blob storage".to_string());

        let mut help_bodies = HashMap::new();
        help_bodies.insert("device", "A small hardware device that proves it's really you. The secrets it holds are generated on the key and can never be copied off it — so even a compromised computer can't steal them.".to_string());
        help_bodies.insert("fido2", "FIDO2 lets this key act as a passkey — a phishing-resistant replacement for passwords. A website remembers your key; you just tap it to sign in. Nothing secret ever leaves the device.".to_string());
        help_bodies.insert("pin", "A short PIN that unlocks the key's passkeys on this computer. It is not your account password and never leaves the key. Too many wrong tries and the key locks itself to protect you.".to_string());
        help_bodies.insert("passkeys", "Passkeys stored directly on the key (a.k.a. discoverable credentials). They let you sign in without even typing a username. You can review and remove them here.".to_string());
        help_bodies.insert("unlock", "Enter the key's PIN to unlock it for this session. Unlocking gives access to managing passkeys, fingerprints, and security settings; it stays unlocked until you lock it again or unplug the key. The PIN never leaves the device.".to_string());
        help_bodies.insert("oath", "The rolling 6-digit codes you'd normally get from an authenticator app — but stored on the key itself. They survive a lost or wiped phone and never sync to anyone's cloud.".to_string());
        help_bodies.insert("otp", "TOTP/HOTP codes stored on this Token2 key's own OTP applet, read over CCID/NFC. Add entries, read live codes, and (on keys that support it) trigger a code by touching the key. The seeds live on the device and never sync anywhere.".to_string());
        help_bodies.insert("mds", "Details the FIDO Alliance publishes about this authenticator model, looked up by its AAGUID: vendor name, icon, certification level (e.g. FIDO Certified L2) and date, supported protocol versions, and more. This data is bundled with keyroost and can be refreshed by a maintainer regenerating it from the FIDO metadata.".to_string());
        help_bodies.insert("fingerprint", "Enroll, rename, and delete fingerprints on a biometric key via CTAP2 authenticatorBioEnrollment. Enrolled fingerprints let the key satisfy user verification by touch instead of typing the PIN. Requires the PIN to manage. Templates live on the device and never leave it.".to_string());
        help_bodies.insert("touch-hotp", "Provision a single HOTP slot that types a fresh code as keyboard input when you touch the key outside any session. Needs the keyboard (HID-HOTP) interface enabled. You can change the typing options \u{2014} send Enter, long touch, numeric keypad \u{2014} without re-entering the seed.".to_string());
        help_bodies.insert("pgp", "Turns the key into a smart card for encrypting & signing email and files (and for SSH). The private keys live on the card and never touch your computer's disk.".to_string());
        help_bodies.insert("pgp-keys", "Each of the three keys \u{2014} signature, decryption, authentication \u{2014} can be created right on the card, or imported from an RSA-2048 file you already have. Either way OVERWRITES whatever was in that key, and the only way to clear it again is a full reset. You'll need the admin PIN, and the key may ask for a touch.".to_string());
        help_bodies.insert("pgp-card-details", "Optional labels stored on the card: the cardholder name and a web address where your public key can be found. They're public information, but writing them still needs the admin PIN.".to_string());
        help_bodies.insert("piv", "A US-government smart-card standard used for enterprise sign-in, VPNs and document signing. Manage it here: generate keys, create self-signed certificates or CA requests (signed on the card), import certificates, change the PIN/PUK and management key, and reset the applet. Writes need the management key (factory default 010203…0708).".to_string());
        help_bodies.insert("piv-generate", "Creates a brand-new private key inside this slot and shows you its public key. If the slot already held a key, this overwrites it for good. You'll need the management key.".to_string());
        help_bodies.insert("piv-certificate", "A self-signed certificate is stored straight into the slot and is ready to use. A CSR is a request file you send to a certificate authority so they can issue one for you. Either way the signing happens on the card, so it needs the PIN.".to_string());
        help_bodies.insert("piv-import", "Loads a certificate file you already have (PEM or DER) into this slot. You'll need the management key.".to_string());
        help_bodies.insert("piv-export", "Saves this slot's certificate to a file on your computer. It's public information, so no PIN is needed.".to_string());
        help_bodies.insert("piv-delete", "Clearing the certificate leaves the key in place; erasing the private key removes it for good (and needs a YubiKey 5.7 or newer). Both are permanent and can't be undone.".to_string());
        help_bodies.insert("piv-admin", "These settings — the PIN and PUK, how many tries they allow, the management key, and a full reset — apply to the whole PIV applet, not to a single slot.".to_string());
        help_bodies.insert("molto", "A standalone token with its own screen that displays authenticator codes — no phone or app required. You program its slots here, then read the live codes right on the device.".to_string());
        help_bodies.insert("custkey", "An optional password that protects programming on this token. Leave it blank for the factory default. Enter it and Authenticate before writing any slot.".to_string());
        help_bodies.insert("reset", "A factory reset wipes every credential and PIN on the applet. It cannot be undone — keyroost asks you to type a confirmation and touch the key first.".to_string());
        help_bodies.insert("settings", "Change how this key enforces verification and PINs over CTAP 2.1 authenticatorConfig: always require user verification, raise the minimum PIN length, force a PIN change, or enable enterprise attestation. Some of these are one-way and can only be undone by a full reset, so keyroost confirms before applying them.".to_string());
        help_bodies.insert("large_blobs", "A key-global area where relying parties store opaque, RP-encrypted data (e.g. SSH certificates). Anyone holding the key can read it, so it is not a place for plaintext secrets. keyroost shows each stored entry as hex and ASCII; you can also keep your own plaintext notes here (add, edit, delete). Writing rewrites the whole array with a fresh checksum and needs your PIN. keyroost recognizes its own notes and OpenSSH certificates and shows a capacity meter; anything else is relying-party data, displayed raw and never modified. Any entry can be exported to a file.".to_string());

        let mut ui_strings = HashMap::new();
        ui_strings.insert("learn_link", "Learn how to use this  ↗".to_string());
        ui_strings.insert("what_is_this", "What's this?".to_string());
        ui_strings.insert("touch_to_begin", "Touch the sensor to begin…".to_string());

        Self {
            help_titles,
            help_bodies,
            ui_strings,
        }
    }

    fn chinese() -> Self {
        let mut help_titles = HashMap::new();
        help_titles.insert("device", "您的安全密钥".to_string());
        help_titles.insert("fido2", "通行密钥与 FIDO2".to_string());
        help_titles.insert("pin", "密钥的 PIN 码".to_string());
        help_titles.insert("passkeys", "驻留通行密钥".to_string());
        help_titles.insert("unlock", "解锁密钥".to_string());
        help_titles.insert("oath", "动态验证码 (OATH)".to_string());
        help_titles.insert("otp", "设备端 OTP".to_string());
        help_titles.insert("mds", "设备元数据 (FIDO MDS)".to_string());
        help_titles.insert("fingerprint", "指纹（生物识别注册）".to_string());
        help_titles.insert("touch-hotp", "HID-HOTP（触摸触发 HOTP）".to_string());
        help_titles.insert("pgp", "OpenPGP".to_string());
        help_titles.insert("pgp-keys", "生成或导入密钥".to_string());
        help_titles.insert("pgp-card-details", "持卡人姓名与 URL".to_string());
        help_titles.insert("piv", "PIV 智能卡".to_string());
        help_titles.insert("piv-generate", "生成密钥".to_string());
        help_titles.insert("piv-certificate", "创建证书".to_string());
        help_titles.insert("piv-import", "导入证书".to_string());
        help_titles.insert("piv-export", "导出证书".to_string());
        help_titles.insert("piv-delete", "从插槽删除".to_string());
        help_titles.insert("piv-admin", "卡片管理".to_string());
        help_titles.insert("molto", "可编程 TOTP 令牌".to_string());
        help_titles.insert("custkey", "客户密钥".to_string());
        help_titles.insert("reset", "重置密钥".to_string());
        help_titles.insert("settings", "安全策略".to_string());
        help_titles.insert("large_blobs", "大型数据存储".to_string());

        let mut help_bodies = HashMap::new();
        help_bodies.insert("device", "一个证明您身份的小型硬件设备。它保存的密钥在设备上生成，永远无法被复制出去——即使计算机被入侵，攻击者也无法窃取这些密钥。".to_string());
        help_bodies.insert("fido2", "FIDO2 让这个密钥充当通行密钥——一种防钓鱼的密码替代方案。网站记住您的密钥；您只需触摸它即可登录。任何敏感信息都不会离开设备。".to_string());
        help_bodies.insert("pin", "一个短 PIN 码，用于在这台计算机上解锁密钥的通行密钥。它不是您的账户密码，也永远不会离开密钥。输入错误次数过多，密钥会自动锁定以保护您。".to_string());
        help_bodies.insert("passkeys", "直接存储在密钥上的通行密钥（又称可发现凭证）。它们让您无需输入用户名即可登录。您可以在此查看和删除它们。".to_string());
        help_bodies.insert("unlock", "输入密钥的 PIN 码以解锁本次会话。解锁后可以管理通行密钥、指纹和安全设置；在您再次锁定或拔出密钥之前，它将保持解锁状态。PIN 码永远不会离开设备。".to_string());
        help_bodies.insert("oath", "通常从身份验证器应用获取的滚动 6 位数字代码——但存储在密钥本身上。即使手机丢失或被擦除，这些代码也能保留，并且永远不会同步到任何人的云端。".to_string());
        help_bodies.insert("otp", "存储在这个 Token2 密钥自己的 OTP 小程序上的 TOTP/HOTP 代码，通过 CCID/NFC 读取。添加条目、读取实时代码，以及（在支持的密钥上）通过触摸密钥触发代码。种子保存在设备上，永远不会同步到任何地方。".to_string());
        help_bodies.insert("mds", "FIDO 联盟发布的关于此身份验证器型号的详细信息，通过其 AAGUID 查询：供应商名称、图标、认证级别（例如 FIDO Certified L2）和日期、支持的协议版本等。此数据与 keyroost 捆绑，维护者可以通过从 FIDO 元数据重新生成来刷新它。".to_string());
        help_bodies.insert("fingerprint", "通过 CTAP2 authenticatorBioEnrollment 在生物识别密钥上注册、重命名和删除指纹。注册的指纹让密钥可以通过触摸而不是输入 PIN 码来满足用户验证。需要 PIN 码进行管理。模板保存在设备上，永远不会离开。".to_string());
        help_bodies.insert("touch-hotp", "配置一个 HOTP 插槽，当您在任何会话之外触摸密钥时，它会作为键盘输入输入新的代码。需要启用键盘（HID-HOTP）接口。您可以更改输入选项——发送回车、长触摸、数字键盘——而无需重新输入种子。".to_string());
        help_bodies.insert("pgp", "将密钥变成智能卡，用于加密和签名电子邮件和文件（以及 SSH）。私钥保存在卡上，永远不会接触您计算机的磁盘。".to_string());
        help_bodies.insert("pgp-keys", "三个密钥中的每一个——签名、解密、身份验证——都可以直接在卡上创建，也可以从您已有的 RSA-2048 文件导入。无论哪种方式都会覆盖该密钥中的任何内容，清除它的唯一方法是完全重置。您需要管理员 PIN，密钥可能会要求您触摸。".to_string());
        help_bodies.insert("pgp-card-details", "存储在卡上的可选标签：持卡人姓名和可以找到您公钥的网址。它们是公共信息，但写入它们仍需要管理员 PIN。".to_string());
        help_bodies.insert("piv", "美国政府智能卡标准，用于企业登录、VPN 和文档签名。在此管理：生成密钥、创建自签名证书或 CA 请求（在卡上签名）、导入证书、更改 PIN/PUK 和管理密钥，以及重置小程序。写入需要管理密钥（出厂默认 010203…0708）。".to_string());
        help_bodies.insert("piv-generate", "在此插槽内创建全新的私钥并显示其公钥。如果插槽已有密钥，这将永久覆盖它。您需要管理密钥。".to_string());
        help_bodies.insert("piv-certificate", "自签名证书直接存储到插槽中，可以立即使用。CSR 是您发送给证书颁发机构的请求文件，以便他们为您颁发证书。无论哪种方式，签名都在卡上进行，因此需要 PIN 码。".to_string());
        help_bodies.insert("piv-import", "将您已有的证书文件（PEM 或 DER）加载到此插槽中。您需要管理密钥。".to_string());
        help_bodies.insert("piv-export", "将此插槽的证书保存到计算机上的文件中。它是公共信息，因此不需要 PIN 码。".to_string());
        help_bodies.insert("piv-delete", "清除证书会保留密钥；擦除私钥会永久删除它（需要 YubiKey 5.7 或更新版本）。两者都是永久性的，无法撤销。".to_string());
        help_bodies.insert("piv-admin", "这些设置——PIN 和 PUK、允许的尝试次数、管理密钥和完全重置——适用于整个 PIV 小程序，而不是单个插槽。".to_string());
        help_bodies.insert("molto", "一个带有自己屏幕的独立令牌，显示身份验证器代码——无需手机或应用。您在此处编程其插槽，然后直接在设备上读取实时代码。".to_string());
        help_bodies.insert("custkey", "保护此令牌编程的可选密码。留空使用出厂默认值。在写入任何插槽之前输入它并进行身份验证。".to_string());
        help_bodies.insert("reset", "出厂重置会擦除小程序上的所有凭证和 PIN。它无法撤销——keyroost 要求您先输入确认信息并触摸密钥。".to_string());
        help_bodies.insert("settings", "更改此密钥通过 CTAP 2.1 authenticatorConfig 强制执行验证和 PIN 的方式：始终要求用户验证、提高最小 PIN 长度、强制更改 PIN 或启用企业证明。其中一些是单向的，只能通过完全重置来撤销，因此 keyroost 在应用它们之前会进行确认。".to_string());
        help_bodies.insert("large_blobs", "密钥全局区域，依赖方在此存储不透明的、RP 加密的数据（例如 SSH 证书）。任何持有密钥的人都可以读取它，因此它不是存储明文秘密的地方。keyroost 将每个存储的条目显示为十六进制和 ASCII；您也可以在此保存自己的明文笔记（添加、编辑、删除）。写入会用新的校验和重写整个数组，并且需要您的 PIN。keyroost 识别自己的笔记和 OpenSSH 证书，并显示容量表；任何其他内容都是依赖方数据，显示为原始数据且永远不会被修改。任何条目都可以导出到文件。".to_string());

        let mut ui_strings = HashMap::new();
        ui_strings.insert("learn_link", "了解如何使用此功能  ↗".to_string());
        ui_strings.insert("what_is_this", "这是什么？".to_string());
        ui_strings.insert("touch_to_begin", "触摸传感器开始…".to_string());

        Self {
            help_titles,
            help_bodies,
            ui_strings,
        }
    }

    pub fn help_title(&self, topic: &str) -> Option<&str> {
        self.help_titles.get(topic).map(String::as_str)
    }

    pub fn help_body(&self, topic: &str) -> Option<&str> {
        self.help_bodies.get(topic).map(String::as_str)
    }

    pub fn ui_string(&self, key: &str) -> Option<&str> {
        self.ui_strings.get(key).map(String::as_str)
    }
}

/// Get the current language from environment or default to English
pub fn detect_language() -> Language {
    if let Ok(lang) = std::env::var("KEYROOST_LANG") {
        if let Some(l) = Language::from_str(&lang) {
            return l;
        }
    }
    if let Ok(lang) = std::env::var("LANG") {
        if lang.starts_with("zh") {
            return Language::ZhCn;
        }
    }
    Language::En
}
