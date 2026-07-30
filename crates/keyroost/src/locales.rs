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
        ui_strings.insert("plug_key", "Plug in a security key to begin".to_string());
        ui_strings.insert("plug_key_desc", "keyroost manages YubiKeys, Nitrokeys, SoloKeys and Token2 tokens.\nConnect one over USB and it shows up in the list on the left.".to_string());
        ui_strings.insert("step1", "Insert your key into a USB port".to_string());
        ui_strings.insert("step2", "It appears in the Devices list automatically".to_string());
        ui_strings.insert("step3", "Select it to view and manage everything it can do".to_string());
        ui_strings.insert("scan_devices", "Scan for devices".to_string());
        ui_strings.insert("supported_devices", "Supported devices".to_string());
        ui_strings.insert("settings", "Settings".to_string());
        ui_strings.insert("language", "Language".to_string());
        ui_strings.insert("refresh", "Refresh".to_string());
        ui_strings.insert("devices", "DEVICES".to_string());
        ui_strings.insert("no_keys", "No keys detected yet.".to_string());
        ui_strings.insert("filter_keys", "Filter keys...".to_string());
        ui_strings.insert("overview", "Overview".to_string());
        ui_strings.insert("fido2", "FIDO2".to_string());
        ui_strings.insert("authenticator", "Authenticator".to_string());
        ui_strings.insert("openpgp", "OpenPGP".to_string());
        ui_strings.insert("piv", "PIV".to_string());
        ui_strings.insert("passkeys_signin", "Passkeys & sign-in (FIDO2)".to_string());
        ui_strings.insert("admin_rights_needed", "Administrator rights needed".to_string());
        ui_strings.insert("open_fido2_tab", "Open the FIDO2 tab to manage this key via Windows settings or restart as administrator.".to_string());
        ui_strings.insert("auth_codes_oath", "Authenticator codes (OATH)".to_string());
        ui_strings.insert("open_auth_view_codes", "Open Authenticator to view live codes.".to_string());
        ui_strings.insert("open_openpgp_status", "Open OpenPGP and Read status to view key slots.".to_string());
        ui_strings.insert("piv_smart_card", "PIV smart card".to_string());
        ui_strings.insert("open_piv_slots", "Open PIV to read certificate slots.".to_string());
        ui_strings.insert("factory_reset", "Factory reset".to_string());
        ui_strings.insert("factory_reset_desc", "Resets every applet on this key (OATH, OpenPGP, PIV, FIDO2) to factory state. Each step reports on its own — anything that doesn't complete is listed below.".to_string());
        ui_strings.insert("connected", "Connected".to_string());
        ui_strings.insert("name_this_key", "Name this key".to_string());
        ui_strings.insert("manage", "Manage".to_string());
        ui_strings.insert("several_keys", "Several keys plugged in? Give them names".to_string());
        ui_strings.insert("generate_key", "Generate key".to_string());
        ui_strings.insert("certificate", "Certificate".to_string());
        ui_strings.insert("name", "Name".to_string());
        ui_strings.insert("valid_for", "Valid for".to_string());
        ui_strings.insert("days", "days".to_string());
        ui_strings.insert("csr_file", "CSR file".to_string());
        ui_strings.insert("self_signed_slot", "Self-signed → slot".to_string());
        ui_strings.insert("save", "Save...".to_string());
        ui_strings.insert("sign_save_csr", "Sign & save CSR".to_string());
        ui_strings.insert("import_cert", "Import cert".to_string());
        ui_strings.insert("file", "File".to_string());
        ui_strings.insert("browse", "Browse...".to_string());
        ui_strings.insert("import_certificate", "Import certificate".to_string());
        ui_strings.insert("export_cert", "Export cert".to_string());
        ui_strings.insert("destination", "Destination".to_string());
        ui_strings.insert("export_certificate", "Export certificate".to_string());
        ui_strings.insert("delete", "Delete".to_string());
        ui_strings.insert("delete_certificate", "Delete certificate...".to_string());
        ui_strings.insert("delete_key", "Delete key...".to_string());
        ui_strings.insert("reset_applet", "Reset applet".to_string());
        ui_strings.insert("reset_applet_desc", "Wipes ALL PIV keys, certificates, and PINs. Only works when both the PIN and PUK are already blocked.".to_string());
        ui_strings.insert("state_empty", "State: empty".to_string());
        ui_strings.insert("generate", "Generate...".to_string());

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
        ui_strings.insert("plug_key", "插入安全密钥以开始".to_string());
        ui_strings.insert("plug_key_desc", "keyroost 管理 YubiKey、Nitrokey、SoloKeys 和 Token2 令牌。\n通过 USB 连接后，它会出现在左侧的列表中。".to_string());
        ui_strings.insert("step1", "将密钥插入 USB 端口".to_string());
        ui_strings.insert("step2", "它会自动出现在设备列表中".to_string());
        ui_strings.insert("step3", "选择它以查看和管理所有功能".to_string());
        ui_strings.insert("scan_devices", "扫描设备".to_string());
        ui_strings.insert("supported_devices", "支持的设备".to_string());
        ui_strings.insert("settings", "设置".to_string());
        ui_strings.insert("language", "语言".to_string());
        ui_strings.insert("refresh", "刷新".to_string());
        ui_strings.insert("devices", "设备".to_string());
        ui_strings.insert("no_keys", "尚未检测到密钥。".to_string());
        ui_strings.insert("filter_keys", "筛选密钥...".to_string());
        ui_strings.insert("overview", "概览".to_string());
        ui_strings.insert("fido2", "FIDO2".to_string());
        ui_strings.insert("authenticator", "身份验证器".to_string());
        ui_strings.insert("openpgp", "OpenPGP".to_string());
        ui_strings.insert("piv", "PIV".to_string());
        ui_strings.insert("passkeys_signin", "通行密钥与登录 (FIDO2)".to_string());
        ui_strings.insert("admin_rights_needed", "需要管理员权限".to_string());
        ui_strings.insert("open_fido2_tab", "打开 FIDO2 选项卡通过 Windows 设置管理此密钥，或以管理员身份重启。".to_string());
        ui_strings.insert("auth_codes_oath", "动态验证码 (OATH)".to_string());
        ui_strings.insert("open_auth_view_codes", "打开身份验证器查看实时验证码。".to_string());
        ui_strings.insert("open_openpgp_status", "打开 OpenPGP 并读取状态以查看密钥插槽。".to_string());
        ui_strings.insert("piv_smart_card", "PIV 智能卡".to_string());
        ui_strings.insert("open_piv_slots", "打开 PIV 读取证书插槽。".to_string());
        ui_strings.insert("factory_reset", "出厂重置".to_string());
        ui_strings.insert("factory_reset_desc", "将此密钥上的所有小程序 (OATH, OpenPGP, PIV, FIDO2) 重置为出厂状态。每个步骤单独报告 — 未完成的项目列在下方。".to_string());
        ui_strings.insert("connected", "已连接".to_string());
        ui_strings.insert("name_this_key", "命名此密钥".to_string());
        ui_strings.insert("manage", "管理".to_string());
        ui_strings.insert("several_keys", "插入了多个密钥？为它们命名".to_string());
        ui_strings.insert("generate_key", "生成密钥".to_string());
        ui_strings.insert("certificate", "证书".to_string());
        ui_strings.insert("name", "名称".to_string());
        ui_strings.insert("valid_for", "有效期".to_string());
        ui_strings.insert("days", "天".to_string());
        ui_strings.insert("csr_file", "CSR 文件".to_string());
        ui_strings.insert("self_signed_slot", "自签名 → 插槽".to_string());
        ui_strings.insert("save", "保存...".to_string());
        ui_strings.insert("sign_save_csr", "签名并保存 CSR".to_string());
        ui_strings.insert("import_cert", "导入证书".to_string());
        ui_strings.insert("file", "文件".to_string());
        ui_strings.insert("browse", "浏览...".to_string());
        ui_strings.insert("import_certificate", "导入证书".to_string());
        ui_strings.insert("export_cert", "导出证书".to_string());
        ui_strings.insert("destination", "目标路径".to_string());
        ui_strings.insert("export_certificate", "导出证书".to_string());
        ui_strings.insert("delete", "删除".to_string());
        ui_strings.insert("delete_certificate", "删除证书...".to_string());
        ui_strings.insert("delete_key", "删除密钥...".to_string());
        ui_strings.insert("reset_applet", "重置小程序".to_string());
        ui_strings.insert("reset_applet_desc", "清除所有 PIV 密钥、证书和 PIN。仅在 PIN 和 PUK 均已被阻止时有效。".to_string());
        ui_strings.insert("state_empty", "状态：空".to_string());
        ui_strings.insert("generate", "生成...".to_string());
        ui_strings.insert("passkeys_fido2", "通行密钥与登录 (FIDO2)".to_string());
        ui_strings.insert("manage_passkeys", "管理通行密钥".to_string());
        ui_strings.insert("oath_accounts", "OATH 账户".to_string());
        ui_strings.insert("manage_oath", "管理 OATH".to_string());
        ui_strings.insert("openpgp_keys", "OpenPGP 密钥".to_string());
        ui_strings.insert("manage_openpgp", "管理 OpenPGP".to_string());
        ui_strings.insert("piv_slots", "PIV 插槽".to_string());
        ui_strings.insert("manage_piv", "管理 PIV".to_string());
        ui_strings.insert("on_device_otp", "设备端 OTP".to_string());
        ui_strings.insert("manage_otp", "管理 OTP".to_string());
        ui_strings.insert("piv_smart_card", "PIV 智能卡".to_string());
        ui_strings.insert("applet_version", "小程序版本".to_string());
        ui_strings.insert("serial", "序列号".to_string());
        ui_strings.insert("pin_retries", "PIN 重试次数".to_string());
        ui_strings.insert("pin_puk", "PIN 与 PUK".to_string());
        ui_strings.insert("change_pin", "更改 PIN...".to_string());
        ui_strings.insert("change_puk", "更改 PUK...".to_string());
        ui_strings.insert("unblock_pin", "解锁 PIN...".to_string());
        ui_strings.insert("retry_counts", "重试次数".to_string());
        ui_strings.insert("pin_tries", "PIN 尝试次数".to_string());
        ui_strings.insert("puk_tries", "PUK 尝试次数".to_string());
        ui_strings.insert("set_retry_counts", "设置重试次数...".to_string());
        ui_strings.insert("management_key", "管理密钥".to_string());
        ui_strings.insert("change_management_key", "更改管理密钥...".to_string());
        ui_strings.insert("authentication_9a", "身份验证 (9A)".to_string());
        ui_strings.insert("signature_9c", "签名 (9C)".to_string());
        ui_strings.insert("key_management_9d", "密钥管理 (9D)".to_string());
        ui_strings.insert("card_authentication_9e", "卡片身份验证 (9E)".to_string());
        ui_strings.insert("admin_rights_needed", "需要管理员权限".to_string());
        ui_strings.insert("open_fido2_admin", "打开 FIDO2 选项卡通过 Windows 设置管理此密钥，或以管理员身份重启。".to_string());
        ui_strings.insert("pin_set", "已设置 PIN".to_string());
        ui_strings.insert("pin_configured_ready", "PIN 已配置 · 准备使用通行密钥".to_string());
        ui_strings.insert("reading_key", "读取密钥中...".to_string());
        ui_strings.insert("retry_counts", "重试次数".to_string());
        ui_strings.insert("pin_tries", "PIN 尝试次数".to_string());
        ui_strings.insert("puk_tries", "PUK 尝试次数".to_string());
        ui_strings.insert("set_retry_counts", "设置重试次数...".to_string());
        ui_strings.insert("management_key", "管理密钥".to_string());
        ui_strings.insert("change_management_key", "更改管理密钥...".to_string());
        ui_strings.insert("change_pin", "更改 PIN...".to_string());
        ui_strings.insert("change_puk", "更改 PUK...".to_string());
        ui_strings.insert("unblock_pin", "解锁 PIN...".to_string());
        ui_strings.insert("status", "状态".to_string());
        ui_strings.insert("locked", "已锁定".to_string());
        ui_strings.insert("unlocked", "已解锁".to_string());
        ui_strings.insert("enter_pin", "输入 PIN".to_string());
        ui_strings.insert("reset_key", "重置密钥".to_string());
        ui_strings.insert("reset_this_key", "重置此密钥".to_string());
        ui_strings.insert("reset_desc", "清除密钥上的所有凭证和 PIN。此操作无法撤销。".to_string());
        ui_strings.insert("save_certificate", "保存证书...".to_string());
        ui_strings.insert("manage_passkeys", "管理通行密钥".to_string());
        ui_strings.insert("manage_fingerprints", "管理指纹".to_string());
        ui_strings.insert("manage_settings", "管理设置".to_string());
        ui_strings.insert("manage_storage", "管理存储".to_string());
        ui_strings.insert("unlock_key", "解锁密钥".to_string());
        ui_strings.insert("lock_key", "锁定密钥".to_string());
        ui_strings.insert("change_key_pin", "更改密钥 PIN".to_string());
        ui_strings.insert("no_pin_configured", "未配置 PIN".to_string());
        ui_strings.insert("reading_key", "读取密钥中...".to_string());
        ui_strings.insert("open_auth_view", "打开身份验证器查看实时验证码。".to_string());
        ui_strings.insert("open_openpgp_view", "打开 OpenPGP 并读取状态以查看密钥插槽。".to_string());
        ui_strings.insert("open_piv_view", "打开 PIV 读取证书插槽。".to_string());
        ui_strings.insert("open_otp_view", "打开设备端 OTP 查看存储的条目。".to_string());
        ui_strings.insert("pin_sign_in", "PIN 与登录".to_string());
        ui_strings.insert("change_pin", "更改 PIN".to_string());
        ui_strings.insert("set_a_pin", "设置 PIN".to_string());
        ui_strings.insert("lock", "锁定".to_string());
        ui_strings.insert("pin_set_status", "已设置 PIN".to_string());
        ui_strings.insert("has_pin", "此密钥有 PIN。".to_string());
        ui_strings.insert("has_pin_unlock", "此密钥有 PIN。请在下方解锁以管理。".to_string());
        ui_strings.insert("no_pin_yet", "尚未设置 PIN".to_string());
        ui_strings.insert("set_pin_protect", "设置 PIN 以保护此密钥并启用通行密钥。".to_string());
        ui_strings.insert("no_pin_support", "不支持 PIN".to_string());
        ui_strings.insert("pin_not_supported", "此密钥不支持 PIN。".to_string());
        ui_strings.insert("couldnt_read_key", "无法读取此密钥。".to_string());
        ui_strings.insert("create_pin", "创建 PIN".to_string());
        ui_strings.insert("new_pin", "新 PIN".to_string());
        ui_strings.insert("confirm", "确认".to_string());
        ui_strings.insert("current_pin", "当前 PIN".to_string());
        ui_strings.insert("confirm_new_pin", "确认新 PIN".to_string());
        ui_strings.insert("set_pin", "设置 PIN".to_string());
        ui_strings.insert("cancel", "取消".to_string());
        ui_strings.insert("pin_length", "4–63 个字符。".to_string());
        ui_strings.insert("fido2_tab_admin", "FIDO2 选项卡需要管理员权限".to_string());
        ui_strings.insert("fido2_admin_desc", "已连接安全密钥，但在此应用中管理其 FIDO2 设置（PIN、通行密钥、重置、指纹）需要 Windows 管理员权限。".to_string());
        ui_strings.insert("fido2_admin_hint", "您可以使用 Windows 内置的安全密钥设置更改 PIN、管理生物识别或重置密钥（无需管理员权限），或以管理员身份重启此应用以进行完整管理。".to_string());
        ui_strings.insert("open_windows_settings", "打开 Windows 安全密钥设置".to_string());
        ui_strings.insert("restart_as_admin", "以管理员身份重启".to_string());
        ui_strings.insert("unlock_this_key", "解锁此密钥".to_string());
        ui_strings.insert("enter_pin_unlock", "输入 PIN 以解锁此密钥".to_string());
        ui_strings.insert("unlock", "解锁".to_string());
        ui_strings.insert("unlock_manage", "解锁以管理通行密钥、指纹和设置".to_string());
        ui_strings.insert("security_policy", "安全策略".to_string());
        ui_strings.insert("always_require_uv", "始终要求用户验证".to_string());
        ui_strings.insert("on", "开启".to_string());
        ui_strings.insert("off", "关闭".to_string());
        ui_strings.insert("min_pin_length", "最小 PIN 长度".to_string());
        ui_strings.insert("force_pin_change", "强制更改 PIN".to_string());
        ui_strings.insert("required_next_use", "下次使用时必需".to_string());
        ui_strings.insert("enterprise_attestation", "企业证明".to_string());
        ui_strings.insert("enabled", "已启用".to_string());
        ui_strings.insert("supported", "已支持".to_string());
        ui_strings.insert("unlock_change", "解锁以更改这些设置。".to_string());
        ui_strings.insert("passkeys", "通行密钥".to_string());
        ui_strings.insert("fingerprints", "指纹".to_string());
        ui_strings.insert("settings", "设置".to_string());
        ui_strings.insert("storage", "存储".to_string());
        ui_strings.insert("resident_passkeys", "驻留通行密钥".to_string());
        ui_strings.insert("reload", "刷新".to_string());
        ui_strings.insert("stored", "已存储".to_string());
        ui_strings.insert("room_for", "还可存储".to_string());
        ui_strings.insert("more", "个".to_string());
        ui_strings.insert("no_passkeys_stored", "此密钥上尚未存储通行密钥。".to_string());
        ui_strings.insert("no_credentials", "无凭证".to_string());
        ui_strings.insert("remove", "移除".to_string());
        ui_strings.insert("name_this_key", "命名此密钥".to_string());
        ui_strings.insert("openpgp_card", "OpenPGP 卡片".to_string());
        ui_strings.insert("read_status", "读取状态".to_string());
        ui_strings.insert("click_read_status", "点击「读取状态」以读取此卡片（无需 PIN 或触摸）。".to_string());
        ui_strings.insert("card_details", "卡片详情".to_string());
        ui_strings.insert("holder_name", "持卡人姓名".to_string());
        ui_strings.insert("public_url", "公钥 URL".to_string());
        ui_strings.insert("language_preferences", "语言偏好".to_string());
        ui_strings.insert("sex", "性别".to_string());
        ui_strings.insert("signature", "签名".to_string());
        ui_strings.insert("decryption", "解密".to_string());
        ui_strings.insert("authentication", "身份验证".to_string());
        ui_strings.insert("generate_on_card", "在卡片上生成".to_string());
        ui_strings.insert("generate_overwrites", "生成将覆盖此密钥（只能通过完全重置清除）。需要管理员 PIN；如果密钥闪烁请触摸它。".to_string());
        ui_strings.insert("import_rsa_2048", "导入 RSA-2048".to_string());
        ui_strings.insert("from_file", "从文件".to_string());
        ui_strings.insert("generate_import", "生成并导入...".to_string());
        ui_strings.insert("import_file", "导入文件...".to_string());
        ui_strings.insert("state_read_status", "读取状态以查看此密钥".to_string());
        ui_strings.insert("signatures_made", "已签名次数".to_string());
        ui_strings.insert("reset_applet", "重置小程序".to_string());
        ui_strings.insert("reset_applet_confirm", "确认重置".to_string());
        ui_strings.insert("reset_applet_warning", "此操作将清除小程序上的所有数据。此操作无法撤销。".to_string());
        ui_strings.insert("retired_slots", "已停用插槽".to_string());
        ui_strings.insert("retired_slot", "已停用插槽".to_string());
        ui_strings.insert("slot_empty", "空".to_string());
        ui_strings.insert("slot_has_key", "有密钥".to_string());
        ui_strings.insert("slot_has_cert", "有证书".to_string());
        ui_strings.insert("authenticator_tab", "身份验证器".to_string());
        ui_strings.insert("openpgp_tab", "OpenPGP".to_string());
        ui_strings.insert("piv_tab", "PIV".to_string());
        ui_strings.insert("fido2_tab", "FIDO2".to_string());
        ui_strings.insert("change_user_pin", "更改用户 PIN".to_string());
        ui_strings.insert("change_admin_pin", "更改管理员 PIN".to_string());
        ui_strings.insert("unblock_user_pin", "解锁用户 PIN".to_string());
        ui_strings.insert("card_holder_name", "持卡人姓名".to_string());
        ui_strings.insert("public_key_url", "公钥 URL".to_string());
        ui_strings.insert("new_credential", "新建凭证".to_string());
        ui_strings.insert("credential_added", "✓ 凭证已添加".to_string());
        ui_strings.insert("done", "完成".to_string());
        ui_strings.insert("issuer_account", "签发者:账户".to_string());
        ui_strings.insert("secret", "密钥".to_string());
        ui_strings.insert("base32_hint", "base32（QR 码后面）".to_string());
        ui_strings.insert("type", "类型".to_string());
        ui_strings.insert("require_touch", "需要触摸".to_string());
        ui_strings.insert("secret_sent_to_key", "密钥发送到设备，不会被 keyroost 写入磁盘。".to_string());
        ui_strings.insert("add", "添加".to_string());
        ui_strings.insert("delete_credential", "删除凭证？".to_string());
        ui_strings.insert("delete_credential_desc", "从此密钥永久删除「{name}」？此操作无法撤销。".to_string());
        ui_strings.insert("delete", "删除".to_string());
        ui_strings.insert("reset_oath", "重置 OATH 小程序？".to_string());
        ui_strings.insert("reset_oath_desc", "永久擦除此密钥上的所有身份验证器凭证并清除其密码？此操作无法撤销。".to_string());
        ui_strings.insert("reset_applet", "重置小程序".to_string());
        ui_strings.insert("factory_reset_key", "出厂重置此密钥？".to_string());
        ui_strings.insert("yes_wipe_key", "是的，擦除此密钥".to_string());
        ui_strings.insert("adding_credential", "添加凭证中...".to_string());
        ui_strings.insert("deleting_credential", "删除凭证中...".to_string());
        ui_strings.insert("resetting_oath", "重置 OATH 小程序中...".to_string());
        ui_strings.insert("generating_key", "生成密钥中...".to_string());
        ui_strings.insert("generating_key_touch", "生成密钥中...（如果密钥闪烁请触摸它）".to_string());
        ui_strings.insert("importing_key", "导入密钥中...".to_string());
        ui_strings.insert("setting_name", "设置持卡人姓名中...".to_string());
        ui_strings.insert("setting_url", "设置公钥 URL 中...".to_string());
        ui_strings.insert("changing_user_pin", "更改用户 PIN 中...".to_string());
        ui_strings.insert("changing_admin_pin", "更改管理员 PIN 中...".to_string());
        ui_strings.insert("unblocking_user_pin", "解锁用户 PIN 中...".to_string());
        ui_strings.insert("resetting_openpgp", "重置 OpenPGP 小程序中...".to_string());
        ui_strings.insert("pin_changed", "PIN 已更改".to_string());
        ui_strings.insert("admin_pin_changed", "管理员 PIN 已更改".to_string());
        ui_strings.insert("user_pin_unblocked", "用户 PIN 已解锁".to_string());
        ui_strings.insert("name_set", "持卡人姓名已设置".to_string());
        ui_strings.insert("url_set", "公钥 URL 已设置".to_string());
        ui_strings.insert("key_generated", "密钥已生成".to_string());
        ui_strings.insert("key_generated_imported", "密钥已生成并导入".to_string());
        ui_strings.insert("key_imported", "密钥已导入".to_string());
        ui_strings.insert("applet_reset", "小程序已重置".to_string());
        ui_strings.insert("piv_pin_changed", "PIV PIN 已更改".to_string());
        ui_strings.insert("piv_puk_changed", "PIV PUK 已更改".to_string());
        ui_strings.insert("piv_pin_unblocked", "PIV PIN 已解锁并重置".to_string());
        ui_strings.insert("piv_key_generated", "PIV 密钥已生成".to_string());
        ui_strings.insert("piv_cert_imported", "PIV 证书已导入".to_string());
        ui_strings.insert("piv_cert_created", "PIV 证书已创建".to_string());
        ui_strings.insert("piv_csr_signed", "PIV 证书请求已签名并保存".to_string());
        ui_strings.insert("piv_retries_set", "PIV 重试次数已设置".to_string());
        ui_strings.insert("piv_mgmt_key_changed", "PIV 管理密钥已更改".to_string());
        ui_strings.insert("piv_cert_deleted", "PIV 证书已删除".to_string());
        ui_strings.insert("piv_key_deleted", "PIV 密钥已删除".to_string());
        ui_strings.insert("piv_key_moved", "PIV 密钥已移动".to_string());
        ui_strings.insert("piv_factory_reset", "PIV 应用已恢复出厂设置".to_string());
        ui_strings.insert("reset_this_key", "重置此密钥".to_string());
        ui_strings.insert("reset_key", "重置密钥...".to_string());
        ui_strings.insert("reset_key_desc", "擦除此密钥上的所有通行密钥和 PIN。此操作无法撤销。".to_string());
        ui_strings.insert("security_policy", "安全策略".to_string());
        ui_strings.insert("no_auth_codes", "此密钥上没有身份验证器验证码。".to_string());
        ui_strings.insert("reset_applet", "重置小程序".to_string());
        ui_strings.insert("state_label", "状态".to_string());
        ui_strings.insert("state_read_status", "读取状态以查看此密钥".to_string());
        ui_strings.insert("several_keys", "插入了多个密钥".to_string());
        ui_strings.insert("give_names", "为它们命名".to_string());
        ui_strings.insert("connected", "已连接".to_string());
        ui_strings.insert("refresh", "刷新".to_string());
        ui_strings.insert("add_credential", "添加凭证".to_string());
        ui_strings.insert("card_details", "卡片详情".to_string());
        ui_strings.insert("name", "名称".to_string());
        ui_strings.insert("url", "URL".to_string());
        ui_strings.insert("pins", "PIN".to_string());
        ui_strings.insert("change_user_pin", "更改用户 PIN".to_string());
        ui_strings.insert("change_admin_pin", "更改管理员 PIN".to_string());
        ui_strings.insert("unblock_user_pin", "解锁用户 PIN".to_string());
        ui_strings.insert("set_name", "设置名称".to_string());
        ui_strings.insert("set_url", "设置 URL".to_string());
        ui_strings.insert("auth_9a", "身份验证 (9A)".to_string());
        ui_strings.insert("auth_9c", "签名 (9C)".to_string());
        ui_strings.insert("auth_9d", "密钥管理 (9D)".to_string());
        ui_strings.insert("auth_9e", "卡片身份验证 (9E)".to_string());
        ui_strings.insert("always_require_uv", "始终要求用户验证".to_string());
        ui_strings.insert("min_pin_length", "最小 PIN 长度".to_string());
        ui_strings.insert("enterprise_attestation", "企业证明".to_string());
        ui_strings.insert("unlock_to_change", "解锁以更改这些设置".to_string());
        ui_strings.insert("have_supported", "已支持".to_string());
        ui_strings.insert("force_pin_change", "下次使用时强制更改 PIN".to_string());
        ui_strings.insert("force_pin_hint", "在将密钥交给他人之前很有用。".to_string());
        ui_strings.insert("set_min_pin", "设置最小 PIN 长度".to_string());
        ui_strings.insert("set_min_pin_hint", "只能增加，不能在不重置的情况下减少。".to_string());
        ui_strings.insert("current_min", "当前最小值".to_string());
        ui_strings.insert("toggle", "切换".to_string());
        ui_strings.insert("enable_enterprise", "启用企业证明".to_string());
        ui_strings.insert("enterprise_on", "当前已启用。再次禁用需要设备重置。".to_string());
        ui_strings.insert("enterprise_off", "单向操作：再次禁用需要设备重置。".to_string());
        ui_strings.insert("force", "强制".to_string());
        ui_strings.insert("set", "设置...".to_string());
        ui_strings.insert("large_blob_storage", "大型数据存储".to_string());
        ui_strings.insert("large_blob_hint", "任何持有密钥的人都可以读取此存储。".to_string());
        ui_strings.insert("add_note", "添加笔记".to_string());
        ui_strings.insert("edit", "编辑".to_string());
        ui_strings.insert("clear_all", "清除全部".to_string());
        ui_strings.insert("export", "导出".to_string());
        ui_strings.insert("done", "完成".to_string());
        ui_strings.insert("add", "添加".to_string());
        ui_strings.insert("cancel", "取消".to_string());
        ui_strings.insert("delete", "删除".to_string());
        ui_strings.insert("save", "保存".to_string());
        ui_strings.insert("close", "关闭".to_string());
        ui_strings.insert("ok", "确定".to_string());
        ui_strings.insert("toggle", "切换".to_string());
        ui_strings.insert("set", "设置".to_string());
        ui_strings.insert("force", "强制".to_string());
        ui_strings.insert("enable", "启用".to_string());
        ui_strings.insert("apply", "应用".to_string());
        ui_strings.insert("copy", "复制".to_string());
        ui_strings.insert("edit", "编辑".to_string());
        ui_strings.insert("rename", "重命名".to_string());
        ui_strings.insert("remove", "移除".to_string());
        ui_strings.insert("reload", "刷新".to_string());
        ui_strings.insert("load", "加载".to_string());
        ui_strings.insert("collapse", "折叠".to_string());
        ui_strings.insert("erase_all", "擦除全部".to_string());
        ui_strings.insert("read_code", "读取验证码".to_string());
        ui_strings.insert("arm_reset", "准备重置".to_string());
        ui_strings.insert("yes_wipe_key", "是的，擦除此密钥".to_string());
        ui_strings.insert("yes_factory_reset", "是的，出厂重置".to_string());
        ui_strings.insert("yes_delete_seed", "是的，删除种子".to_string());
        ui_strings.insert("write_to_slot", "写入插槽".to_string());
        ui_strings.insert("write_title_only", "仅写入标题".to_string());
        ui_strings.insert("delete_seed", "删除种子...".to_string());
        ui_strings.insert("import_otpauth", "导入 otpauth...".to_string());
        ui_strings.insert("sync_time", "同步时间".to_string());
        ui_strings.insert("sync_time_all", "同步所有时间".to_string());
        ui_strings.insert("bulk_import", "批量导入".to_string());
        ui_strings.insert("factory_reset", "出厂重置...".to_string());
        ui_strings.insert("authenticate", "身份验证".to_string());
        ui_strings.insert("refresh_slots", "刷新插槽".to_string());
        ui_strings.insert("burn_seed", "写入种子".to_string());
        ui_strings.insert("copy_public_key", "复制公钥".to_string());
        ui_strings.insert("read_status", "读取状态".to_string());
        ui_strings.insert("set_url", "设置 URL...".to_string());
        ui_strings.insert("set_name", "设置名称...".to_string());
        ui_strings.insert("change_user_pin", "更改用户 PIN...".to_string());
        ui_strings.insert("change_admin_pin", "更改管理员 PIN...".to_string());
        ui_strings.insert("unblock_user_pin", "解锁用户 PIN...".to_string());
        ui_strings.insert("new_credential", "新建凭证".to_string());
        ui_strings.insert("delete_credential", "删除凭证？".to_string());
        ui_strings.insert("reset_oath_applet", "重置 OATH 小程序？".to_string());
        ui_strings.insert("factory_reset_key", "出厂重置此密钥？".to_string());
        ui_strings.insert("reset_security_key", "重置安全密钥？".to_string());
        ui_strings.insert("delete_fingerprint", "删除指纹？".to_string());
        ui_strings.insert("card_details", "卡片详情".to_string());
        ui_strings.insert("pin_retries", "PIN 重试".to_string());
        ui_strings.insert("site_name", "站点名称".to_string());
        ui_strings.insert("site_url", "站点 URL".to_string());
        ui_strings.insert("add_note", "添加笔记".to_string());
        ui_strings.insert("large_blob_storage", "大型数据存储".to_string());
        ui_strings.insert("security_policy", "安全策略".to_string());
        ui_strings.insert("resident_passkeys", "驻留通行密钥".to_string());
        ui_strings.insert("fingerprints", "指纹".to_string());
        ui_strings.insert("storage", "存储".to_string());
        ui_strings.insert("passkeys", "通行密钥".to_string());
        ui_strings.insert("settings", "设置".to_string());
        ui_strings.insert("on_device_otp", "设备端 OTP".to_string());
        ui_strings.insert("authenticator_codes", "身份验证器验证码".to_string());

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
