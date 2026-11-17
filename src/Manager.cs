using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Automation;
using System.Windows.Forms;

namespace ValoAccounts {
    public class Account {
        public string Id { get; set; }
        public string Label { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public bool Mfa { get; set; }
        public string Email { get; set; }
        public string EmailPassword { get; set; }
        public string EmailUrl { get; set; }
        public Account() { Id = Guid.NewGuid().ToString("N"); Label = Username = Password = Email = EmailPassword = EmailUrl = ""; }
        public override string ToString() { return String.IsNullOrWhiteSpace(Label) ? Username : Label; }
    }
    public class VaultData {
        public int Version { get; set; }
        public string RiotPath { get; set; }
        public List<Account> Accounts { get; set; }
        public VaultData() { Version = 1; RiotPath = ""; Accounts = new List<Account>(); }
    }
    public static class Vault {
        public static string UserDirectory { get { return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data"); } }
        public static VaultData LoadOrMigrate(string path, IEnumerable<string> legacyPaths) {
            if (File.Exists(path)) return Load(path);
            foreach (string legacy in legacyPaths) {
                if (!File.Exists(legacy) || String.Equals(Path.GetFullPath(path), Path.GetFullPath(legacy), StringComparison.OrdinalIgnoreCase)) continue;
                var data = Load(legacy); Save(path, data); return data;
            }
            return new VaultData();
        }
        static readonly byte[] Entropy = Encoding.UTF8.GetBytes("ValoAccounts.LocalVault.v1");
        public static byte[] Encode(VaultData data) {
            byte[] clear = Encoding.UTF8.GetBytes(new JavaScriptSerializer().Serialize(data));
            try { return ProtectedData.Protect(clear, Entropy, DataProtectionScope.CurrentUser); }
            finally { Array.Clear(clear, 0, clear.Length); }
        }
        public static VaultData Decode(byte[] bytes) {
            byte[] clear = ProtectedData.Unprotect(bytes, Entropy, DataProtectionScope.CurrentUser);
            try {
                var data = new JavaScriptSerializer().Deserialize<VaultData>(Encoding.UTF8.GetString(clear));
                if (data == null || data.Version != 1 || data.Accounts == null) throw new InvalidDataException();
                var ids = new HashSet<string>();
                foreach (var a in data.Accounts) {
                    if (a == null || String.IsNullOrEmpty(a.Id) || !ids.Add(a.Id) ||
                        String.IsNullOrWhiteSpace(a.Username) || String.IsNullOrEmpty(a.Password)) throw new InvalidDataException();
                    a.Label = a.Label ?? ""; a.Email = a.Email ?? ""; a.EmailPassword = a.EmailPassword ?? ""; a.EmailUrl = a.EmailUrl ?? "";
                }
                return data;
            } finally { Array.Clear(clear, 0, clear.Length); }
        }
        public static VaultData Load(string path) { return File.Exists(path) ? Decode(File.ReadAllBytes(path)) : new VaultData(); }
        public static VaultData Clone(VaultData data) { return new JavaScriptSerializer().Deserialize<VaultData>(new JavaScriptSerializer().Serialize(data)); }
        public static void Save(string path, VaultData data) {
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            string temp = path + ".tmp";
            byte[] bytes = Encode(data);
            try {
                using (var fs = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None)) { fs.Write(bytes, 0, bytes.Length); fs.Flush(true); }
                if (File.Exists(path)) File.Replace(temp, path, path + ".bak"); else File.Move(temp, path);
            } finally { if (File.Exists(temp)) File.Delete(temp); }
        }
    }
    public static class MailLinks {
        public static string Suggest(string email) {
            string domain = (email ?? "").Split('@').Last().Trim().ToLowerInvariant();
            switch (domain) {
                case "gmail.com": case "googlemail.com": return "https://mail.google.com/";
                case "outlook.com": case "hotmail.com": case "live.com": case "msn.com": return "https://outlook.live.com/mail/";
                case "qq.com": case "foxmail.com": return "https://mail.qq.com/";
                case "163.com": return "https://mail.163.com/";
                case "126.com": return "https://mail.126.com/";
                case "yeah.net": return "https://mail.yeah.net/";
                case "icloud.com": case "me.com": case "mac.com": return "https://www.icloud.com/mail/";
                case "proton.me": case "protonmail.com": return "https://mail.proton.me/";
                case "yahoo.com": return "https://mail.yahoo.com/";
                default: return "";
            }
        }
        public static string Normalize(string value) {
            string text = (value ?? "").Trim();
            if (text.Length == 0) return "";
            if (text.StartsWith("//", StringComparison.Ordinal)) text = "https:" + text;
            else if (text.IndexOf("://", StringComparison.Ordinal) < 0) text = "https://" + text;
            Uri uri;
            return Uri.TryCreate(text, UriKind.Absolute, out uri) ? uri.AbsoluteUri : text;
        }
        public static bool Valid(string value) {
            Uri uri;
            return Uri.TryCreate(Normalize(value), UriKind.Absolute, out uri) && uri.Scheme == "https" &&
                !String.IsNullOrEmpty(uri.Host) && String.IsNullOrEmpty(uri.UserInfo) && !uri.IsLoopback && uri.Host.Contains(".");
        }
        public static bool ValidEmail(string email) {
            try { var address = new System.Net.Mail.MailAddress(email); return address.Address == email && email.Contains("@"); }
            catch { return false; }
        }
    }
    public static class SafeClipboard {
        [DllImport("user32.dll")] static extern uint GetClipboardSequenceNumber();
        static uint sequence;
        static System.Windows.Forms.Timer timer;
        public static void Copy(string value) {
            if (String.IsNullOrEmpty(value)) return;
            var payload = new DataObject();
            payload.SetData("CanIncludeInClipboardHistory", false, new MemoryStream(new byte[4]));
            payload.SetData("CanUploadToCloudClipboard", false, new MemoryStream(new byte[4]));
            payload.SetData("ExcludeClipboardContentFromMonitorProcessing", false, new MemoryStream(new byte[] { 1 }));
            payload.SetText(value, TextDataFormat.UnicodeText);
            Clipboard.SetDataObject(payload, true); sequence = GetClipboardSequenceNumber();
            if (timer == null) { timer = new System.Windows.Forms.Timer { Interval = 30000 }; timer.Tick += delegate { Clear(); }; }
            timer.Stop(); timer.Start();
        }
        public static void Clear() {
            if (timer != null) timer.Stop();
            try { if (sequence != 0 && sequence == GetClipboardSequenceNumber()) Clipboard.Clear(); } catch { }
            sequence = 0;
        }
    }
    public static class I18n {
        public static bool English;
        static readonly Dictionary<string, string> Translations = new Dictionary<string, string> {
            { "未填写", "Not provided" },
            { "复制邮箱", "Copy email" },
            { "复制邮箱密码", "Copy email password" },
            { "未完成", "Not completed" },
            { "添加账号", "Add account" },
            { "编辑账号", "Edit account" },
            { "添加一个账号", "Add account" },
            { "编辑账号资料", "Edit account" },
            { "账号备注", "Note" },
            { "Riot 登录名 *", "Riot username *" },
            { "Riot 密码 *", "Riot password *" },
            { "邮箱地址", "Email address" },
            { "邮箱密码", "Email password" },
            { "邮箱登录网址", "Email login URL" },
            { "显示密码", "Show passwords" },
            { "取消", "Cancel" },
            { "保存账号", "Save account" },
            { "请填写 Riot 登录名和密码。", "Enter your Riot username and password." },
            { "邮箱地址格式不正确。", "Enter a valid email address." },
            { "请先填写关联邮箱地址。", "Enter the associated email address first." },
            { "邮箱登录网址可以留空；若填写，请使用有效域名或 HTTPS 网址，例如 mail.zsthost.com。", "The email URL is optional. If entered, use a valid domain or HTTPS URL, such as mail.zsthost.com." },
            { "Windows 阻止了输入。请让两个程序以相同的普通用户权限运行。", "Windows blocked input. Run both apps under the same standard user permissions." },
            { "窗口或输入焦点发生变化，已停止填入。请检查 Riot 登录框后再试。", "The active window or input focus changed. Input stopped. Check the Riot login form and retry." },
            { "请先选择正确的 RiotClientServices.exe。", "Select RiotClientServices.exe first." },
            { "未能确认 Riot 的账号和密码输入框。可能已登录、客户端尚未加载，或当前版本未向 Windows 提供输入框信息。\n\n诊断记录已保存到 EXE 同目录 data/diagnostics/fill-status.log（不含账密）。可通过“账号资料”手动复制。", "Could not identify the Riot login fields. You may already be signed in, the client may still be loading, or accessibility information may be unavailable.\n\nDiagnostics: data/diagnostics/fill-status.log next to the EXE (no credentials). Use Account details to copy manually." },
            { "+ 添加账号", "+ Add account" },
            { "搜索", "Search" },
            { "账号", "Account" },
            { "Riot 登录名", "Riot username" },
            { "邮箱", "Email" },
            { "请在编辑账号中填写有效的邮箱登录网址。", "Edit the account and enter a valid email login URL." },
            { "无法打开默认浏览器，请检查 Windows 默认浏览器设置。", "Could not open the default browser. Check Windows browser settings." },
            { "编辑", "Edit" },
            { "删除", "Delete" },
            { "账号资料", "Account details" },
            { "客户端位置", "Client location" },
            { "更多 ···", "More ···" },
            { "启动并填入 →", "Launch & fill →" },
            { "正在停止填入，请稍候…", "Stopping input…" },
            { "暂无账号", "No accounts yet" },
            { "无匹配账号", "No matching accounts" },
            { "已选中：", "Selected: " },
            { "无法保存加密账号库。请检查文件夹是否可写、磁盘空间是否充足。原有账号未被替换。", "Could not save the encrypted vault. Check folder permissions and free disk space. Existing accounts were not replaced." },
            { "删除“", "Delete “" },
            { "”及其保存的游戏、邮箱资料？", "” and its saved game and email credentials?" },
            { "删除账号", "Delete account" },
            { "账号资料 · ", "Account details · " },
            { "手动填入备用", "Manual entry" },
            { "复制登录名", "Copy username" },
            { "剪贴板暂时不可用。", "Clipboard is temporarily unavailable." },
            { "Riot 密码", "Riot password" },
            { "复制密码", "Copy password" },
            { "复制后 30 秒或关闭时清除，并请求 Windows 不保留历史。", "Cleared after 30 seconds or on close. Windows history exclusion requested." },
            { "选择 RiotClientServices.exe", "Select RiotClientServices.exe" },
            { "Riot 客户端|RiotClientServices.exe", "Riot client|RiotClientServices.exe" },
            { "正在检测 Riot 登录框，出现后立即尝试填入（超时 12 秒）… 请暂时不要切换窗口。", "Waiting for Riot login fields (12-second timeout)… Keep the client in focus." },
            { "已取消填入。", "Input cancelled." },
            { "未能完成填入。请检查 Riot 登录窗口，或使用“账号资料”手动复制。没有提交登录。", "Input failed. Check the Riot login window or copy from Account details. Login was not submitted." },
            { "账号管理器已经打开，请切换到现有窗口。", "ValAccount is already open. Switch to the existing window." },
            { "VALO 账号启动器", "ValAccount By Noiric" },
            { "无法读取、迁移或解密账号库。请确认使用原来的 Windows 用户、EXE 所在文件夹可写，且文件未损坏。\n\n程序不会覆盖原文件；data 中的 .bak 是上一版加密备份。", "Could not read, migrate, or decrypt the vault. Use the original Windows user, check that the EXE folder is writable and the file is intact.\n\nThe original file is retained. The .bak file in data is the previous encrypted backup." },
            { "账号库未打开", "Vault unavailable" },
            { "没有的可以不填写。", "Leave unavailable fields blank." },
            { "带 * 为必填项。", "* Required." },
            { "Riot 账号", "Riot account" },
            { "关联邮箱（选填）", "Linked email (optional)" },
            { "例如：主账号 · 亚服", "e.g. Main · AP" },
            { "可留空，常见邮箱会自动识别", "Optional; common providers are detected" },
            { "搜索账号、登录名或邮箱", "Search accounts, usernames or email" },
            { "还没有账号。点击右上角“+ 添加账号”开始。", "No accounts yet. Click “+ Add account” to get started." },
            { "没有匹配的账号，换个关键词试试。", "No matching accounts. Try another keyword." },
            { "添加账号后，双击即可启动并填入。", "Add an account, then double-click it to launch & fill." },
            { " 个账号 · 双击账号即可启动并填入", " account(s) · Double-click to launch & fill" },
            { "已复制", "Copied" }
        };
        public static string T(string text) { string result; return English && Translations.TryGetValue(text, out result) ? result : text; }
        public static bool LoadPreference() {
            try { string value = File.ReadAllText(Path.Combine(Vault.UserDirectory, "language.txt")).Trim();
                if (value != "en" && value != "zh") return false;
                English = value == "en"; return true;
            } catch { return false; }
        }
        public static void SavePreference() {
            Directory.CreateDirectory(Vault.UserDirectory);
            File.WriteAllText(Path.Combine(Vault.UserDirectory, "language.txt"), English ? "en" : "zh");
        }
    }
    public class LanguageForm : Form {
        public LanguageForm() {
            Theme.Form(this, "ValAccount By Noiric", 440, 262); MinimizeBox = false; ShowInTaskbar = false;
            Theme.Label(this, "语言 / Language", 32, 22, 376, 34, 16, false, true);
            Theme.Label(this, "选择界面语言 / Choose display language", 32, 58, 376, 22, 9.5f, true);
            bool english = I18n.English;
            RoundedButton zh = null, en = null;
            zh = Theme.Button(this, "简体中文", 32, 100, 182, 56, false, delegate { english = false; zh.Checked = true; en.Checked = false; });
            en = Theme.Button(this, "English", 226, 100, 182, 56, false, delegate { english = true; en.Checked = true; zh.Checked = false; });
            zh.Checked = !english; en.Checked = english;
            var next = Theme.Button(this, "继续 / Continue", 238, 190, 170, 42, true, delegate {
                bool previous = I18n.English; I18n.English = english;
                try { I18n.SavePreference(); }
                catch { I18n.English = previous; Theme.Error(this, "无法保存语言设置 / Could not save language. Check folder permissions."); return; }
                DialogResult = DialogResult.OK; Close();
            });
            AcceptButton = next;
        }
    }
    public class RoundedButton : Button {
        bool hover, pressed, isChecked;
        public bool Primary, Danger;
        public Color Surface = Color.Empty;
        public bool Checked { get { return isChecked; } set { isChecked = value; Invalidate(); } }
        public RoundedButton() {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            FlatStyle = FlatStyle.Flat; FlatAppearance.BorderSize = 0; Cursor = Cursors.Hand; UseVisualStyleBackColor = false;
        }
        protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { hover = pressed = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(MouseEventArgs e) { if (e.Button == MouseButtons.Left) { pressed = true; Invalidate(); } base.OnMouseDown(e); }
        protected override void OnMouseUp(MouseEventArgs e) { pressed = false; Invalidate(); base.OnMouseUp(e); }
        protected override void OnEnabledChanged(EventArgs e) { if (!Enabled) hover = pressed = false; Invalidate(); base.OnEnabledChanged(e); }
        protected override void OnTextChanged(EventArgs e) { Invalidate(); base.OnTextChanged(e); }
        protected override void OnPaint(PaintEventArgs e) {
            var g = e.Graphics; g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            g.Clear(Surface != Color.Empty ? Surface : Parent == null ? Theme.Bg : Parent.BackColor);
            Color fill, border, fore;
            if (Primary) {
                fill = !Enabled ? Color.FromArgb(239, 186, 190) : pressed ? Color.FromArgb(172, 28, 39) : hover ? Theme.AccentDark : Theme.Accent;
                border = fill; fore = Color.White;
            } else if (isChecked) {
                fill = Theme.AccentSoft; border = Theme.Accent; fore = Theme.Text;
            } else {
                fill = !Enabled ? Color.FromArgb(246, 246, 248) : pressed ? Color.FromArgb(236, 237, 241) : hover ? Theme.Hover : Theme.Card;
                border = Enabled && hover ? Color.FromArgb(206, 208, 214) : Theme.Border;
                fore = !Enabled ? Color.FromArgb(170, 170, 178) : Danger ? Theme.Accent : Theme.Text;
            }
            var rect = new RectangleF(.5f, .5f, Width - 1f, Height - 1f);
            using (var path = Theme.Round(rect, 9)) {
                using (var b = new SolidBrush(fill)) g.FillPath(b, path);
                using (var pen = new Pen(border, isChecked ? 1.5f : 1f)) g.DrawPath(pen, path);
            }
            if (Focused && ShowFocusCues && Enabled) {
                var inner = new RectangleF(2.5f, 2.5f, Width - 5f, Height - 5f);
                using (var path = Theme.Round(inner, 7)) using (var pen = new Pen(Primary ? Color.White : Theme.Accent, 1.5f)) g.DrawPath(pen, path);
            }
            TextRenderer.DrawText(g, Text, Font, ClientRectangle, fore, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
        }
    }
    public class MenuRenderer : ToolStripProfessionalRenderer {
        protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e) { e.Graphics.Clear(Theme.Card); }
        protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e) {
            using (var pen = new Pen(Theme.Border)) e.Graphics.DrawRectangle(pen, 0, 0, e.ToolStrip.Width - 1, e.ToolStrip.Height - 1);
        }
        protected override void OnRenderImageMargin(ToolStripRenderEventArgs e) { }
        protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e) {
            if (!e.Item.Selected || !e.Item.Enabled) return;
            e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            using (var path = Theme.Round(new RectangleF(4, 1, e.Item.Width - 8, e.Item.Height - 2), 6)) using (var b = new SolidBrush(Theme.AccentSoft)) e.Graphics.FillPath(b, path);
        }
        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e) { e.TextColor = e.Item.Enabled ? Theme.Text : Theme.Muted; base.OnRenderItemText(e); }
    }
    public static class Theme {
        public static Color Bg = Color.FromArgb(244, 245, 248), Card = Color.White, Text = Color.FromArgb(24, 24, 27), Muted = Color.FromArgb(113, 113, 122),
            Border = Color.FromArgb(226, 228, 233), Field = Color.FromArgb(248, 249, 251), Hover = Color.FromArgb(246, 247, 250), Divider = Color.FromArgb(240, 241, 244),
            Accent = Color.FromArgb(220, 48, 59), AccentDark = Color.FromArgb(194, 34, 46), AccentSoft = Color.FromArgb(254, 239, 240);
        static readonly Dictionary<string, Font> fonts = new Dictionary<string, Font>();
        public static Font Font(float size, bool bold) {
            string name = I18n.English ? "Segoe UI" : "Microsoft YaHei UI";
            FontStyle style = bold ? FontStyle.Bold : FontStyle.Regular;
            string key = name + "|" + size + "|" + style;
            Font font;
            if (!fonts.TryGetValue(key, out font)) { font = new Font(name, size, style); fonts[key] = font; }
            return font;
        }
        [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr SendMessage(IntPtr hwnd, int msg, IntPtr wParam, string lParam);
        static int ColorRef(Color c) { return c.R | (c.G << 8) | (c.B << 16); }
        public static System.Drawing.Drawing2D.GraphicsPath Round(RectangleF r, float radius) {
            var p = new System.Drawing.Drawing2D.GraphicsPath(); float d = radius * 2;
            p.AddArc(r.Left, r.Top, d, d, 180, 90); p.AddArc(r.Right - d, r.Top, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90); p.AddArc(r.Left, r.Bottom - d, d, d, 90, 90); p.CloseFigure(); return p;
        }
        public static void Form(Form f, string title, int w, int h) {
            f.Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            f.Text = title; f.ClientSize = new Size(w, h); f.BackColor = Bg; f.ForeColor = Text;
            f.Font = Font(10, false); f.StartPosition = FormStartPosition.CenterScreen;
            f.FormBorderStyle = FormBorderStyle.FixedSingle; f.MaximizeBox = false; f.AutoScaleMode = AutoScaleMode.Dpi;
            typeof(Control).GetProperty("DoubleBuffered", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance).SetValue(f, true, null);
            // Windows 11: tint the title bar to match the window background. Ignored on older systems.
            f.HandleCreated += delegate {
                try { int caption = ColorRef(Bg), text = ColorRef(Text); DwmSetWindowAttribute(f.Handle, 35, ref caption, 4); DwmSetWindowAttribute(f.Handle, 36, ref text, 4); } catch { }
            };
        }
        public static void Surface(Control p, Rectangle r) {
            p.Paint += delegate(object sender, PaintEventArgs e) {
                e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                using (var path = Round(new RectangleF(r.X + .5f, r.Y + .5f, r.Width - 1f, r.Height - 1f), 12)) {
                    using (var b = new SolidBrush(Card)) e.Graphics.FillPath(b, path);
                    using (var pen = new Pen(Border)) e.Graphics.DrawPath(pen, path);
                }
            };
        }
        public static Label Label(Control p, string text, int x, int y, int w, int h, float size, bool muted, bool bold = false) {
            var c = new Label { Text = text, Location = new Point(x, y), Size = new Size(w, h), ForeColor = muted ? Muted : Text, Font = Font(size, bold), BackColor = Color.Transparent, UseMnemonic = false, AutoEllipsis = true };
            p.Controls.Add(c); return c;
        }
        public static RoundedButton Button(Control p, string text, int x, int y, int w, int h, bool accent, EventHandler click) {
            var c = new RoundedButton { Text = text, Location = new Point(x, y), Size = new Size(w, h), Primary = accent, BackColor = accent ? Accent : Card, ForeColor = accent ? Color.White : Text, Font = Font(10, accent) };
            c.Click += click; p.Controls.Add(c); return c;
        }
        public static TextBox Input(Control p, int x, int y, int w, bool secret) {
            var c = new TextBox { BackColor = Card, ForeColor = Text, BorderStyle = BorderStyle.None, UseSystemPasswordChar = secret, MaxLength = 512 };
            var shell = new Panel { Location = new Point(x - 1, y - 7), Size = new Size(w + 2, 40), BackColor = Color.Transparent, Cursor = Cursors.IBeam };
            bool hover = false;
            p.Controls.Add(shell); shell.SendToBack();
            shell.Paint += delegate(object sender, PaintEventArgs e) {
                e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                using (var path = Round(new RectangleF(.5f, .5f, shell.Width - 1.5f, shell.Height - 1.5f), 8)) {
                    using (var fill = new SolidBrush(c.BackColor)) e.Graphics.FillPath(fill, path);
                    Color line = c.Focused ? Accent : hover && !c.ReadOnly ? Color.FromArgb(200, 202, 209) : Border;
                    using (var pen = new Pen(line, c.Focused ? 1.5f : 1f)) e.Graphics.DrawPath(pen, path);
                }
            };
            EventHandler enter = delegate { hover = true; shell.Invalidate(); }, leave = delegate { hover = shell.ClientRectangle.Contains(shell.PointToClient(Cursor.Position)); shell.Invalidate(); };
            shell.MouseEnter += enter; c.MouseEnter += enter; shell.MouseLeave += leave; c.MouseLeave += leave;
            shell.Click += delegate { c.Focus(); };
            c.GotFocus += delegate { shell.Invalidate(); }; c.LostFocus += delegate { shell.Invalidate(); };
            c.BackColorChanged += delegate { shell.Invalidate(); };
            // Fixed height with spare room below the text so descenders and underscores are not clipped.
            shell.Controls.Add(c); c.AutoSize = false; int textHeight = c.Font.Height;
            c.Size = new Size(w - 22, textHeight + 6); c.Location = new Point(12, Math.Max(0, (shell.Height - textHeight) / 2)); return c;
        }
        public static void Placeholder(TextBox c, string text) {
            EventHandler apply = delegate { SendMessage(c.Handle, 0x1501, (IntPtr)1, text); };
            if (c.IsHandleCreated) apply(c, EventArgs.Empty);
            c.HandleCreated += apply;
        }
        public static CheckBox Check(Control p, string text, int x, int y, int w) {
            var c = new CheckBox { Text = text, Location = new Point(x, y), Size = new Size(w, 26), Font = Font(9.5f, false), ForeColor = Text, BackColor = Color.Transparent, Cursor = Cursors.Hand };
            p.Controls.Add(c); return c;
        }
        public static void Error(IWin32Window owner, string text) { MessageBox.Show(owner, text, I18n.T("未完成"), MessageBoxButtons.OK, MessageBoxIcon.Information); }
    }
    public class EditForm : Form {
        public Account Result;
        TextBox label, user, pass, email, emailPass, url;
        public EditForm(Account account) {
            Theme.Form(this, account == null ? I18n.T("添加账号") : I18n.T("编辑账号"), 600, 624); MinimizeBox = false; ShowInTaskbar = false;
            Theme.Label(this, account == null ? I18n.T("添加一个账号") : I18n.T("编辑账号资料"), 32, 22, 536, 34, 16, false, true);
            Theme.Label(this, I18n.T("没有的可以不填写。") + "  " + I18n.T("带 * 为必填项。"), 32, 58, 536, 22, 9.5f, true);

            Theme.Surface(this, new Rectangle(32, 96, 536, 214));
            Theme.Label(this, I18n.T("Riot 账号"), 52, 112, 496, 24, 10.5f, false, true);
            Theme.Label(this, I18n.T("账号备注"), 52, 146, 496, 22, 9.5f, true);
            label = Theme.Input(this, 52, 177, 496, false); label.MaxLength = 80;
            Theme.Label(this, I18n.T("Riot 登录名 *"), 52, 226, 240, 22, 9.5f, true);
            user = Theme.Input(this, 52, 257, 240, false);
            Theme.Label(this, I18n.T("Riot 密码 *"), 308, 226, 240, 22, 9.5f, true);
            pass = Theme.Input(this, 308, 257, 240, true);

            Theme.Surface(this, new Rectangle(32, 326, 536, 214));
            Theme.Label(this, I18n.T("关联邮箱（选填）"), 52, 342, 496, 24, 10.5f, false, true);
            Theme.Label(this, I18n.T("邮箱地址"), 52, 376, 240, 22, 9.5f, true);
            email = Theme.Input(this, 52, 407, 240, false);
            Theme.Label(this, I18n.T("邮箱密码"), 308, 376, 240, 22, 9.5f, true);
            emailPass = Theme.Input(this, 308, 407, 240, true);
            Theme.Label(this, I18n.T("邮箱登录网址"), 52, 456, 496, 22, 9.5f, true);
            url = Theme.Input(this, 52, 487, 496, false); url.MaxLength = 2048;

            Theme.Placeholder(label, I18n.T("例如：主账号 · 亚服"));
            Theme.Placeholder(email, "name@example.com");
            Theme.Placeholder(url, I18n.T("可留空，常见邮箱会自动识别"));

            var reveal = Theme.Check(this, I18n.T("显示密码"), 32, 567, 200);
            reveal.CheckedChanged += delegate { pass.UseSystemPasswordChar = emailPass.UseSystemPasswordChar = !reveal.Checked; };
            string previousEmail = account == null ? "" : account.Email;
            email.Leave += delegate {
                if (String.IsNullOrWhiteSpace(url.Text) || url.Text == MailLinks.Suggest(previousEmail)) url.Text = MailLinks.Suggest(email.Text);
                previousEmail = email.Text;
            };
            var cancel = Theme.Button(this, I18n.T("取消"), 332, 560, 104, 40, false, delegate { Close(); });
            var save = Theme.Button(this, I18n.T("保存账号"), 448, 560, 120, 40, true, delegate {
                if (String.IsNullOrWhiteSpace(user.Text) || String.IsNullOrEmpty(pass.Text)) { Theme.Error(this, I18n.T("请填写 Riot 登录名和密码。")); return; }
                if (!String.IsNullOrWhiteSpace(email.Text) && !MailLinks.ValidEmail(email.Text.Trim())) { Theme.Error(this, I18n.T("邮箱地址格式不正确。")); return; }
                if (!String.IsNullOrEmpty(emailPass.Text) && String.IsNullOrWhiteSpace(email.Text)) { Theme.Error(this, I18n.T("请先填写关联邮箱地址。")); return; }
                if (String.IsNullOrWhiteSpace(url.Text) && !String.IsNullOrWhiteSpace(email.Text)) url.Text = MailLinks.Suggest(email.Text);
                if (!String.IsNullOrWhiteSpace(url.Text) && !MailLinks.Valid(url.Text)) { Theme.Error(this, I18n.T("邮箱登录网址可以留空；若填写，请使用有效域名或 HTTPS 网址，例如 mail.zsthost.com。")); return; }
                Result = new Account { Id = account == null ? Guid.NewGuid().ToString("N") : account.Id, Label = label.Text.Trim(), Username = user.Text.Trim(), Password = pass.Text, Email = email.Text.Trim(), EmailPassword = emailPass.Text, EmailUrl = MailLinks.Normalize(url.Text) };
                DialogResult = DialogResult.OK; Close();
            });
            AcceptButton = save; CancelButton = cancel;
            if (account != null) { label.Text = account.Label; user.Text = account.Username; pass.Text = account.Password; email.Text = account.Email; emailPass.Text = account.EmailPassword; url.Text = account.EmailUrl; }
            ActiveControl = account == null ? label : user;
            Shown += delegate { var focused = ActiveControl as TextBox; if (focused != null) focused.Select(focused.TextLength, 0); };
        }
    }
    public static class RiotFill {
        static void Diagnostic(string message) {
            try {
                string dir = Path.Combine(Vault.UserDirectory, "diagnostics");
                Directory.CreateDirectory(dir);
                File.AppendAllText(Path.Combine(dir, "fill-status.log"), DateTime.Now.ToString("s") + " " + message + Environment.NewLine);
            } catch { }
        }
        [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr hwnd);
        [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
        [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr hwnd, int cmd);
        [DllImport("user32.dll")] static extern uint SendInput(uint n, INPUT[] input, int size);
        [StructLayout(LayoutKind.Sequential)] struct INPUT { public uint type; public UNION u; }
        [StructLayout(LayoutKind.Explicit)] struct UNION { [FieldOffset(0)] public KEYBDINPUT ki; [FieldOffset(0)] public MOUSEINPUT mi; }
        [StructLayout(LayoutKind.Sequential)] struct KEYBDINPUT { public ushort vk, scan; public uint flags, time; public UIntPtr extra; }
        [StructLayout(LayoutKind.Sequential)] struct MOUSEINPUT { public int dx, dy; public uint data, flags, time; public UIntPtr extra; }
        static INPUT Key(ushort key, bool up, bool unicode) { return new INPUT { type = 1, u = new UNION { ki = new KEYBDINPUT { vk = unicode ? (ushort)0 : key, scan = unicode ? key : (ushort)0, flags = (unicode ? 4u : 0u) | (up ? 2u : 0u) } } }; }
        static void Send(INPUT[] input) { if (SendInput((uint)input.Length, input, Marshal.SizeOf(typeof(INPUT))) != input.Length) throw new InvalidOperationException(I18n.T("Windows 阻止了输入。请让两个程序以相同的普通用户权限运行。")); }
        static void Check(AutomationElement field, int pid, CancellationToken cancel) {
            cancel.ThrowIfCancellationRequested(); uint foreground; GetWindowThreadProcessId(GetForegroundWindow(), out foreground);
            if (foreground != pid || !AutomationElement.FocusedElement.Equals(field) || !field.Current.IsEnabled || field.Current.IsOffscreen)
                throw new InvalidOperationException(I18n.T("窗口或输入焦点发生变化，已停止填入。请检查 Riot 登录框后再试。"));
        }
        public static bool TestInputGuards() {
            bool wrongWindow = false, cancelled = false;
            try { Check(null, -1, CancellationToken.None); } catch (InvalidOperationException) { wrongWindow = true; }
            using (var c = new CancellationTokenSource()) {
                c.Cancel(); try { Check(null, -1, c.Token); } catch (OperationCanceledException) { cancelled = true; }
            }
            return wrongWindow && cancelled;
        }
        static void Type(AutomationElement field, string value, int pid, CancellationToken cancel) {
            field.SetFocus(); Thread.Sleep(150); Check(field, pid, cancel);
            Send(new[] { Key(0x11, false, false), Key(0x41, false, false), Key(0x41, true, false), Key(0x11, true, false) });
            foreach (char c in value) { Check(field, pid, cancel); Send(new[] { Key(c, false, true), Key(c, true, true) }); }
            Check(field, pid, cancel);
        }
        public static string DiscoverPath() {
            try {
                string file = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Riot Games", "RiotClientInstalls.json");
                if (File.Exists(file)) {
                    var dict = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(File.ReadAllText(file));
                    foreach (string key in new[] { "rc_live", "rc_default" }) if (dict.ContainsKey(key) && ValidPath(Convert.ToString(dict[key]))) return Convert.ToString(dict[key]);
                }
            } catch { }
            return "";
        }
        public static bool ValidPath(string path) { return !String.IsNullOrEmpty(path) && File.Exists(path) && String.Equals(Path.GetFileName(path), "RiotClientServices.exe", StringComparison.OrdinalIgnoreCase); }
        static IEnumerable<Process> ClientProcesses() {
            return Process.GetProcessesByName("Riot Client").Concat(Process.GetProcessesByName("RiotClientUx")).Concat(Process.GetProcessesByName("RiotClientServices"));
        }
        static bool TrustedProcess(Process process, string launcher) {
            try {
                string actual = Path.GetFullPath(process.MainModule.FileName);
                string root = Path.GetFullPath(Path.GetDirectoryName(launcher)).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                if (process.ProcessName.Equals("RiotClientServices", StringComparison.OrdinalIgnoreCase))
                    return actual.Equals(Path.GetFullPath(launcher), StringComparison.OrdinalIgnoreCase);
                if (process.ProcessName.Equals("Riot Client", StringComparison.OrdinalIgnoreCase))
                    return actual.Equals(Path.GetFullPath(Path.Combine(root, "RiotClientElectron", "Riot Client.exe")), StringComparison.OrdinalIgnoreCase);
                return process.ProcessName.Equals("RiotClientUx", StringComparison.OrdinalIgnoreCase) && actual.StartsWith(root, StringComparison.OrdinalIgnoreCase);
            } catch { return false; }
        }
        public static void Fill(Account account, string launcher, CancellationToken cancel) {
            if (!ValidPath(launcher)) throw new InvalidOperationException(I18n.T("请先选择正确的 RiotClientServices.exe。"));
            Diagnostic("Attempt started (no credentials logged).");
            bool existingWindow = false;
            foreach (var p in ClientProcesses()) using (p) {
                if (TrustedProcess(p, launcher) && p.MainWindowHandle != IntPtr.Zero) { existingWindow = true; break; }
            }
            if (!existingWindow) {
                var start = new ProcessStartInfo(launcher, "--launch-product=valorant --launch-patchline=live") { UseShellExecute = false, WorkingDirectory = Path.GetDirectoryName(launcher) };
                using (var launched = Process.Start(start)) { }
            }
            Diagnostic(existingWindow ? "Using existing client window." : "Client launch requested.");
            var until = DateTime.UtcNow.AddSeconds(12);
            var observed = new HashSet<string>();
            while (DateTime.UtcNow < until) {
                cancel.ThrowIfCancellationRequested();
                foreach (var p in ClientProcesses()) using (p) {
                    if (!TrustedProcess(p, launcher)) continue;
                    if (observed.Add("process:" + p.ProcessName)) Diagnostic("Verified process: " + p.ProcessName);
                    var windows = AutomationElement.RootElement.FindAll(TreeScope.Children, new PropertyCondition(AutomationElement.ProcessIdProperty, p.Id));
                    foreach (AutomationElement window in windows) {
                        cancel.ThrowIfCancellationRequested();
                        AutomationElement username = null, password = null;
                        var edits = window.FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Edit));
                        var visible = edits.Cast<AutomationElement>().Where(e => e.Current.IsEnabled && !e.Current.IsOffscreen && e.Current.IsKeyboardFocusable).ToList();
                        var secrets = visible.Where(e => e.Current.IsPassword).ToList();
                        var normal = visible.Where(e => !e.Current.IsPassword).ToList();
                        string state = p.ProcessName + ": edit=" + visible.Count + ", password=" + secrets.Count + ", other=" + normal.Count;
                        if (observed.Add(state)) Diagnostic(state);
                        if (secrets.Count != 1 || normal.Count != 1 || visible.Count != 2) continue;
                        password = secrets[0]; username = normal[0];
                        string identity = ((username.Current.Name ?? "") + " " + (username.Current.AutomationId ?? "")).ToLowerInvariant();
                        bool knownLabel = identity.Contains("username") || identity.Contains("user name") || identity.Contains("用户名") || identity.Contains("使用者名稱") || identity.Contains("帳號") || identity.Contains(I18n.T("账号")) || identity.Contains("riot");
                        var userBounds = username.Current.BoundingRectangle;
                        var passBounds = password.Current.BoundingRectangle;
                        // With exactly two visible edit controls, accept an unlabeled username
                        // only when it lies above and horizontally aligns with the password field.
                        bool alignedPair = !userBounds.IsEmpty && !passBounds.IsEmpty && userBounds.Bottom <= passBounds.Top && Math.Abs(userBounds.Left - passBounds.Left) < 24;
                        if (!knownLabel && !alignedPair) { if (observed.Add("ambiguous")) Diagnostic("Input pair ambiguous; no input sent."); continue; }
                        var hwnd = new IntPtr(window.Current.NativeWindowHandle);
                        ShowWindow(hwnd, 9); SetForegroundWindow(hwnd); Thread.Sleep(200);
                        try {
                            Diagnostic("Login fields identified; attempting username input.");
                            Type(username, account.Username, p.Id, cancel);
                            Diagnostic("Username input sent; attempting password input.");
                            Type(password, account.Password, p.Id, cancel);
                            Diagnostic("Both inputs sent; no login submitted.");
                        } catch (Exception ex) { Diagnostic("Input stopped: " + ex.GetType().Name); throw; }
                        // Deliberately no Enter, click, submit, captcha, token, or game process access.
                        return;
                    }
                }
                Thread.Sleep(100);
            }
            Diagnostic("Timed out: no confirmed login fields.");
            throw new InvalidOperationException(I18n.T("未能确认 Riot 的账号和密码输入框。可能已登录、客户端尚未加载，或当前版本未向 Windows 提供输入框信息。\n\n诊断记录已保存到 EXE 同目录 data/diagnostics/fill-status.log（不含账密）。可通过“账号资料”手动复制。"));
        }
    }
    public class MainForm : Form {
        public bool LanguageChanged { get; private set; }
        readonly string vaultPath;
        VaultData data;
        TextBox search;
        ListView list;
        Label status, summary, emptyHint;
        Button launch;
        CancellationTokenSource cancellation;
        bool busy;
        bool preview;
        int hoverIndex = -1;
        string lastSelectedId;
        const int RowHeight = 52;
        static readonly Color[] AvatarColors = {
            Color.FromArgb(99, 102, 241), Color.FromArgb(14, 165, 233), Color.FromArgb(16, 185, 129), Color.FromArgb(245, 158, 11),
            Color.FromArgb(236, 72, 153), Color.FromArgb(139, 92, 246), Color.FromArgb(20, 184, 166), Color.FromArgb(234, 88, 12)
        };
        public MainForm(string path, VaultData initial, bool isPreview) {
            vaultPath = path; data = initial; preview = isPreview;
            Theme.Form(this, "ValAccount By Noiric", 960, 568);
            KeyPreview = true;

            // Header: title, account count, search and add.
            Theme.Label(this, "ValAccount", 32, 20, 420, 34, 16, false, true);
            summary = Theme.Label(this, "", 32, 56, 440, 22, 9.5f, true);
            search = Theme.Input(this, 500, 35, 270, false); search.TextChanged += delegate { RefreshList(null); };
            Theme.Placeholder(search, I18n.T("搜索账号、登录名或邮箱"));
            Theme.Button(this, I18n.T("+ 添加账号"), 788, 28, 140, 40, true, delegate { Edit(null); });

            // Account list inside a rounded card.
            Theme.Surface(this, new Rectangle(32, 88, 896, 368));
            list = new ListView { Location = new Point(36, 94), Size = new Size(888, 356), View = View.Details, FullRowSelect = true, HideSelection = false, MultiSelect = false, BackColor = Theme.Card, ForeColor = Theme.Text, BorderStyle = BorderStyle.None, HeaderStyle = ColumnHeaderStyle.Nonclickable, Font = Theme.Font(10, false) };
            list.Columns.Add(I18n.T("账号"), 300); list.Columns.Add(I18n.T("Riot 登录名"), 260); list.Columns.Add(I18n.T("邮箱"), 320);
            var rowSize = new ImageList { ImageSize = new Size(1, RowHeight) };
            list.SmallImageList = rowSize;
            Disposed += delegate { rowSize.Dispose(); };
            list.OwnerDraw = true;
            list.DrawColumnHeader += delegate(object sender, DrawListViewColumnHeaderEventArgs e) {
                using (var b = new SolidBrush(Theme.Card)) e.Graphics.FillRectangle(b, e.Bounds);
                using (var pen = new Pen(Theme.Border)) e.Graphics.DrawLine(pen, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
                var r = e.Bounds; r.X += e.ColumnIndex == 0 ? 16 : 12; r.Width -= e.ColumnIndex == 0 ? 16 : 12;
                TextRenderer.DrawText(e.Graphics, e.Header.Text, Theme.Font(9, false), r, Theme.Muted, TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);
            };
            list.DrawSubItem += delegate(object sender, DrawListViewSubItemEventArgs e) {
                var g = e.Graphics;
                var rowAccount = data.Accounts.Find(a => a.Id == Convert.ToString(e.Item.Tag));
                bool selected = e.Item.Selected, hovered = e.ItemIndex == hoverIndex;
                bool emailLink = e.ColumnIndex == 2 && rowAccount != null && HasMailLink(rowAccount);
                using (var brush = new SolidBrush(selected ? Theme.AccentSoft : hovered ? Theme.Hover : Theme.Card)) g.FillRectangle(brush, e.Bounds);
                using (var pen = new Pen(Theme.Divider)) g.DrawLine(pen, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
                const TextFormatFlags flags = TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine;
                var bounds = e.Bounds;
                if (e.ColumnIndex == 0) {
                    g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                    if (selected) using (var bar = Theme.Round(new RectangleF(bounds.Left, bounds.Top + 12, 4, bounds.Height - 24), 2)) using (var b = new SolidBrush(Theme.Accent)) g.FillPath(b, bar);
                    string name = e.SubItem.Text ?? "";
                    var circle = new Rectangle(bounds.Left + 16, bounds.Top + (bounds.Height - 32) / 2, 32, 32);
                    using (var b = new SolidBrush(AvatarColor(Convert.ToString(e.Item.Tag)))) g.FillEllipse(b, circle);
                    string letter = name.Length == 0 ? "?" : Char.IsSurrogate(name, 0) && name.Length > 1 ? name.Substring(0, 2) : name.Substring(0, 1).ToUpperInvariant();
                    TextRenderer.DrawText(g, letter, Theme.Font(10, true), circle, Color.White, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
                    var text = new Rectangle(bounds.Left + 60, bounds.Top, bounds.Width - 68, bounds.Height);
                    TextRenderer.DrawText(g, name, Theme.Font(10, true), text, Theme.Text, flags);
                } else if (e.ColumnIndex == 2 && String.IsNullOrEmpty(e.SubItem.Text)) {
                    bounds.X += 12; bounds.Width -= 20;
                    TextRenderer.DrawText(g, "—", list.Font, bounds, Color.FromArgb(190, 190, 198), flags);
                } else {
                    bounds.X += 12; bounds.Width -= 20;
                    var font = emailLink && hovered ? new Font(list.Font, FontStyle.Underline) : list.Font;
                    try { TextRenderer.DrawText(g, e.SubItem.Text, font, bounds, emailLink ? Theme.Accent : e.ColumnIndex == 2 ? Theme.Muted : Theme.Text, flags); }
                    finally { if (font != list.Font) font.Dispose(); }
                }
            };
            list.MouseMove += delegate(object sender, MouseEventArgs e) {
                var item = list.GetItemAt(e.X, e.Y); SetHover(item == null ? -1 : item.Index);
                list.Cursor = EmailAt(e.Location) == null ? Cursors.Default : Cursors.Hand;
            };
            list.MouseLeave += delegate { SetHover(-1); list.Cursor = Cursors.Default; };
            list.MouseClick += delegate(object sender, MouseEventArgs e) {
                if (e.Button != MouseButtons.Left || busy) return;
                var a = EmailAt(e.Location); if (a == null) return;
                string url = MailLinks.Normalize(String.IsNullOrWhiteSpace(a.EmailUrl) ? MailLinks.Suggest(a.Email) : a.EmailUrl);
                if (!MailLinks.Valid(url)) { Theme.Error(this, I18n.T("请在编辑账号中填写有效的邮箱登录网址。")); return; }
                try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
                catch { Theme.Error(this, I18n.T("无法打开默认浏览器，请检查 Windows 默认浏览器设置。")); }
            };
            // Clicking empty space would otherwise clear the selection; keep the last chosen account selected.
            list.MouseUp += delegate {
                if (list.SelectedItems.Count > 0 || lastSelectedId == null) return;
                foreach (ListViewItem item in list.Items) if (Convert.ToString(item.Tag) == lastSelectedId) { item.Selected = true; item.Focused = true; break; }
            };
            list.MouseDoubleClick += async delegate(object sender, MouseEventArgs e) {
                var hit = list.HitTest(e.Location);
                if (e.Button == MouseButtons.Left && hit.Item != null && hit.SubItem != hit.Item.SubItems[2]) await Launch();
            };
            list.KeyDown += async delegate(object sender, KeyEventArgs e) {
                if (e.KeyCode == Keys.Enter) { e.Handled = e.SuppressKeyPress = true; await Launch(); }
                else if (e.KeyCode == Keys.Delete) { e.Handled = true; Delete(); }
            };
            list.ClientSizeChanged += delegate { FitColumns(); };
            Controls.Add(list);
            list.SelectedIndexChanged += delegate { if (list.SelectedItems.Count > 0) lastSelectedId = SelectedId(); list.Invalidate(); UpdateStatus(); };
            emptyHint = Theme.Label(list, "", 0, 110, list.Width, 64, 10, true);
            emptyHint.TextAlign = ContentAlignment.MiddleCenter; emptyHint.BackColor = Theme.Card; emptyHint.Visible = false;

            // Footer actions.
            Theme.Button(this, I18n.T("编辑"), 32, 476, 88, 40, false, delegate { var a = Selected(); if (a != null) Edit(a); });
            Theme.Button(this, I18n.T("删除"), 130, 476, 88, 40, false, delegate { Delete(); }).Danger = true;
            var moreMenu = new ContextMenuStrip { ShowImageMargin = false, Renderer = new MenuRenderer(), Font = Theme.Font(10, false), Padding = new Padding(0, 4, 0, 4) };
            moreMenu.Items.Add(I18n.T("账号资料"), null, delegate { Details(); });
            moreMenu.Items.Add(I18n.T("客户端位置"), null, delegate { ChooseLauncher(); });
            foreach (ToolStripItem item in moreMenu.Items) { item.Padding = new Padding(8, 6, 24, 6); }
            Theme.Button(this, I18n.English ? "语言" : "Language", 228, 476, 104, 40, false, delegate {
                using (var language = new LanguageForm()) if (language.ShowDialog(this) == DialogResult.OK) { LanguageChanged = true; Close(); }
            });
            Disposed += delegate { moreMenu.Dispose(); };
            Theme.Button(this, I18n.T("更多 ···"), 342, 476, 104, 40, false, delegate(object sender, EventArgs e) { var button = (Button)sender; moreMenu.Show(button, new Point(0, button.Height + 4)); });
            launch = Theme.Button(this, I18n.T("启动并填入 →"), 728, 472, 200, 48, true, async delegate { await Launch(); });
            launch.Font = Theme.Font(10.5f, true);
            status = Theme.Label(this, "", 32, 532, 896, 24, 9, true);
            RefreshList(null);
            KeyDown += delegate(object sender, KeyEventArgs e) {
                if (e.Control && e.KeyCode == Keys.F) { search.Focus(); search.SelectAll(); e.Handled = e.SuppressKeyPress = true; }
                else if (e.Control && e.KeyCode == Keys.N && !busy) { e.Handled = e.SuppressKeyPress = true; Edit(null); }
            };
            Shown += delegate { list.Focus(); };
            FormClosing += delegate(object sender, FormClosingEventArgs e) { if (busy) { cancellation.Cancel(); e.Cancel = true; status.Text = I18n.T("正在停止填入，请稍候…"); } else SafeClipboard.Clear(); };
        }
        static Color AvatarColor(string id) {
            int sum = 0; foreach (char c in id ?? "") sum += c;
            return AvatarColors[sum % AvatarColors.Length];
        }
        void SetHover(int index) {
            if (index == hoverIndex) return;
            int old = hoverIndex; hoverIndex = index;
            if (old >= 0 && old < list.Items.Count) list.Invalidate(list.Items[old].Bounds);
            if (index >= 0 && index < list.Items.Count) list.Invalidate(list.Items[index].Bounds);
        }
        void FitColumns() {
            int width = list.ClientSize.Width;
            if (!list.IsHandleCreated) {
                // Before the handle exists, estimate whether a vertical scrollbar will be needed.
                bool scroll = list.Items.Count * RowHeight + 32 > list.Height;
                width = list.Width - (scroll ? SystemInformation.VerticalScrollBarWidth : 0);
            }
            int rest = width - list.Columns[0].Width - list.Columns[1].Width;
            if (rest > 80 && list.Columns[2].Width != rest) list.Columns[2].Width = rest;
        }
        string SelectedId() { return list.SelectedItems.Count == 0 ? null : Convert.ToString(list.SelectedItems[0].Tag); }
        static bool HasMailLink(Account a) {
            return !String.IsNullOrWhiteSpace(a.Email) && MailLinks.Valid(String.IsNullOrWhiteSpace(a.EmailUrl) ? MailLinks.Suggest(a.Email) : a.EmailUrl);
        }
        Account EmailAt(Point point) {
            var hit = list.HitTest(point);
            if (hit.Item == null || hit.SubItem != hit.Item.SubItems[2]) return null;
            var a = data.Accounts.Find(x => x.Id == Convert.ToString(hit.Item.Tag));
            return a == null || !HasMailLink(a) ? null : a;
        }
        Account Selected() { string id = SelectedId(); return data.Accounts.Find(a => a.Id == id); }
        void RefreshList(string wanted) {
            string keep = wanted ?? SelectedId() ?? lastSelectedId; list.BeginUpdate(); list.Items.Clear(); hoverIndex = -1;
            string q = search.Text.Trim();
            foreach (var a in data.Accounts.Where(a => (a.Label + " " + a.Username + " " + a.Email).IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0)) {
                var item = new ListViewItem(new[] { a.ToString(), a.Username, a.Email ?? "" }) { Tag = a.Id };
                list.Items.Add(item); if (a.Id == keep) { item.Selected = true; item.Focused = true; }
            }
            if (list.SelectedItems.Count == 0 && list.Items.Count > 0) { list.Items[0].Selected = true; list.Items[0].Focused = true; }
            list.EndUpdate(); FitColumns();
            if (list.SelectedItems.Count > 0) list.SelectedItems[0].EnsureVisible();
            emptyHint.Visible = list.Items.Count == 0;
            emptyHint.Text = data.Accounts.Count == 0 ? I18n.T("还没有账号。点击右上角“+ 添加账号”开始。") : I18n.T("没有匹配的账号，换个关键词试试。");
            int count = data.Accounts.Count;
            summary.Text = count == 0 ? I18n.T("添加账号后，双击即可启动并填入。") : count + I18n.T(" 个账号 · 双击账号即可启动并填入");
            UpdateStatus();
        }
        void UpdateStatus() {
            if (status == null || busy) return;
            var a = Selected(); launch.Enabled = a != null;
            status.Text = data.Accounts.Count == 0 ? I18n.T("暂无账号") : a == null ? I18n.T("无匹配账号") : I18n.T("已选中：") + a.ToString();
        }
        bool Commit(VaultData next) {
            if (preview) { data = next; return true; }
            try { Vault.Save(vaultPath, next); data = next; return true; }
            catch { Theme.Error(this, I18n.T("无法保存加密账号库。请检查文件夹是否可写、磁盘空间是否充足。原有账号未被替换。")); return false; }
        }
        void Edit(Account a) {
            using (var edit = new EditForm(a)) if (edit.ShowDialog(this) == DialogResult.OK) {
                var next = Vault.Clone(data); int index = next.Accounts.FindIndex(x => x.Id == edit.Result.Id);
                if (index < 0) next.Accounts.Add(edit.Result); else next.Accounts[index] = edit.Result;
                if (Commit(next)) { search.Text = ""; RefreshList(edit.Result.Id); }
            }
        }
        void Delete() {
            var a = Selected(); if (a == null) return;
            if (MessageBox.Show(this, I18n.T("删除“") + a.ToString() + I18n.T("”及其保存的游戏、邮箱资料？"), I18n.T("删除账号"), MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            var next = Vault.Clone(data); next.Accounts.RemoveAll(x => x.Id == a.Id); if (Commit(next)) RefreshList(null);
        }
        void Details() {
            var a = Selected(); if (a == null) return;
            using (var f = AccountDetails(a)) f.ShowDialog(this);
        }
        public static Form AccountDetails(Account a) {
            var f = new Form();
            Theme.Form(f, I18n.T("账号资料 · ") + a.ToString(), 600, 500); f.MinimizeBox = false; f.ShowInTaskbar = false;
            Theme.Label(f, I18n.T("账号资料"), 32, 22, 536, 34, 16, false, true);
            Theme.Label(f, a.ToString(), 32, 58, 536, 22, 9.5f, true);
            Theme.Surface(f, new Rectangle(32, 96, 536, 320));
            string[] labels = { "Riot 登录名", "Riot 密码", "邮箱地址", "邮箱密码" };
            string[] values = { a.Username, a.Password, a.Email, a.EmailPassword };
            string[] buttons = { "复制登录名", "复制密码", "复制邮箱", "复制邮箱密码" };
            var secrets = new List<TextBox>();
            Button first = null;
            for (int i = 0; i < labels.Length; i++) {
                int y = 112 + i * 74;
                bool secret = i == 1 || i == 3;
                string value = values[i] ?? "";
                Theme.Label(f, I18n.T(labels[i]), 52, y, 330, 22, 9.5f, true);
                var input = Theme.Input(f, 52, y + 31, 330, secret && value.Length > 0);
                input.Text = value.Length == 0 ? I18n.T("未填写") : value;
                input.ReadOnly = true; input.BackColor = Theme.Field; input.TabStop = false;
                if (secret && value.Length > 0) secrets.Add(input);
                if (value.Length == 0) input.ForeColor = Theme.Muted;
                string caption = I18n.T(buttons[i]);
                RoundedButton copy = null;
                var revert = new System.Windows.Forms.Timer { Interval = 1600 };
                revert.Tick += delegate { revert.Stop(); copy.Text = caption; };
                f.Disposed += delegate { revert.Dispose(); };
                copy = Theme.Button(f, caption, 396, y + 24, 152, 40, false, delegate {
                    try { SafeClipboard.Copy(value); copy.Text = "✓ " + I18n.T("已复制"); revert.Stop(); revert.Start(); }
                    catch { Theme.Error(f, I18n.T("剪贴板暂时不可用。")); }
                });
                copy.Surface = Theme.Card;
                copy.Enabled = value.Length > 0;
                if (first == null && copy.Enabled) first = copy;
            }
            var reveal = Theme.Check(f, I18n.T("显示密码"), 32, 430, 260);
            reveal.CheckedChanged += delegate { foreach (var input in secrets) input.UseSystemPasswordChar = !reveal.Checked; };
            Theme.Label(f, I18n.T("复制后 30 秒或关闭时清除，并请求 Windows 不保留历史。"), 32, 462, 536, 22, 9, true);
            if (first != null) f.ActiveControl = first;
            f.KeyPreview = true; f.KeyDown += delegate(object sender, KeyEventArgs e) { if (e.KeyCode == Keys.Escape) f.Close(); };
            f.FormClosed += delegate { SafeClipboard.Clear(); };
            return f;
        }
        bool ChooseLauncher() {
            using (var d = new OpenFileDialog { Title = I18n.T("选择 RiotClientServices.exe"), Filter = I18n.T("Riot 客户端|RiotClientServices.exe"), CheckFileExists = true }) {
                if (d.ShowDialog(this) != DialogResult.OK) return false;
                if (!RiotFill.ValidPath(d.FileName)) return false;
                var next = Vault.Clone(data); next.RiotPath = d.FileName; return Commit(next);
            }
        }
        async Task Launch() {
            if (busy || preview) return;
            var a = Selected(); if (a == null) return;
            string launcher = data.RiotPath;
            if (!RiotFill.ValidPath(launcher)) launcher = RiotFill.DiscoverPath();
            if (!RiotFill.ValidPath(launcher)) { if (!ChooseLauncher()) return; launcher = data.RiotPath; }
            busy = true; cancellation = new CancellationTokenSource();
            foreach (Control c in Controls) c.Enabled = false;
            status.Enabled = true; status.Text = I18n.T("正在检测 Riot 登录框，出现后立即尝试填入（超时 12 秒）… 请暂时不要切换窗口。");
            bool success = false;
            try { await Task.Run(() => RiotFill.Fill(a, launcher, cancellation.Token)); success = true; }
            catch (OperationCanceledException) { status.Text = I18n.T("已取消填入。"); }
            catch (InvalidOperationException ex) { Theme.Error(this, ex.Message); }
            catch { Theme.Error(this, I18n.T("未能完成填入。请检查 Riot 登录窗口，或使用“账号资料”手动复制。没有提交登录。")); }
            finally { busy = false; cancellation.Dispose(); foreach (Control c in Controls) c.Enabled = true; UpdateStatus(); }
            if (success) {
                SafeClipboard.Clear(); Hide();
                Close();
            }
        }
    }
    static class Program {
        [STAThread] static int Main(string[] args) {
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            if (args.Length == 2 && (args[0] == "--self-test" || args[0] == "--self-test-en")) { I18n.English = args[0] == "--self-test-en"; return SelfTest(args[1]); }
            if (args.Length == 2 && (args[0] == "--render-preview" || args[0] == "--render-preview-en")) { I18n.English = args[0] == "--render-preview-en"; Render(args[1]); return 0; }
            bool created;
            using (var mutex = new Mutex(true, "Local\\ValoAccountManager.LocalVault.v1", out created)) {
                if (!created) { MessageBox.Show(I18n.T("账号管理器已经打开，请切换到现有窗口。"), I18n.T("VALO 账号启动器")); return 0; }
                I18n.LoadPreference();
                string path = Path.Combine(Vault.UserDirectory, "accounts.vault");
                VaultData data;
                try {
                    string root = AppDomain.CurrentDomain.BaseDirectory;
                    data = Vault.LoadOrMigrate(path, new[] {
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ValoAccountManager", "accounts.vault"),
                        Path.Combine(root, "ValoAccountManager", "data", "accounts.vault")
                    });
                }
                catch { MessageBox.Show(I18n.T("无法读取、迁移或解密账号库。请确认使用原来的 Windows 用户、EXE 所在文件夹可写，且文件未损坏。\n\n程序不会覆盖原文件；data 中的 .bak 是上一版加密备份。"), I18n.T("账号库未打开"), MessageBoxButtons.OK, MessageBoxIcon.Error); return 1; }
                bool changeLanguage;
                do {
                    using (var main = new MainForm(path, data, false)) {
                        Application.Run(main); changeLanguage = main.LanguageChanged;
                    }
                    if (changeLanguage) data = Vault.Load(path);
                } while (changeLanguage);
                SafeClipboard.Clear(); mutex.ReleaseMutex();
            }
            return 0;
        }
        static VaultData Demo() {
            var d = new VaultData();
            d.Accounts.Add(new Account { Label = "主账号 · 亚服", Username = "demo_primary", Password = "Demo-Only-123", Email = "example@gmail.com", EmailUrl = "https://mail.google.com/", Mfa = true });
            d.Accounts.Add(new Account { Label = "", Username = "demo_practice", Password = "Demo-Only-456" });
            d.Accounts.Add(new Account { Label = "周末组队", Username = "demo_weekend", Password = "Demo-Only-789", Email = "example@outlook.com", EmailPassword = "Demo-Mail-Only", EmailUrl = "https://outlook.live.com/mail/", Mfa = true });
            return d;
        }
        static void Render(string directory) {
            Directory.CreateDirectory(directory); var d = Demo();
            using (var language = new LanguageForm()) RenderForm(language, Path.Combine(directory, "00-language.png"));
            using (var main = new MainForm("", d, true)) RenderForm(main, Path.Combine(directory, "01-launcher.png"));
            using (var edit = new EditForm(d.Accounts[0])) RenderForm(edit, Path.Combine(directory, "02-account.png"));
            using (var details = MainForm.AccountDetails(d.Accounts[2])) RenderForm(details, Path.Combine(directory, "03-details.png"));
        }
        static void RenderForm(Form f, string path) {
            f.StartPosition = FormStartPosition.Manual; f.Location = new Point(-20000, -20000); f.Show(); Application.DoEvents();
            using (var b = new Bitmap(f.Width, f.Height)) { f.DrawToBitmap(b, new Rectangle(0, 0, b.Width, b.Height)); b.Save(path, System.Drawing.Imaging.ImageFormat.Png); }
            f.Close();
        }
        static int SelfTest(string directory) {
            Directory.CreateDirectory(directory); var lines = new List<string>();
            try {
                string path = Path.Combine(directory, "test-accounts.vault"); var data = Demo();
                Vault.Save(path, data); var read = Vault.Load(path);
                Assert(read.Accounts.Count == 3 && read.Accounts[2].EmailPassword == "Demo-Mail-Only" && read.Accounts[1].Label == "" && read.Accounts[1].ToString() == "demo_practice", "DPAPI round trip including optional email password and blank label", lines);
                Assert(!Encoding.UTF8.GetString(File.ReadAllBytes(path)).Contains("Demo-Mail-Only"), "No plaintext password in vault", lines);
                var next = Vault.Clone(read); next.Accounts[0].Label = "Edited"; next.Accounts.RemoveAt(1); Vault.Save(path, next);
                Assert(Vault.Load(path).Accounts.Count == 2 && Vault.Load(path).Accounts[0].Label == "Edited", "Atomic update and delete", lines);
                Assert(Vault.Load(path + ".bak").Accounts.Count == 3, "Encrypted previous-version backup", lines);
                string migratedPath = Path.Combine(directory, "migration-" + Guid.NewGuid().ToString("N"), "accounts.vault");
                var migrated = Vault.LoadOrMigrate(migratedPath, new[] { path });
                Assert(migrated.Accounts.Count == 2 && Vault.Load(path).Accounts.Count == 2, "Legacy migration preserves source vault", lines);
                Assert(Vault.LoadOrMigrate(migratedPath, new[] { path + ".bak" }).Accounts.Count == 2, "Existing portable vault takes precedence", lines);
                byte[] broken = File.ReadAllBytes(path); broken[broken.Length / 2] ^= 1; bool failed = false;
                try { Vault.Decode(broken); } catch { failed = true; }
                Assert(failed, "Tampered vault rejected", lines);
                Assert(MailLinks.Valid("https://mail.google.com/") && !MailLinks.Valid("file:///C:/Windows") && !MailLinks.Valid("javascript:alert(1)") && !MailLinks.Valid("https://user:pass@example.com/") && !MailLinks.Valid("http://mail.qq.com/"), "Email link scheme and embedded credential checks", lines);
                Assert(MailLinks.Suggest("a@gmail.com") == "https://mail.google.com/" && MailLinks.Suggest("a@custom.example") == "" && MailLinks.Valid("MAIL.ZSTHOST.COM") && MailLinks.Normalize(" MAIL.ZSTHOST.COM ") == "https://mail.zsthost.com/", "Provider mapping and bare uppercase email domain normalization", lines);
                Assert(MailLinks.ValidEmail("example@outlook.com") && !MailLinks.ValidEmail("invalid"), "Email validation", lines);
                Assert(!RiotFill.ValidPath("C:\\Windows\\System32\\notepad.exe"), "Non-Riot launcher rejected", lines);
                Assert(RiotFill.TestInputGuards(), "Wrong foreground and cancellation reject input before keystrokes", lines);
                using (var editor = new EditForm(null)) {
                    editor.StartPosition = FormStartPosition.Manual; editor.Location = new Point(-20000, -20000); editor.Show(); Application.DoEvents();
                    var inputs = TextInputs(editor).ToArray();
                    inputs[0].Text = "   "; inputs[1].Text = "test_login"; inputs[2].Text = "TestPassword!";
                    inputs[3].Text = "test@zsthost.com"; inputs[4].Text = "OptionalMailPassword"; inputs[5].Text = "MAIL.ZSTHOST.COM";
                    editor.Controls.OfType<Button>().First(b => b.Text == I18n.T("保存账号")).PerformClick();
                    Assert(editor.Result != null && editor.Result.Label == "" && editor.Result.ToString() == "test_login" && editor.Result.EmailPassword == "OptionalMailPassword" && editor.Result.EmailUrl == "https://mail.zsthost.com/", "Add-account UI accepts blank label and normalizes bare email domain", lines);
                }
                using (var main = new MainForm(path, data, true)) {
                    main.StartPosition = FormStartPosition.Manual; main.Location = new Point(-20000, -20000); main.Show(); Application.DoEvents();
                    TextInputs(main).Single().Text = "demo_weekend";
                    Assert(main.Controls.OfType<ListView>().Single().Items.Count == 1, "Account search filters list", lines);
                    TextInputs(main).Single().Text = "does-not-exist";
                    Assert(main.Controls.OfType<ListView>().Single().Items.Count == 0 && !main.Controls.OfType<Button>().First(b => b.Text == I18n.T("启动并填入 →")).Enabled, "No-match search disables launch", lines);
                    main.Close();
                }
                using (var editor = new EditForm(null)) {
                    editor.StartPosition = FormStartPosition.Manual; editor.Location = new Point(-20000, -20000); editor.Show(); Application.DoEvents();
                    var inputs = TextInputs(editor).ToArray();
                    inputs[1].Text = "optional_url_test"; inputs[2].Text = "TestOnly!"; inputs[3].Text = "user@custom.example";
                    editor.Controls.OfType<Button>().First(b => b.Text == I18n.T("保存账号")).PerformClick();
                    Assert(editor.Result != null && editor.Result.Email == "user@custom.example" && editor.Result.EmailUrl == "", "Custom-domain email saves without login URL", lines);
                }
                using (var details = MainForm.AccountDetails(data.Accounts[2])) {
                    var fields = TextInputs(details).ToArray();
                    Assert(fields.Length == 4 && fields[2].Text == "example@outlook.com" && fields[3].Text == "Demo-Mail-Only" && fields[3].UseSystemPasswordChar, "Details shows email credentials with password masked", lines);
                    details.Controls.OfType<CheckBox>().Single().Checked = true;
                    Assert(!fields[1].UseSystemPasswordChar && !fields[3].UseSystemPasswordChar, "Details reveal toggle updates both passwords", lines);
                }
                using (var details = MainForm.AccountDetails(new Account { Username = "test", Password = "test-only" })) {
                    var fields = TextInputs(details).ToArray();
                    Assert(fields[2].Text == I18n.T("未填写") && fields[3].Text == I18n.T("未填写") && details.Controls.OfType<Button>().Count(b => !b.Enabled) == 2, "Missing email fields show placeholders and disable copy", lines);
                }
                File.WriteAllLines(Path.Combine(directory, "test-results.txt"), lines, Encoding.UTF8); return 0;
            } catch (Exception ex) { lines.Add("FAIL: " + ex.GetType().Name); File.WriteAllLines(Path.Combine(directory, "test-results.txt"), lines, Encoding.UTF8); return 1; }
        }
        static IEnumerable<TextBox> TextInputs(Control root) {
            foreach (Control c in root.Controls) {
                var text = c as TextBox; if (text != null) yield return text;
                foreach (var child in TextInputs(c)) yield return child;
            }
        }
        static void Assert(bool ok, string name, List<string> lines) { if (!ok) throw new InvalidOperationException(name); lines.Add("PASS: " + name); }
    }
}
