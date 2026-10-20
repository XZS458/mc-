// PCL 原版下载恢复工具 —— 干净重写版
// 功能与公开的 v1.1 一致：为两种已验证的 2.99.0.0 构建生成"恢复原版下载"的副本。
// 本工具不联网、不写注册表、不启动任何进程、不安装任何东西。
// .NET Framework 4.8，单文件，免安装。

using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

static class Info
{
    public const string Title = "PCL 原版下载恢复工具（干净版）";
    public const string Version = "1.0";
}

// ─────────────────────────── 补丁数据 ───────────────────────────
// 两个 2.99.0.0 构建各自的原版指纹、补丁位置与原始指令。
// 补丁长度为等长替换，PE 布局与资源不受影响。
static class PatchData
{
    public sealed class Build
    {
        public int Length;
        public int LoaderOffset;        // 下载页加载器的修补位置
        public int VisibilityOffset;    // 版本修改页原版入口的可见性
        public string SourceHash;       // 原版 SHA-256
        public string ResultHash;       // 修补后 SHA-256（用于结果校验）
        public byte[] SourceBytes;      // 该位置原有的指令，用于二次确认
        public Build(int length, int loader, int visibility, string sourceHash, string resultHash, string before)
        {
            Length = length;
            LoaderOffset = loader;
            VisibilityOffset = visibility;
            SourceHash = sourceHash;
            ResultHash = resultHash;
            SourceBytes = Hex.ToBytes(before);
        }
    }

    public static readonly Build[] All = new Build[]
    {
        new Build(5980160, 180442, 205542,
            "6B6E1260CB5A1D6A303855F1C60CAB3D0BC1AEBBA7E40A964180188B271E7386",
            "98B494DD68B953988F445BFC29485C7D2014D472D8A7A685488A136FEA4D3F5F",
            "72334701707EFB0900042C077EFB0900042B167EF9090004FE0667140006738D05000A2580FB0900041418738E05000A"),
        new Build(5985280, 182174, 207274,
            "5B64D6D540C376390470CEA3AB99D47661E8BCA81BE2BA647EA83E7D2E9428FA",
            "3561464287E7AAE8EDE78ABF0573EE55CC7BD2076BA1F8975EEEB135EC8FAB29",
            "728A4901707EFD0900042C077EFD0900042B167EFB090004FE0667140006738E05000A2580FD0900041418738F05000A")
    };

    // 替换后的指令：跳过条件判断，直接读取原版列表字段
    public static readonly byte[] LoaderReplacement = Hex.ToBytes(
        "7E0F04000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    public const byte VisibilitySource = 0x18;
    public const byte VisibilityResult = 0x16;
}

static class Hex
{
    public static byte[] ToBytes(string text)
    {
        byte[] result = new byte[text.Length / 2];
        for (int i = 0; i < result.Length; i++)
            result[i] = Convert.ToByte(text.Substring(i * 2, 2), 16);
        return result;
    }
}

// ─────────────────────────── 核心逻辑 ───────────────────────────
static class Patcher
{
    public static string Sha256(byte[] data)
    {
        using (SHA256 sha = SHA256.Create())
            return BitConverter.ToString(sha.ComputeHash(data)).Replace("-", "");
    }

    static byte[] Load(string path)
    {
        byte[] data = File.ReadAllBytes(path);
        bool known = false;
        foreach (PatchData.Build build in PatchData.All)
            if (data.Length == build.Length) known = true;
        if (!known)
            throw new InvalidOperationException(
                "不支持这个文件（" + data.Length + " 字节）。\n本工具只处理两种已验证的 2.99.0.0 构建，未修改任何文件。");
        return data;
    }

    // 返回：0=可处理的原版，1=已处理过，2=指纹不匹配
    public static int Inspect(string path, out string message)
    {
        byte[] data = Load(path);
        string hash = Sha256(data);
        foreach (PatchData.Build build in PatchData.All)
        {
            if (hash == build.ResultHash)
            {
                message = "这个文件已经恢复过原版下载，无需重复处理。";
                return 1;
            }
            if (hash == build.SourceHash)
            {
                message = "校验通过：支持的原版构建，可以生成副本。";
                return 0;
            }
        }
        message = "文件指纹不匹配。\n只支持两种已验证的 2.99.0.0 构建；其他版本、改版或损坏文件不会被修改。";
        return 2;
    }

    public static string Apply(string input, string output)
    {
        string fullIn = Path.GetFullPath(input);
        string fullOut = Path.GetFullPath(output);
        if (string.Equals(fullIn, fullOut, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("请另存为副本，不能覆盖原启动器。");

        byte[] data = Load(fullIn);
        string hash = Sha256(data);

        PatchData.Build target = null;
        foreach (PatchData.Build build in PatchData.All)
        {
            if (hash == build.ResultHash)
                throw new InvalidOperationException("这个文件已经恢复过原版下载，无需重复处理。");
            if (hash == build.SourceHash) target = build;
        }
        if (target == null)
            throw new InvalidOperationException("文件指纹不匹配，已停止，未修改任何文件。");

        // 第二次确认：目标位置的指令必须与已知原版一致，否则拒绝
        for (int i = 0; i < target.SourceBytes.Length; i++)
            if (data[target.LoaderOffset + i] != target.SourceBytes[i])
                throw new InvalidOperationException("下载页指令校验失败，文件可能被改动过，已停止。");
        if (data[target.VisibilityOffset] != PatchData.VisibilitySource)
            throw new InvalidOperationException("版本修改页指令校验失败，已停止。");

        Array.Copy(PatchData.LoaderReplacement, 0, data, target.LoaderOffset, PatchData.LoaderReplacement.Length);
        data[target.VisibilityOffset] = PatchData.VisibilityResult;

        string resultHash = Sha256(data);
        if (resultHash != target.ResultHash)
            throw new InvalidOperationException("补丁结果校验失败，未写入任何文件。");

        if (File.Exists(fullOut))
            throw new IOException("目标文件已存在，请换一个文件名。本工具不会覆盖已有文件。");

        bool created = false;
        try
        {
            using (FileStream stream = new FileStream(fullOut, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                created = true;
                stream.Write(data, 0, data.Length);
                stream.Flush(true);
            }
            if (Sha256(File.ReadAllBytes(fullOut)) != target.ResultHash)
                throw new IOException("写入后的校验失败，副本可能不完整，已删除。");
        }
        catch
        {
            if (created && File.Exists(fullOut))
            {
                try { File.Delete(fullOut); } catch { }
            }
            throw;
        }
        return resultHash;
    }
}

// ─────────────────────────── 界面 ───────────────────────────
sealed class MainForm : Form
{
    readonly TextBox pathBox = new TextBox();
    readonly Label statusLabel = new Label();
    readonly Button pickButton = new Button();
    readonly Button applyButton = new Button();
    readonly TextBox logBox = new TextBox();

    public MainForm()
    {
        Text = Info.Title + " v" + Info.Version;
        Font = new Font("Microsoft YaHei UI", 10F);
        ClientSize = new Size(720, 470);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.White;
        AllowDrop = true;

        Label heading = new Label();
        heading.Text = "恢复原版游戏下载";
        heading.Font = new Font(Font.FontFamily, 18F, FontStyle.Bold);
        heading.AutoSize = true;
        heading.Location = new Point(26, 22);

        Label hint = new Label();
        hint.Text = "选择现有的 PCL2.exe，生成可单独运行的副本。原文件保留，游戏与配置不受影响。\n也可以直接把 PCL2.exe 拖进这个窗口。";
        hint.Location = new Point(28, 74);
        hint.Size = new Size(660, 46);

        pathBox.SetBounds(28, 130, 540, 28);
        pathBox.ReadOnly = true;

        pickButton.Text = "选择文件…";
        pickButton.SetBounds(578, 128, 114, 32);
        pickButton.Click += delegate { PickFile(); };

        statusLabel.SetBounds(28, 172, 664, 62);
        statusLabel.Text = "等待选择文件。\n支持两种已验证的 2.99.0.0 构建（自动校验 SHA-256）。";

        applyButton.Text = "生成恢复下载的副本…";
        applyButton.SetBounds(28, 240, 300, 42);
        applyButton.BackColor = Color.FromArgb(226, 239, 255);
        applyButton.Enabled = false;
        applyButton.Click += delegate { Apply(); };

        logBox.SetBounds(28, 294, 664, 118);
        logBox.Multiline = true;
        logBox.ReadOnly = true;
        logBox.ScrollBars = ScrollBars.Vertical;
        logBox.BackColor = Color.FromArgb(248, 248, 248);
        logBox.Font = new Font("Consolas", 9F);

        Label foot = new Label();
        foot.Text = "本工具自身 SHA-256：" + SelfHash();
        foot.Location = new Point(28, 420);
        foot.Size = new Size(664, 22);
        foot.ForeColor = Color.DimGray;
        foot.Font = new Font(Font.FontFamily, 8.5F);

        Controls.AddRange(new Control[] { heading, hint, pathBox, pickButton, statusLabel, applyButton, logBox, foot });

        DragEnter += delegate(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy;
        };
        DragDrop += delegate(object sender, DragEventArgs e)
        {
            string[] files = e.Data.GetData(DataFormats.FileDrop) as string[];
            if (files != null && files.Length > 0) Select(files[0]);
        };
    }

    public MainForm(string initial) : this()
    {
        if (!string.IsNullOrEmpty(initial) && File.Exists(initial))
            Shown += delegate { Select(initial); };
    }

    static string SelfHash()
    {
        try { return Patcher.Sha256(File.ReadAllBytes(Application.ExecutablePath)); }
        catch { return "（读取失败）"; }
    }

    void PickFile()
    {
        using (OpenFileDialog dialog = new OpenFileDialog())
        {
            dialog.Title = "选择需要恢复原版下载的 PCL2 启动器";
            dialog.Filter = "PCL 启动器 (*.exe)|*.exe|所有文件 (*.*)|*.*";
            if (dialog.ShowDialog(this) == DialogResult.OK) Select(dialog.FileName);
        }
    }

    void Select(string path)
    {
        applyButton.Enabled = false;
        pathBox.Text = path;
        try
        {
            string message;
            int code = Patcher.Inspect(path, out message);
            if (code == 0)
            {
                statusLabel.ForeColor = Color.DarkGreen;
                statusLabel.Text = message + "\n原版版本列表与版本修改入口将恢复；整合包安装限制仍保留。";
                applyButton.Enabled = true;
            }
            else if (code == 1)
            {
                statusLabel.ForeColor = Color.DarkBlue;
                statusLabel.Text = message;
            }
            else
            {
                statusLabel.ForeColor = Color.Firebrick;
                statusLabel.Text = message;
            }
        }
        catch (Exception ex)
        {
            statusLabel.ForeColor = Color.Firebrick;
            statusLabel.Text = ex.Message;
        }
    }

    void Apply()
    {
        using (SaveFileDialog dialog = new SaveFileDialog())
        {
            dialog.Title = "保存副本（不会覆盖原文件）";
            dialog.Filter = "PCL 启动器 (*.exe)|*.exe";
            dialog.InitialDirectory = Path.GetDirectoryName(pathBox.Text);
            dialog.FileName = Path.GetFileNameWithoutExtension(pathBox.Text) + ".原版下载恢复.exe";
            dialog.DefaultExt = "exe";
            if (dialog.ShowDialog(this) != DialogResult.OK) return;

            applyButton.Enabled = false;
            pickButton.Enabled = false;
            try
            {
                Log("开始处理：" + Path.GetFileName(pathBox.Text));
                string resultHash = Patcher.Apply(pathBox.Text, dialog.FileName);
                Log("已生成：" + dialog.FileName);
                Log("输出 SHA-256：" + resultHash);
                Log("校验一致，处理完成。");

                statusLabel.ForeColor = Color.DarkGreen;
                statusLabel.Text = "已生成并校验成功。\n请关闭原启动器，再运行新副本。";
                MessageBox.Show(this,
                    "已生成：\n" + dialog.FileName + "\n\n请关闭原启动器后运行此副本。原文件已保留。",
                    "完成", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                Log("失败：" + ex.Message);
                MessageBox.Show(this, ex.Message, "未生成副本", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                applyButton.Enabled = true;
                pickButton.Enabled = true;
            }
        }
    }

    void Log(string line)
    {
        logBox.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + line + "\r\n");
    }
}

static class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        try
        {
            if (args.Length == 1 && args[0] == "--version")
            {
                Console.WriteLine(Info.Title + " v" + Info.Version);
                Console.WriteLine("SHA-256: " + Patcher.Sha256(File.ReadAllBytes(Application.ExecutablePath)));
                return 0;
            }
            if (args.Length == 2 && args[0] == "--check")
            {
                string message;
                int code = Patcher.Inspect(args[1], out message);
                Console.WriteLine(message);
                return code == 0 ? 0 : (code == 1 ? 2 : 1);
            }
            if (args.Length == 3 && args[0] == "--patch")
            {
                string hash = Patcher.Apply(args[1], args[2]);
                Console.WriteLine("已生成：" + args[2]);
                Console.WriteLine("SHA-256：" + hash);
                return 0;
            }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm(args.Length == 1 ? args[0] : null));
            return 0;
        }
        catch (Exception ex)
        {
            if (args.Length == 0)
                MessageBox.Show(ex.Message, Info.Title, MessageBoxButtons.OK, MessageBoxIcon.Error);
            else
                Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }
}
