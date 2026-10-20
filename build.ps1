# 用 Windows 自带的 .NET Framework 编译器构建，无第三方依赖。
# 产物输出到 dist\，并打印 SHA-256 供核对。
$ErrorActionPreference = 'Stop'

$name = 'PCL原版下载恢复-干净版.exe'
$source = Join-Path $PSScriptRoot 'src\PclDownloadRestoreClean.cs'
$dist = Join-Path $PSScriptRoot 'dist'
$target = Join-Path $dist $name

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $csc)) {
    throw '找不到 Windows 自带的 csc.exe，需要 .NET Framework 4.x。'
}
if (-not (Test-Path -LiteralPath $source)) {
    throw "找不到源码：$source"
}

if (-not (Test-Path -LiteralPath $dist)) {
    New-Item -ItemType Directory -Path $dist -Force | Out-Null
}

& $csc /nologo /target:winexe /platform:anycpu /optimize+ /codepage:65001 `
    /reference:System.Windows.Forms.dll /reference:System.Drawing.dll `
    "/out:$target" $source

if ($LASTEXITCODE -ne 0) { throw "编译失败，csc 退出码 $LASTEXITCODE。" }

$file = Get-Item -LiteralPath $target
$hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash

Write-Host ''
Write-Host '编译完成' -ForegroundColor Green
Write-Host ("  文件   {0}" -f $file.Name)
Write-Host ("  大小   {0} 字节" -f $file.Length)
Write-Host ("  SHA256 {0}" -f $hash)
