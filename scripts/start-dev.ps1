# Chay BE + ngrok cho moi truong dev.
#
#   powershell -ExecutionPolicy Bypass -File scripts/start-dev.ps1
#
# Gop nguyen nguoi ban hay gap phoi:
#   1. Dung BE neu dang chay (no can doc .env moi de lay redirect_uri).
#   2. Bat ngrok, doc URL moi.
#   3. Ghi redirect_uri moi vao .env.
#   4. Khoi dong BE.
#
# Sau khi chay xong, COPY dung dong "CAN DANG KY O HARAVAN" roi dan vao Haravan Partner
# Dashboard. Giong nguyen day; mot ky tu khac la Haravan tu choi `invalid_request`.
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$ngrok = 'C:\Users\hieu hoang\AppData\Local\Microsoft\WinGet\Packages\Ngrok.Ngrok_Microsoft.Winget.Source_8wekyb3d8bbwe\ngrok.exe'

function Stop-Listening([int]$port) {
    $conn = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    foreach ($item in $conn) {
        Stop-Process -Id $item.OwningProcess -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 2
}

Stop-Listening 3000

$existing = Get-Process ngrok -ErrorAction SilentlyContinue
if ($existing) { $existing | Stop-Process -Force }
Start-Sleep -Seconds 1

if (-not (Test-Path -LiteralPath $ngrok)) {
    throw "Khong tim thay ngrok tai $ngrok"
}

Start-Process -FilePath $ngrok -ArgumentList 'http', '3000' -NoNewWindow

$publicUrl = $null
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 1
    try {
        $tunnels = Invoke-RestMethod -Uri 'http://127.0.0.1:4040/api/tunnels' -TimeoutSec 3
        $publicUrl = ($tunnels.tunnels | Where-Object { $_.public_url } | Select-Object -First 1).public_url
        if ($publicUrl) { break }
    } catch {
        # chua len, cho them
    }
}

if (-not $publicUrl) {
    throw 'ngrok khong len duoc trong 20 giay'
}

$envFile = Join-Path $root '.env'
$text = Get-Content -LiteralPath $envFile -Raw
$callback = "$publicUrl/api/v1/haravan/auth/callback"
$text = $text -replace 'HARAVAN_OPENID_REDIRECT_URI=.*', "HARAVAN_OPENID_REDIRECT_URI=$callback"
[System.IO.File]::WriteAllText($envFile, $text, (New-Object System.Text.UTF8Encoding($false)))

Start-Process -FilePath 'npx.cmd' -ArgumentList 'nest', 'start' -WorkingDirectory $root -WindowStyle Hidden

Write-Host ''
Write-Host 'BE    : http://localhost:3000' -ForegroundColor Green
Write-Host "ngrok : $publicUrl" -ForegroundColor Green
Write-Host ''
Write-Host 'CAN DANG KY O HARAVAN (chen nguyen dong nay):' -ForegroundColor Yellow
Write-Host "  $callback" -ForegroundColor Yellow
Write-Host ''
