# Fire a real brute-force attack at both routers, yourself, anytime.
#
#   powershell -File lab\attack.ps1              # small burst: ~70 log lines, 2 findings
#   powershell -File lab\attack.ps1 -Users 6 -Tries 3   # bigger if you want more
#
# Real wrong-password SSH -> genuine "Failed password" events -> forwarded to
# the auditor on UDP 5514. Watch http://localhost:8501.
#
# Sizing: each router gets Users*Tries attempts, and each attempt produces
# ~4-5 forwarded log lines. Default 4x2 = 8 attempts/router x2 routers = ~70
# log lines total, grouped into 2 findings (one Brute Force per router).
param([int]$Users = 4, [int]$Tries = 2)

$targets = @{ 'Router-01' = '172.18.0.3'; 'Router-02' = '172.18.0.2' }
$names = @('admin','root','hacker','test','guest','oracle','ubuntu','postgres','deploy','ftp')

Write-Host "Attacking both routers ($Users users x $Tries tries)..." -ForegroundColor Yellow
$jobs = foreach ($src in $targets.Keys) {
    $dst = $targets[$src]
    Start-Job -ArgumentList $src, $dst, $Users, $Tries, $names -ScriptBlock {
        param($src, $dst, $Users, $Tries, $names)
        foreach ($u in $names[0..($Users-1)]) {
            for ($i = 0; $i -lt $Tries; $i++) {
                docker exec $src sshpass -p wrongpass ssh -o StrictHostKeyChecking=no `
                    -o ConnectTimeout=2 -o PreferredAuthentications=password `
                    -o PubkeyAuthentication=no "$u@$dst" true 2>$null
            }
        }
    }
}
Wait-Job $jobs -Timeout 90 | Out-Null
Remove-Job $jobs -Force
Write-Host "Attack complete. Watch http://localhost:8501 (updates within ~60s)." -ForegroundColor Green
