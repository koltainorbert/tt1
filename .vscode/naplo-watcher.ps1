$p = (Get-Location).Path
while ($true) {
    $fj = @(git diff --name-only HEAD 2>$null) + @(git ls-files --others --exclude-standard 2>$null) | Where-Object { $_ -ne "" }
    if ($fj.Count -gt 0) {
        git add .
        git diff --cached --quiet
        if ($LASTEXITCODE -ne 0) {
            git commit -m ("Auto_" + (Get-Date -Format "yyyy.MM.dd_HH.mm"))
            git push
        }
    }
    Start-Sleep -Seconds 60
}
