param(
    [string]$Path = "."
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Error "Path does not exist: $Path"
}

$patterns = @(
    @{ Name = "JavaScript innerHTML"; Pattern = "innerHTML\s*="; Include = @("*.js", "*.jsx", "*.ts", "*.tsx", "*.html") },
    @{ Name = "JavaScript outerHTML"; Pattern = "outerHTML\s*="; Include = @("*.js", "*.jsx", "*.ts", "*.tsx", "*.html") },
    @{ Name = "JavaScript insertAdjacentHTML"; Pattern = "insertAdjacentHTML\s*\("; Include = @("*.js", "*.jsx", "*.ts", "*.tsx", "*.html") },
    @{ Name = "JavaScript document.write"; Pattern = "document\.write\s*\("; Include = @("*.js", "*.jsx", "*.ts", "*.tsx", "*.html") },
    @{ Name = "JavaScript eval"; Pattern = "\beval\s*\("; Include = @("*.js", "*.jsx", "*.ts", "*.tsx", "*.html") },
    @{ Name = "Django template safe filter"; Pattern = "\|\s*safe\b"; Include = @("*.html", "*.django") },
    @{ Name = "Python shell=True"; Pattern = "shell\s*=\s*True"; Include = @("*.py") },
    @{ Name = "Python pickle usage"; Pattern = "\bpickle\.loads?\b"; Include = @("*.py") },
    @{ Name = "Python unsafe yaml load"; Pattern = "\byaml\.load\s*\("; Include = @("*.py") },
    @{ Name = "Potential raw SQL formatting"; Pattern = "execute\s*\(\s*f[`"']|raw\s*\(\s*f[`"']"; Include = @("*.py") },
    @{ Name = "Django csrf_exempt"; Pattern = "@csrf_exempt\b|csrf_exempt\s*\("; Include = @("*.py") }
)

$findings = @()

foreach ($entry in $patterns) {
    $extensions = $entry.Include | ForEach-Object { $_.TrimStart("*") }
    $files = Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $extensions -contains $_.Extension }
    foreach ($file in $files) {
        $matches = Select-String -LiteralPath $file.FullName -Pattern $entry.Pattern -AllMatches -ErrorAction SilentlyContinue
        foreach ($match in $matches) {
            $findings += [pscustomobject]@{
                Rule = $entry.Name
                File = $file.FullName
                Line = $match.LineNumber
                Text = $match.Line.Trim()
            }
        }
    }
}

if ($findings.Count -eq 0) {
    Write-Host "No high-risk secure-coding patterns found."
    exit 0
}

Write-Host "Potential secure-coding review findings:"
$findings | Format-Table -AutoSize
Write-Host ""
Write-Host "Review each finding manually. Some results may be acceptable after validation, encoding, or contextual safeguards."
exit 1
