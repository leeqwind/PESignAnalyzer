param(
    [Parameter(Mandatory = $true)]
    [string]$Executable
)

$ErrorActionPreference = 'Stop'
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$RepositoryRoot = Split-Path -Parent $PSScriptRoot

function Invoke-Analyzer {
    param([string]$Path)

    $output = & $Executable $Path 2>&1 | Out-String
    [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Output = $output
    }
}

function Assert-Match {
    param(
        [string]$Text,
        [string]$Pattern,
        [string]$Message
    )

    if ($Text -notmatch $Pattern) {
        throw "$Message`nOutput:`n$Text"
    }
}

$unsigned = Invoke-Analyzer (Join-Path $RepositoryRoot 'README.md')
if ($unsigned.ExitCode -eq 0) {
    throw 'Unsigned input unexpectedly returned success.'
}
Assert-Match $unsigned.Output 'signtype:\s+none' `
    'Unsigned input was not reported as signtype none.'

$embeddedCandidates = @(
    'C:\Program Files\Git\cmd\git.exe',
    'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
)
$embeddedPath = $embeddedCandidates | Where-Object {
    if (-not (Test-Path -LiteralPath $_)) { return $false }
    (Get-AuthenticodeSignature -LiteralPath $_).SignatureType -eq 'Authenticode'
} | Select-Object -First 1

if ($embeddedPath) {
    $embedded = Invoke-Analyzer $embeddedPath
    if ($embedded.ExitCode -ne 0) {
        throw "Embedded signature analysis failed for $embeddedPath.`n$($embedded.Output)"
    }
    Assert-Match $embedded.Output 'signtype:\s+embedded' `
        'Embedded signature was not identified.'
    Assert-Match $embedded.Output '\|- subject:\s+\S' `
        'Embedded signature did not produce a signer certificate.'
}

$catalogPath = Join-Path $env:SystemRoot 'System32\notepad.exe'
if (Test-Path -LiteralPath $catalogPath) {
    $signature = Get-AuthenticodeSignature -LiteralPath $catalogPath
    if ($signature.SignatureType -eq 'Catalog') {
        $catalog = Invoke-Analyzer $catalogPath
        if ($catalog.ExitCode -ne 0) {
            throw "Catalog signature analysis failed for $catalogPath.`n$($catalog.Output)"
        }
        Assert-Match $catalog.Output 'signtype:\s+cataloged' `
            'Catalog signature was not identified.'
        Assert-Match $catalog.Output 'catafile:\s+.+\.cat' `
            'Catalog signature did not report its catalog file.'
    }
}

Write-Host 'PESignAnalyzer smoke tests passed.'
