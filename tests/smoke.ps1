param(
    [Parameter(Mandatory = $true)]
    [string]$Executable
)

$ErrorActionPreference = 'Stop'
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$RepositoryRoot = Split-Path -Parent $PSScriptRoot

function Invoke-Analyzer {
    param([string]$Path)

    Invoke-Arguments @($Path)
}

function Invoke-Arguments {
    param([string[]]$Arguments)

    $output = & $Executable @Arguments 2>&1 | Out-String
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

$help = Invoke-Arguments @('--help')
if ($help.ExitCode -ne 0) {
    throw '--help did not return exit code 0.'
}
Assert-Match $help.Output 'Usage: PESignAnalyzer\.exe \[options\] <file>' `
    '--help did not print the standardized usage text.'

$version = Invoke-Arguments @('--version')
if ($version.ExitCode -ne 0) {
    throw '--version did not return exit code 0.'
}
Assert-Match $version.Output '^PESignAnalyzer \d+\.\d+\.\d+' `
    '--version did not print a semantic version.'

$missingInput = Invoke-Arguments @()
if ($missingInput.ExitCode -ne 2) {
    throw 'A missing input file did not return usage exit code 2.'
}

$unknownOption = Invoke-Arguments @('--not-an-option')
if ($unknownOption.ExitCode -ne 2) {
    throw 'An unknown option did not return usage exit code 2.'
}

$missingCatalog = Invoke-Arguments @('--catalog')
if ($missingCatalog.ExitCode -ne 2) {
    throw 'A missing --catalog value did not return usage exit code 2.'
}

$optionConflict = Invoke-Arguments @(
    '--catalog', 'unused.cat', '--embedded-only', 'unused.exe')
if ($optionConflict.ExitCode -ne 2) {
    throw 'Conflicting catalog options did not return usage exit code 2.'
}

$readmePath = Join-Path $RepositoryRoot 'README.md'
$unsigned = Invoke-Analyzer $readmePath
if ($unsigned.ExitCode -eq 0) {
    throw 'Unsigned input unexpectedly returned success.'
}
Assert-Match $unsigned.Output 'signtype:\s+none' `
    'Unsigned input was not reported as signtype none.'

$endOfOptions = Invoke-Arguments @('--', $readmePath)
if ($endOfOptions.ExitCode -ne 1) {
    throw '-- did not preserve the unsigned-file analysis exit code.'
}

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

        $embeddedOnly = Invoke-Arguments @('--embedded-only', $catalogPath)
        if ($embeddedOnly.ExitCode -eq 0) {
            throw '--embedded-only unexpectedly accepted a catalog-only file.'
        }
        Assert-Match $embeddedOnly.Output 'signtype:\s+none' `
            '--embedded-only did not disable catalog discovery.'

        $catalogMatch = [regex]::Match(
            $catalog.Output, '(?m)^catafile:\s+(.+\.cat)\s*$')
        if ($catalogMatch.Success) {
            $explicitCatalog = Invoke-Arguments @(
                '--catalog', $catalogMatch.Groups[1].Value, $catalogPath)
            if ($explicitCatalog.ExitCode -ne 0) {
                throw '--catalog failed with the discovered catalog file.'
            }
            Assert-Match $explicitCatalog.Output 'signtype:\s+cataloged' `
                '--catalog did not analyze the specified catalog.'
        }
    }
}

Write-Host 'PESignAnalyzer smoke tests passed.'
