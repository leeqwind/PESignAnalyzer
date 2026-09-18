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

    # Windows PowerShell promotes native stderr to an ErrorRecord. Keep
    # expected diagnostics in the captured output without terminating the test.
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $Executable @Arguments 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    [pscustomobject]@{
        ExitCode = $exitCode
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

$invalidRevocation = Invoke-Arguments @('--revocation', 'sometimes', 'unused.exe')
if ($invalidRevocation.ExitCode -ne 2) {
    throw 'An invalid --revocation value did not return usage exit code 2.'
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

    $verified = Invoke-Arguments @('--verify', $embeddedPath)
    if ($verified.ExitCode -ne 0) {
        throw "Embedded verification failed for $embeddedPath.`n$($verified.Output)"
    }
    Assert-Match $verified.Output 'verification\.contentDigest:\s+valid' `
        'The embedded Authenticode digest was not validated.'
    Assert-Match $verified.Output 'verification\.cmsSignature:\s+valid' `
        'The embedded CMS signature was not validated.'
    Assert-Match $verified.Output 'verification\.overall:\s+valid' `
        'The embedded signature was not reported as valid.'

    $temporaryFile = Join-Path ([IO.Path]::GetTempPath()) `
        ("PESignAnalyzer-{0}.exe" -f [guid]::NewGuid())
    try {
        [IO.File]::Copy($embeddedPath, $temporaryFile)
        $bytes = [IO.File]::ReadAllBytes($temporaryFile)
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
        $optionalSize = [BitConverter]::ToUInt16($bytes, $peOffset + 20)
        $sectionOffset = $peOffset + 24 + $optionalSize
        $rawOffset = [BitConverter]::ToUInt32($bytes, $sectionOffset + 20)
        $bytes[$rawOffset + 16] = $bytes[$rawOffset + 16] -bxor 1
        [IO.File]::WriteAllBytes($temporaryFile, $bytes)
        $tampered = Invoke-Arguments @('--verify', $temporaryFile)
        if ($tampered.ExitCode -ne 3) {
            throw 'Tampered input did not return verification exit code 3.'
        }
        Assert-Match $tampered.Output 'verification\.contentDigest:\s+invalid' `
            'Tampered input was not rejected by the content digest check.'
    }
    finally {
        Remove-Item -LiteralPath $temporaryFile -Force -ErrorAction SilentlyContinue
    }
}

$catalogPath = Join-Path $env:SystemRoot 'System32\notepad.exe'
if (Test-Path -LiteralPath $catalogPath) {
    $signature = Get-AuthenticodeSignature -LiteralPath $catalogPath
    if ($signature.SignatureType -eq 'Catalog') {
        $catalog = Invoke-Analyzer $catalogPath
        if ($catalog.ExitCode -ne 0) {
            throw "Automatic catalog discovery failed.`n$($catalog.Output)"
        }
        Assert-Match $catalog.Output 'signtype:\s+cataloged' `
            'A catalog-only file was not identified automatically.'
        Assert-Match $catalog.Output 'catafile:\s+.+\.cat' `
            'Automatic discovery did not report its catalog path.'

        $catalogVerification = Invoke-Arguments @('--verify', $catalogPath)
        if ($catalogVerification.ExitCode -ne 0) {
            throw "Automatic catalog verification failed.`n$($catalogVerification.Output)"
        }
        Assert-Match $catalogVerification.Output 'verification\.overall:\s+valid' `
            'The automatically discovered catalog was not verified.'

        $embeddedOnly = Invoke-Arguments @('--embedded-only', $catalogPath)
        if ($embeddedOnly.ExitCode -ne 1) {
            throw '--embedded-only did not disable automatic catalog discovery.'
        }

        if ($env:PESIGN_TEST_CATALOG) {
            $explicitCatalog = Invoke-Arguments @('--verify', '--catalog',
                $env:PESIGN_TEST_CATALOG, $catalogPath)
            if ($explicitCatalog.ExitCode -ne 0) {
                throw "Explicit catalog verification failed.`n$($explicitCatalog.Output)"
            }
            Assert-Match $explicitCatalog.Output 'verification\.overall:\s+valid' `
                'Explicit catalog membership was not verified.'
        }
    }
}

Write-Host 'PESignAnalyzer smoke tests passed.'
