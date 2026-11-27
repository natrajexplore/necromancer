<#
.SYNOPSIS
  Builds and deploys NECROMANCER to AWS: Lambda API, S3 + CloudFront UI, USD 1 budget alarm.

.DESCRIPTION
  1. Stages the Lambda sources in build\lambda-src (api, necro, samples, pinned requirements from uv.lock).
  2. sam build, then sam deploy (shows the change set and asks before applying, unless -Yes).
  3. npm.cmd --prefix frontend run build (the UI calls /v1 and /healthz on its own origin).
  4. aws s3 cp/sync of frontend\dist into the private UI bucket, then a CloudFront invalidation.

  With -NoCdn (fallback while CloudFront is unavailable on the account) the order changes: the UI is built
  first, frontend\dist is copied into build\lambda-src\static, the stack is deployed with EnableCdn=false
  (no bucket, distribution or headers policies), and the Lambda serves the UI from the HTTP API endpoint.
  Steps 3 and 4 (S3 sync, invalidation) are skipped.

  Nothing here is hardcoded to an account, region or e-mail address. The region comes from -Region,
  AWS_REGION / AWS_DEFAULT_REGION, or `aws configure`. Credentials come from the usual AWS CLI chain.
  Python tools run as modules (python -m) and npm as npm.cmd, because Smart App Control blocks
  unsigned launchers.

.PARAMETER AlertEmail
  Address that receives the AWS Budgets alerts (USD 1 by default). Required.

.PARAMETER StackName
  CloudFormation stack name. Default: necromancer.

.PARAMETER Region
  AWS region. Default: the AWS CLI configuration.

.PARAMETER Profile
  AWS CLI profile. Default: the AWS CLI default chain.

.PARAMETER Yes
  Apply the change set without the confirmation prompt.

.PARAMETER NoCdn
  Deploy without S3 and CloudFront. The function serves the built UI itself at the API endpoint.
  Redeploy without -NoCdn once CloudFront is available (the stack then creates the CDN resources).

.PARAMETER SkipTests
  Skip the backend API tests that run before the build.

.EXAMPLE
  .\deploy.ps1 -AlertEmail <your-address>
#>
[CmdletBinding(PositionalBinding = $false)]  # a mistyped switch must fail, not become -StackName
param(
    [Parameter(Mandatory = $true)][string]$AlertEmail,
    [string]$StackName = 'necromancer',
    [string]$Region,
    [string]$Profile,
    [switch]$Yes,
    [switch]$NoCdn,
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = $PSScriptRoot
$Stage = Join-Path $Root 'build\lambda-src'
if (-not $env:UV_PYTHON_PREFERENCE) { $env:UV_PYTHON_PREFERENCE = 'only-system' }

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory = $Root
    )
    Write-Host ">> $Exe $($Arguments -join ' ')"
    Push-Location $WorkingDirectory
    try {
        & $Exe @Arguments
        if ($LASTEXITCODE -ne 0) { throw "$Exe failed with exit code $LASTEXITCODE" }
    }
    finally {
        Pop-Location
    }
}

function Get-NativeOutput {
    param([Parameter(Mandatory = $true)][string]$Exe, [string[]]$Arguments = @())
    $text = & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Exe failed with exit code $LASTEXITCODE" }
    return ($text -join "`n")
}

foreach ($tool in 'uv', 'sam', 'aws', 'npm.cmd', 'git') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "Required tool not found on PATH: $tool" }
}

# ---- AWS arguments (region and profile are never hardcoded) -------------------------------------
$profileArgs = @()
if ($Profile) { $profileArgs = @('--profile', $Profile) }

if (-not $Region) { $Region = $env:AWS_REGION }
if (-not $Region) { $Region = $env:AWS_DEFAULT_REGION }
if (-not $Region) {
    $configured = & aws configure get region @profileArgs 2>$null
    if ($LASTEXITCODE -eq 0 -and $configured) { $Region = ($configured -join '').Trim() }
}
if (-not $Region) { throw 'No AWS region. Pass -Region, set AWS_REGION, or run: aws configure' }
$awsArgs = @('--region', $Region) + $profileArgs

Write-Host '== Checking credentials (read-only)'
Invoke-Native 'aws' (@('sts', 'get-caller-identity', '--query', 'Arn', '--output', 'text') + $awsArgs)

function Build-Ui {
    Write-Host '== Building the UI'
    Remove-Item Env:VITE_API_BASE -ErrorAction SilentlyContinue  # same origin: the UI and the API share one host
    if (-not (Test-Path (Join-Path $Root 'frontend\node_modules'))) {
        Invoke-Native 'npm.cmd' @('--prefix', 'frontend', 'ci') | Out-Host  # keep npm output out of the return value
    }
    Invoke-Native 'npm.cmd' @('--prefix', 'frontend', 'run', 'build') | Out-Host
    $built = Join-Path $Root 'frontend\dist'
    if (-not (Test-Path (Join-Path $built 'index.html'))) { throw 'frontend\dist\index.html is missing after the build' }
    return $built
}

# ---- 0. Backend tests ----------------------------------------------------------------------------
if (-not $SkipTests) {
    Write-Host '== Backend API tests'
    Invoke-Native 'uv' @('run', 'python', '-m', 'pytest', '-q', '-x', 'tests/test_api.py') (Join-Path $Root 'backend')
}

# -NoCdn: the UI is built first because it ships inside the Lambda package.
$dist = $null
if ($NoCdn) { $dist = Build-Ui }

# ---- 1. Stage the Lambda sources -----------------------------------------------------------------
Write-Host '== Staging Lambda sources'
if (Test-Path $Stage) { Remove-Item -Recurse -Force $Stage }
New-Item -ItemType Directory -Path $Stage | Out-Null
foreach ($package in 'api', 'necro') {
    Copy-Item -Recurse -Path (Join-Path $Root "backend\$package") -Destination (Join-Path $Stage $package)
}
Copy-Item -Recurse -Path (Join-Path $Root 'samples') -Destination (Join-Path $Stage 'samples')
@(Get-ChildItem -Path $Stage -Recurse -Directory -Filter '__pycache__') | Remove-Item -Recurse -Force
if ($NoCdn) {
    # The app serves this directory when NECRO_STATIC_DIR is set (template.yaml sets it when EnableCdn=false).
    Copy-Item -Recurse -Path $dist -Destination (Join-Path $Stage 'static')
}
# Pinned by uv.lock. The MCP server and uvicorn are dev-box tools, so they and their dependencies are left out.
Invoke-Native 'uv' @(
    'export', '--frozen', '--no-dev', '--no-emit-project', '--no-hashes',
    '--prune', 'mcp', '--prune', 'uvicorn',
    '--output-file', (Join-Path $Stage 'requirements.txt')
) (Join-Path $Root 'backend')

$commit = 'unknown'
$head = & git -C $Root rev-parse --short=12 HEAD 2>$null
if ($LASTEXITCODE -eq 0 -and $head) { $commit = ($head -join '').Trim() }

# ---- 2. sam build + sam deploy -------------------------------------------------------------------
Write-Host '== sam build'
Invoke-Native 'sam' @('build', '--template-file', 'template.yaml')

Write-Host '== sam deploy'
$deployArgs = @(
    'deploy',
    '--stack-name', $StackName,
    '--resolve-s3',
    '--capabilities', 'CAPABILITY_IAM',
    '--no-fail-on-empty-changeset',
    '--parameter-overrides', "AlertEmail=$AlertEmail", "GitCommit=$commit", "EnableCdn=$(if ($NoCdn) { 'false' } else { 'true' })"
)
if ($Yes) { $deployArgs += '--no-confirm-changeset' } else { $deployArgs += '--confirm-changeset' }
Invoke-Native 'sam' ($deployArgs + $awsArgs)

$json = Get-NativeOutput 'aws' (@('cloudformation', 'describe-stacks', '--stack-name', $StackName,
        '--query', 'Stacks[0].Outputs', '--output', 'json') + $awsArgs)
$outputs = @{}
foreach ($item in ($json | ConvertFrom-Json)) { $outputs[$item.OutputKey] = $item.OutputValue }
$required = @('SiteUrl')
if (-not $NoCdn) { $required += @('UiBucketName', 'DistributionId') }
foreach ($key in $required) {
    if (-not $outputs.ContainsKey($key)) { throw "Stack output missing: $key" }
}

# ---- 3. Build the UI -----------------------------------------------------------------------------
if (-not $NoCdn) { $dist = Build-Ui }

if (-not $NoCdn) {
    # ---- 4. Upload and invalidate (skipped with -NoCdn) --------------------------------------------------------------------
    # Content types are set explicitly: on Windows the AWS CLI reads them from the registry, which can
    # label .js as text/plain, and the UI's nosniff header would then stop the script from running.
    Write-Host '== Uploading the UI'
    $bucket = "s3://$($outputs['UiBucketName'])"
    $immutable = 'public, max-age=31536000, immutable'  # Vite hashes the file names under assets/
    $types = @(
        @('*.html', 'text/html; charset=utf-8'),
        @('*.js', 'text/javascript'),
        @('*.css', 'text/css'),
        @('*.woff2', 'font/woff2'),
        @('*.woff', 'font/woff'),
        @('*.svg', 'image/svg+xml'),
        @('*.json', 'application/json'),
        @('*.txt', 'text/plain; charset=utf-8')
    )
    foreach ($entry in $types) {
        $pattern = $entry[0]
        $type = $entry[1]
        Invoke-Native 'aws' (@('s3', 'cp', $dist, $bucket, '--recursive', '--only-show-errors',
                '--exclude', '*', '--include', "assets/$pattern",
                '--content-type', $type, '--cache-control', $immutable) + $awsArgs)
        Invoke-Native 'aws' (@('s3', 'cp', $dist, $bucket, '--recursive', '--only-show-errors',
                '--exclude', '*', '--include', $pattern, '--exclude', 'assets/*',
                '--content-type', $type, '--cache-control', 'no-cache') + $awsArgs)
    }
    # Anything left over (other file types) is uploaded here, and files removed from the build are deleted.
    Invoke-Native 'aws' (@('s3', 'sync', $dist, $bucket, '--delete', '--only-show-errors',
            '--cache-control', 'no-cache') + $awsArgs)

    Write-Host '== Invalidating CloudFront'
    Invoke-Native 'aws' (@('cloudfront', 'create-invalidation', '--distribution-id', $outputs['DistributionId'],
            '--paths', '/*', '--query', 'Invalidation.Status', '--output', 'text') + $awsArgs)
}

Write-Host ''
Write-Host "UI:     $($outputs['SiteUrl'])"
Write-Host "Health: $($outputs['SiteUrl'])/healthz"
if ($NoCdn) { Write-Host 'No-CDN mode: the Lambda serves the UI. Redeploy without -NoCdn once CloudFront is available.' }
Write-Host 'Confirm the budget alert subscription from the e-mail AWS sends to the AlertEmail address.'
