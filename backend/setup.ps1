$ErrorActionPreference = "Stop"

$pythonVersion = $null
foreach ($version in @("3.12", "3.11")) {
    $available = $false
    try {
        & py "-$version" -c "import sys" *> $null
        $available = ($LASTEXITCODE -eq 0)
    } catch {
        $available = $false
    }
    if ($available) {
        $pythonVersion = $version
        break
    }
}

if ($null -eq $pythonVersion) {
    throw "Python 3.11 or 3.12 is required. Python 3.14 is not supported by the pinned pydantic-core release."
}

if (Test-Path ".venv\Scripts\python.exe") {
    $venvVersion = (& ".\.venv\Scripts\python.exe" --version 2>&1) -join " "
    if ($venvVersion -notmatch "Python 3\.(11|12)") {
        throw "The existing .venv uses $venvVersion. Stop processes using it, remove .venv, and run this script again."
    }
} elseif (Test-Path ".venv") {
    throw "The existing .venv is incomplete. Remove .venv and run this script again."
} else {
    Write-Host "Creating backend environment with Python $pythonVersion..."
    & py "-$pythonVersion" -m venv .venv
}

& .\.venv\Scripts\python.exe -m pip install -r requirements.txt

Write-Host "Backend setup complete. Start the API with:"
Write-Host ".\.venv\Scripts\python.exe -m uvicorn app.main:app --reload"