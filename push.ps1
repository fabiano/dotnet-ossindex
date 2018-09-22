$version = Get-Content "$PSScriptRoot\semver.txt"

dotnet nuget push --source https://api.nuget.org/v3/index.json "$PSScriptRoot\.nupkgs\dotnet-ossindex.$version.nupkg"
