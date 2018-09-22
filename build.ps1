$version = Get-Content "$PSScriptRoot\semver.txt"
$output = "$PSScriptRoot\.nupkgs"

dotnet restore
dotnet build
dotnet pack DotNetOSSIndex\DotNetOSSIndex.csproj --configuration Release --version-suffix $version --output $output
