# dotnet-oss-index

A .NET Core global tool to list vulnerable Nuget packages.

This tool uses the [Sonatype OSS Index API](#sonatype-oss-index) to check your packages against known vulnerabilities.

- [Installation](#installation)
- [Usage](#usage)
- [Sonatype OSS Index](#sonatype-oss-index)

## Installation

Download and install the [.NET Core 2.1 SDK](https://www.microsoft.com/net/download) or newer. Once installed, run the following command:

```bash
dotnet tool install --global dotnet-oss-index
```

If you already have a previous version of **dotnet-oss-index** installed, you can upgrade to the latest version using the following command:

```bash
dotnet tool update --global dotnet-oss-index
```

## Usage

```text
Usage: dotnet oss-index [arguments] [options]

Arguments:
  Path                        The path to a .sln, .csproj or .vbproj file

Options:
  -u|--username <USERNAME>    OSS Index Username
  -a|--api-token <API_TOKEN>  OSS Index API Token
  -?|-h|--help                Show help information
```

To run the **dotnet-oss-index** tool you need to specify a solution or project file. In case you pass a solution, the tool will automatically scan all the projects for vulnerabilities.

```bash
dotnet oss-index YourSolution.sln
```

![Screenshot of dotnet-oss-index](screenshot.png)

### OSS Index API rate limit

The OSS Index REST API has a rate limit for unauthenticated requests. If you exceed the limit, you can create an account on their [website](https://ossindex.sonatype.org) and use the authentication options to execute authenticated requests.

```bash
dotnet oss-index YourSolution.sln --username <YOUR-USERNAME> --api-token <YOUR-API-TOKEN>
```

# Sonatype OSS Index

OSS Index is a free service used by developers to identify open source dependencies and determine if there are any known, publicly disclosed, vulnerabilities. 

You can read more about the service here https://ossindex.sonatype.org.
