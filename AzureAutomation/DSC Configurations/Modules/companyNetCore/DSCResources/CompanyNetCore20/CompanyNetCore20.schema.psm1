Configuration CompanyNetCore20
{
    Package NetCore20
    {
        Name = ".Net Core20"
        Path = "https://download.microsoft.com/download/5/6/B/56BFEF92-9045-4414-970C-AB31E0FC07EC/dotnet-runtime-2.0.0-win-x64.exe"
        Arguments = "/quiet"
        ProductId = "BE54D79A-4E7F-4F5D-AB22-9CD46397F2F3"
        Ensure = "Present"
    }
}
