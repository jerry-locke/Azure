Configuration companyNetCore20WindowsHosting
{
    Package NetCore20WindowsHosting
    {
        Name = ".Net Core20"
        Path = "https://download.microsoft.com/download/B/1/D/B1D7D5BF-3920-47AA-94BD-7A6E48822F18/DotNetCore.2.0.0-WindowsHosting.exe"
        Arguments = "/quiet"
        ProductId = "CC604AD5-82F0-47C4-BC0E-635DC1092828"
        Ensure = "Present"
    }
}
