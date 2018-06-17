Configuration companyNginx
{
    Import-DSCResource -Module companyNginx

    Node Server
    {
        companyNginx nginx 
        {
        }

    }
}
