# Get-ADHealth
Powershell module to check AD health

## Ejemplo de utilización para envío por correo electrónico
```
$HtmlFile = "ad-health.html"
Get-ADHealth.ps1 -HtmlFile $HtmlFile
$SmtpServer = "mail.example.com"
$SmtpFrom = "alerts@example.com"
$SmtpTo = "reports@example.com"
$SmtpSubject = "[Active Directory] Comprobacion del estado del Directorio Activo" 

Send-MailMessage -SmtpServer $SmtpServer -From $SmtpFrom -To $SmtpTo -Subject $SmtpSubject -Body (Get-Content $HtmlFile | Out-String) -BodyAsHtml
```
