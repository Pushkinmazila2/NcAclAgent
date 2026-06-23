# 1. Разрешаем TLS 1.2 и отключаем проверку серверного сертификата
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# 2. Загружаем клиентский сертификат из PFX-файла
$pfxPath = "C:\ProgramData\NcAclAgent\certs\nextcloud-client.pfx"
$pfxPassword = ""
$clientCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfxPath, $pfxPassword)
$token_bearer = ""

# 3. Делаем запрос, прикрепив сертификат
$request = [System.Net.HttpWebRequest]::Create("https://127.0.0.1:8443/api/acl/health")
$request.ClientCertificates.Add($clientCert) | Out-Null
$request.Headers.Add("Authorization", "Bearer $token_bearer")

# 4. Читаем ответ
$response = $request.GetResponse()
$reader = New-Object System.IO.StreamReader($response.GetResponseStream())
$responseText = $reader.ReadToEnd()

# Выводим результат
$responseText
