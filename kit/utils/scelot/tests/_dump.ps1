$b = [IO.File]::ReadAllBytes($args[0])
$n = [Math]::Min(96, $b.Length)
($b[0..($n-1)] | ForEach-Object { '{0:x2}' -f $_ }) -join ' '
