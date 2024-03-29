(Get-Content -Path "accu.har" -Raw) | `
  Select-String -Pattern 'https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)' -AllMatches | % `
  { $_.Matches } | % { $_.Value } | `
  ForEach-Object { $_ -replace '^.*https://', '' } | `
  ForEach-Object { $_ -replace '\/.*', ''} | `
  group -NoElement | `
  sort Count -Desc | `
  Format-Table -autosize
