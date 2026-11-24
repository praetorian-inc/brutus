# ntlmssp (Brutus patch)

Vendored from github.com/bodgit/ntlmssp (MIT) so WinRM can pass-the-hash.

The only Brutus change is in `ntowfV1`: if the password is prefixed with
`"\x00NTLMHASH\x00"` and the remainder is 16 bytes, those bytes are used as the
NT hash instead of MD4(UTF-16LE(password)).

`internal/plugins/winrm` is the only caller of that encoding.
