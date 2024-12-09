function Get-SystemStatus {
    [CmdletBinding()]
    param()

    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    # Get system uptime
    $uptime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $uptimeSpan = (Get-Date) - $uptime
    $uptimeString = "{0}d {1}h {2}m" -f $uptimeSpan.Days, $uptimeSpan.Hours, $uptimeSpan.Minutes
    
    # Check for pending restart
    $pendingRestart = $false
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\Auto Update\RebootRequired"
    )
    
    foreach ($path in $paths) {
        if (Test-Path $path) {
            $pendingRestart = $true
            break
        }
    }

    # Get the most frequently used adapter's IPv4 address
    $ipv4Address = (Get-NetIPAddress -AddressFamily IPv4 | Sort-Object -Property InterfaceIndex | Select-Object -First 1).IPAddress

    # Get Azure context
    $azureContext = (Get-AzContext).Account.Name

    # Get GitHub CLI context
    $ghContext = (gh auth status 2>&1 | Select-String "Logged in to github.com as").Line

    # Create output object
    $result = [PSCustomObject]@{
        "Admin Status" = if ($isAdmin) { "Admin 👑" } else { "Standard 👤" }
        "Uptime"       = $uptimeString
        "Restart"      = if ($pendingRestart) { "Pending 🔄" } else { "None ✅" }
        "PC Name"      = $env:COMPUTERNAME
        "IPv4 Address" = $ipv4Address
        "Azure User"   = $azureContext
        "GitHub User"  = $ghContext
    }

    $result | Format-List
}

# Always execute when script is run
Get-SystemStatus
