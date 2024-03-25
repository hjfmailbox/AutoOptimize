# Set the default encoding to UTF8
[Console]::InputEncoding = [Text.Encoding]::UTF8
[Console]::OutputEncoding = [Text.Encoding]::UTF8

# Set the warning preference to SilentlyContinue
$WarningPreference = "SilentlyContinue"

# Change DNS or not
$IsChangeDNS = $true

# Network name
$NetworkName = "Ethernet0"

$ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "script.ps1"

$LogsDirectory = Join-Path -Path $PSScriptRoot -ChildPath "logs"
$InstallPath = Join-Path -Path $PSScriptRoot -ChildPath "tools"
$InstallersDirectory = Join-Path -Path $PSScriptRoot -ChildPath "installers"

$PowershellCoreInstallerPath = "C:\Users\hjf\AppData\Local\Temp\chocolatey\powershell-core\7.4.1\"
$WingetInstallerPath = "C:\ProgramData\chocolatey\lib\winget-cli\tools\"
$DockerInstallerPath = "C:\Users\Administrator\AppData\Local\Temp\chocolatey\docker-desktop\4.28.0\"

#$ActivateWindows = $false
$ActivateWindows = $true

$WindowsFeatures = @(
    "IIS-WebServerRole",
    "TelnetClient",
    "Microsoft-Hyper-V",
    "Microsoft-Windows-Subsystem-Linux",
    "VirtualMachinePlatform"
)

$TaskName = "ContinueScriptAfterReboot"

$AutoLogonRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

$OldUserName = "hjf"
$NewComputerName = "hjf-pc"

# Define the programs to unpin from the taskbar
$ProgramsToUnpin = @(
    'Microsoft Edge',
    'Microsoft Store'
)

# Define the programs to pin to the taskbar and their default installation paths
$ProgramsToPin = @{
    'Windows Terminal' = Join-Path -Path $env:ProgramFiles -ChildPath 'Windows Terminal\wt.exe'
    'IIS Manager'      = Join-Path -Path $env:SystemRoot -ChildPath 'System32\inetsrv\inetmgr.exe'
    'Google Chrome'    = Join-Path -Path $env:ProgramFiles -ChildPath 'Google\Chrome\Application\chrome.exe'
}

# Define the array of apps to be installed using winget, by their IDs
class WingetTool {
    [Parameter(Mandatory = $true)]
    [string] $AppId

    [Parameter(Mandatory = $true)]
    [string] $AppName

    [Parameter(Mandatory = $true)]
    [bool] $Install
}

$UseLocalInstaller = $false

$Installers = [WingetTool[]]@(
    [WingetTool] @{
        AppId   = "7zip.7zip"
        AppName = "7zip"
        Install = $true
    },
    [WingetTool] @{
        AppId   = "Notepad++.Notepad++"
        AppName = "Notepad++"
        Install = $true
    },
    [WingetTool] @{
        AppId   = "Google.Chrome"
        AppName = "Chrome"
        Install = $true
    },
    [WingetTool] @{
        AppId   = "Git.Git"
        AppName = "Git"
        Install = $true
    },
    [WingetTool] @{
        AppId   = "TortoiseGit.TortoiseGit"
        AppName = "TortoiseGit"
        Install = $true
    },
    [WingetTool] @{
        AppId   = "Microsoft.VisualStudioCode"
        AppName = "Microsoft VS Code"
        Install = $true
    },
    [WingetTool] @{
        AppId   = "Microsoft.VisualStudio.2022.Enterprise"
        AppName = "Microsoft Visual Studio"
        Install = $false
    }
)

function InitializeComputer {
    Test-Path -Path $LogsDirectory -PathType Container -ErrorAction SilentlyContinue | Out-Null
    if (-not (Test-Path $LogsDirectory)) {
        New-Item -Path $LogsDirectory -ItemType Directory | Out-Null
    }
    Test-Path -Path $InstallersDirectory -PathType Container -ErrorAction SilentlyContinue | Out-Null
    if (-not (Test-Path $InstallersDirectory)) {
        New-Item -Path $InstallersDirectory -ItemType Directory | Out-Null
    }
    Test-Path -Path $InstallPath -PathType Container -ErrorAction SilentlyContinue | Out-Null
    if (-not (Test-Path $InstallPath)) {
        New-Item -Path $InstallPath -ItemType Directory | Out-Null
    }

    if ($IsChangeDNS) {
        Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter -Name $NetworkName).ifIndex -ServerAddresses 114.114.114.114
    }

    # Set the monitor timeout to 0
    powercfg -change monitor-timeout-ac 0
    # Set the disk timeout to 0
    powercfg -change disk-timeout-ac 0
    # Set the standby timeout to 30
    powercfg -change hibernate-timeout-ac 30

    if ($ActivateWindows) {
        # Activate Windows system
        & ([ScriptBlock]::Create((Invoke-RestMethod https://massgrave.dev/get))) /HWID
    }

    # Rename the computer name
    Rename-Computer -NewName $NewComputerName -Force -ErrorAction Stop | Out-Null

    # Enable the Administrator account
    Enable-LocalUser -Name "Administrator" | Out-Null

    # Disable current user UAC prompt
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'EnableLUA' -Value 0 -Type DWord

    # Set automatic logon for the Administrator account
    Set-ItemProperty -Path $AutoLogonRegistryPath -Name 'AutoAdminLogon' -Value 1 -Type DWORD
    Set-ItemProperty -Path $AutoLogonRegistryPath -Name 'DefaultUsername' -Value "Administrator" -Type String

    # Disable the Smart Glass User Policy Handlers to skip the first-use experience
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" -Name "UserPolicyHandlers" -Value 0

    # Create the registry key if it doesn't exist
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Force | Out-Null
    # Set the policy to disable the privacy experience on OOBE (Out-of-Box Experience)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -Value 1
    # Set the policy to disable the "Agree to cross-border data transfer" prompt
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Name "DisableOobeDatasourceWindows" -Value 1

    # Disable OneDrive startup
    #Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -Value ""
    Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' | Where-Object { $_.Name -like '*OneDrive*' } | Remove-Item

    # Enable the features that require a restart
    Enable-WindowsOptionalFeature -Online -FeatureName $WindowsFeatures -All -NoRestart
    # Disable the Windows Media Player
    Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart

    # Install Chocolatey
    Invoke-WebRequest https://community.chocolatey.org/install.ps1 -UseBasicParsing | Invoke-Expression
    # Enable Chocolatey global confirmation
    choco feature enable -n allowGlobalConfirmation
    # Set the number of retry attempts for installing packages
    choco config set feature.dotnetexe.retryattempts 10
    # Set the wait time between retry attempts for installing packages
    choco config set feature.dotnetexe.retrywait 10000
    # Import RefreshEnv cmd
    Import-Module $env:ChocolateyInstall\helpers\chocolateyProfile.psm1

    # Copy installers to temp
    if($UseLocalInstaller){
        if (Test-Path -Path "$PSScriptRoot\installers\PowerShell-7.4.1-win-x64.msi" -ErrorAction SilentlyContinue) {
            New-Item -ItemType Directory -Path $PowershellCoreInstallerPath -Force | Out-Null
            Copy-Item -Path "$PSScriptRoot\installers\PowerShell-7.4.1-win-x64.msi" -Destination $PowershellCoreInstallerPath -Force | Out-Null
        }
        if (Test-Path -Path "$PSScriptRoot\installers\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -ErrorAction SilentlyContinue) {
            New-Item -ItemType Directory -Path $WingetInstallerPath -Force | Out-Null
            Copy-Item -Path "$PSScriptRoot\installers\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -Destination $WingetInstallerPath -Force | Out-Null
        }
    }

    # Install powershell-core winget
    if($UseLocalInstaller){
        choco install powershell-core 7.4.1 winget v1.7.10661 -y --force --execution-timeout 0
    }
    else {
        choco install powershell-core winget -y --force --execution-timeout 0
    }
}

function CreateScheduledTaskAndRestart {
    param(
        [string]$Method
    )

    # Create a scheduled task to continue the script after a reboot
    $TaskDesc = "Continues the script after the computer restarts."
    $TaskTrigger = New-ScheduledTaskTrigger -AtLogOn
    $TaskAction = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-ExecutionPolicy Bypass -NoExit -File `"$ScriptPath`" `"$Method`" -restart"
    $TaskSettings = New-ScheduledTaskSettingsSet
    Register-ScheduledTask -TaskName $TaskName -Description $TaskDesc -Trigger $TaskTrigger -Settings $TaskSettings -Action $TaskAction -User 'Administrator' -RunLevel 'Highest' -Force  | Out-Null

    # Add a pause statement for debugging
    Write-Host "Press any key to continue debugging..."
    $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    # Restart the computer and continue the script
    Restart-Computer -Force
}

function DeleteScheduledTask {
    # Unregister the scheduled task after restarting the computer
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

function ConfigureWindowsSettings {
    # Delete the standard user account `hjf` and its directory
    Remove-LocalUser -Name $OldUserName
    $UserHome = "C:\Users\$OldUserName"
    Remove-Item -Path $UserHome -Recurse -Force

    # Disable current user UAC prompt
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'EnableLUA' -Value 0 -Type DWord

    # Copy the background image to the default wallpaper location
    $DestinationPath = "C:\Windows\Web\Wallpaper\Windows\background.jpg"
    Copy-Item -Path "$PSScriptRoot\images\background.jpg" -Destination $DestinationPath -Force
    # Set the desktop background image
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name 'Wallpaper' -Value $DestinationPath -Force

    # Show desktop computer icons
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value 0 -Type DWORD

    # Set File Explorer to open This PC by default
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name 'LaunchTo' -Value 1 -Type DWORD -Force

    # Enable showing seconds in the system clock
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name 'ShowSecondsInSystemClock' -Value 1 -Force

    # Not hidden taskbar
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name 'EnableAutoTray' -Value 0 -Type DWORD -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value 0 -Type DWord

    # Show all system tray icons
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideIcons" -Value 0 -Type DWORD -Force

    # Set the taskbar's icon grouping level to "Never combine"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Value 2 -Type DWORD -Force

    # Show hidden files
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name 'Hidden' -Value 1 -Type DWORD -Force

    # Show file extensions
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name 'HideFileExt' -Value 0 -Type DWORD -Force

    # Set the taskbar to the left
    Set-Itemproperty -Path "HKCU:\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED" -Name 'TaskbarAl' -Value 0 -Type DWORD -Force

    # Remove the Task View button from the taskbar
    Set-ItemProperty -Path "HKCU:\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED" -Name 'ShowTaskViewButton' -Value 0 -Type DWORD -Force

    # Remove the Widgets button from the taskbar
    Set-ItemProperty -Path "HKCU:\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED" -Name 'TaskbarDa' -Value 0 -Type DWORD -Force

    # Remove the Copilot button from the taskbar
    Set-ItemProperty -Path "HKCU:\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED" -Name 'ShowCopilotButton' -Value 0 -Type DWORD -Force

    # Change the region to United States and the language to English
    Set-WinHomeLocation -GeoId 0xF4
    Install-Language -Language en-US
    Set-WinUserLanguageList -LanguageList en-US -Force | Out-Null
    Set-SystemPreferredUILanguage -Language en-US
    Set-Culture -CultureInfo en-US
    Set-WinUILanguageOverride -Language en-US

    # Change date and time format to yyyy/MM/dd HH:mm:ss
    Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sShortDate -Value "yyyy/MM/dd"
    Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sShortTime -Value "HH:mm:ss"
    Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sTimeFormat -Value "HH:mm:ss"

    Stop-Process -Name explorer -Force
    Start-Process explorer.exe

    # Update WSL2
    wsl --update
    # Set WSL's default version to 2
    wsl --set-default-version 2
    # Install WSL2
    wsl --install -d Ubuntu-22.04

    # Copy installers to temp
    if($UseLocalInstaller){
        if (Test-Path -Path "$PSScriptRoot\installers\Docker Desktop Installer.exe" -ErrorAction SilentlyContinue) {
            New-Item -ItemType Directory -Path $DockerInstallerPath -Force | Out-Null
            Copy-Item -Path "$PSScriptRoot\installers\Docker Desktop Installer.exe" -Destination $DockerInstallerPath -Force | Out-Null
        }
    }

    if($UseLocalInstaller){
        # Install docker-desktop
        choco install docker-desktop 4.28.0 -y --force --execution-timeout 0
    }
    else {
        choco install docker-desktop -y --force --execution-timeout 0
    }
}

function InstallTools {
    ForEach-Object -InputObject $Installers {
        if ($($_.Install)) {
            $InstallPath = "$InstallPath\$($_.AppName)"
            $LogFilePath = "$LogsDirectory\$($_.AppName).log"
            Write-Host $InstallPath
            Write-Host $LogFilePath
            winget install $($_.AppId) --location $InstallPath --log $LogFilePath --silent --accept-source-agreements --accept-package-agreements
        }
    }

    # Refresh environment variables through chocolatey
    RefreshEnv
}

function PinAndUnpinIcons {
    # Get the list of pinned programs on the taskbar
    $RegPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband'
    $PinnedItems = Get-ItemProperty -Path $RegPath -Name 'Favorites' -ErrorAction SilentlyContinue

    if ($null -ne $PinnedItems) {
        $NewValue = $PinnedItems.Favorites | Where-Object { $_ -notin $PinnedItems.Favorites.Split(',') -and $_ -notin $ProgramsToUnpin }
        $NewValue += $ProgramsToPin.Values | ForEach-Object { $_.Replace(($_.Split('\')[-1]).Split('.')[0], '') }
        Set-ItemProperty -Path $RegPath -Name 'Favorites' -Value ($NewValue -join ',')
    }

    # Restart the explorer process to apply the changes
    Stop-Process -Name explorer -Force  
}


# Script entry point
function main {
    param(
        [string]$Method = "InitializeComputer"
    )

    switch ($Method) {
        "InitializeComputer" { 
            InitializeComputer
            CreateScheduledTaskAndRestart -Method "ConfigureWindowsSettings"
            break
        }
        "ConfigureWindowsSettings" { 
            DeleteScheduledTask
            ConfigureWindowsSettings
            CreateScheduledTaskAndRestart -Method "InstallTools"
            break
        }
        "InstallTools" { 
            DeleteScheduledTask
            InstallTools
            PinAndUnpinIcons
            break
        }
    }

    # Add a pause statement for debugging
    Write-Host "Press any key to continue debugging..."
    $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
main $args[0]
