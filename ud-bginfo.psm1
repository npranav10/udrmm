function New-UDProgressMetric {
    param($Total, $Value, $Metric, $Label, [Switch]$HighIsGood)

    $Percent = [Math]::Round(($Value / $Total) * 100)
    New-UDElement -Tag "h5" -Content { $Label }

    New-UDElement -Tag "div" -Attributes @{ className = "row" } -Content {
        New-UDElement -Tag "span" -Attributes @{ className = "grey-text lighten-1" } -Content { "$Percent% - $($Value.ToString('N')) of $($Total.ToString('N')) $Metric" }
    } 

    if ($HighIsGood) {
        if ($Percent -lt 20) {
            $Color = 'red'
        }
        elseif ($Percent -gt 25 -and $Percent -lt 75) {
            $Color = 'yellow'
        } else {
            $Color = 'green'
        }
    
    } else {
        if ($Percent -lt 50) {
            $Color = 'green'
        }
        elseif ($Percent -gt 50 -and $Percent -lt 75) {
            $Color = 'yellow'
        } else {
            $Color = 'red'
        }
    
    }


    New-UDElement -Tag "div" -Attributes @{ className = 'progress grey' } -Content {
        New-UDElement -Tag "div" -Attributes @{ className = "determinate $color"; style = @{ width = "$Percent%"} } 
    }    
}

function New-UDProgress {
    param($Percent, $Label)

    New-UDElement -Tag "h5" -Content { $Label }

    if ($Percent -lt 50) {
        $Color = 'green'
    }
    elseif ($Percent -gt 50 -and $Percent -lt 75) {
        $Color = 'yellow'
    } else {
        $Color = 'red'
    }

    New-UDElement -Tag "div" -Attributes @{ className = "row" } -Content {
        New-UDElement -Tag "span" -Attributes @{ className = "grey-text lighten-1" } -Content { "$Percent%" }
    } 

    New-UDElement -Tag "div" -Attributes @{ className = 'progress grey' } -Content {
        New-UDElement -Tag "div" -Attributes @{ className = "determinate $color"; style = @{ width = "$Percent%"} }
    }    
}

function ConvertTo-Fahrenheit {
    param($Value)

    (($value /10 -273.15) *1.8 +32)
}

$Cache:Softwares = if (!([Diagnostics.Process]::GetCurrentProcess().Path -match '\\syswow64\\'))
{
  $unistallPath = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
  $unistallWow6432Path = "\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"
  @(
  if (Test-Path "HKLM:$unistallWow6432Path" ) { Get-ChildItem "HKLM:$unistallWow6432Path"}
  if (Test-Path "HKLM:$unistallPath" ) { Get-ChildItem "HKLM:$unistallPath" }
  if (Test-Path "HKCU:$unistallWow6432Path") { Get-ChildItem "HKCU:$unistallWow6432Path"}
  if (Test-Path "HKCU:$unistallPath" ) { Get-ChildItem "HKCU:$unistallPath" }
  ) |
  ForEach-Object { Get-ItemProperty $_.PSPath } |
  Where-Object {
    $_.DisplayName -and !$_.SystemComponent -and !$_.ReleaseType -and !$_.ParentKeyName -and ($_.UninstallString -or $_.NoRemove)
  } |
  Sort-Object DisplayName |
  Select-Object DisplayName , InstallDate, EstimatedSize , DisplayVersion, UninstallString 
}

function New-ListSoftwareCard {



    #New-UDCard -Title "Software" -Content {

       New-UDTable -Title "Software" -Id "softwarelist" -Style striped -Header @("Name", "Installed On","Version", "Size") -BackgroundColor "#adc3ff" -Content {
    


    #foreach($s in $Softwares) 
    #{
    #    New-UDCheckbox -Label "$($s.DisplayName) $($s.InstallDate)" -OnChange 
    #    {
    #    Show-UDToast -Message $EventData
    #     }
      
    # }

    $Cache:Softwares | Out-UDTableData -Property @("DisplayName", "InstallDate","DisplayVersion", "EstimatedSize")

}
#}
}

$Cache:MyVariable = 1

function New-InstallSoftwareCard {

# Installing an exe with path obtained from text box
<# New-UDInput -Title "Install Software"  -SubmitText "Install" -Endpoint {
    param($ApplicationPath) 



    Show-UDToast -Message "Software Location : $($ModuleName)"
    #Start-Process "$($ModuleName)" -Wait
}#>

New-UDInput -Title "Install Software" -SubmitText "Install" -Content {
   New-UDInputField -Type binaryFile -Name file 
} -Endpoint {
   param($File)

   $fileStream = [IO.File]::Create($File.FileName) 
   Show-UDToast -Message "$($File.FileName)"
   $installstring = $File.FileName
   $stream = $File.OpenReadStream()
   $stream.CopyTo($fileStream)
   $fileStream.Dispose()
   $stream.Dispose()
   Invoke-Expression "cmd /c '$installstring'"  | Show-UDToast -Message "Installed $installstring Successfully via Powershell 1/2"
   

}}


function New-UninstallSoftwareCard {
New-UDCard -Title "Uninstall Software" -Id "acard" -Content {

    New-UDRow{
    New-UDColumn -Size 10 -Content {
    New-UDSelect -Label "Softwares"  -Option {
               foreach($s in $Cache:Softwares) 
               {
                    $a = $s.DisplayName
                    New-UDSelectOption -Name $a -Value $a
               }}-OnChange{
                    $Session:Character = $EventData
                    #Show-UDToast -Message "Changed to $($EventData)"
                    #$ModuleName = $EventData
                    $Cache:MyVariable = $EventData
                    Show-UDToast -Message "Selected $($EventData) for Uninstallation"

               }
               }
               New-UDColumn -Size 2 -Content {
    New-UDButton -Text "Uninstall" -OnClick (
        New-UDEndpoint -Endpoint {
        
            Show-UDToast -Message "About to uninstall $($Cache:MyVariable)"

                Try{
        $url =   if (!([Diagnostics.Process]::GetCurrentProcess().Path -match '\\syswow64\\'))
                    {
                      $unistallPath = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
                      $unistallWow6432Path = "\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"
                      @(
                      if (Test-Path "HKLM:$unistallWow6432Path" ) { Get-ChildItem "HKLM:$unistallWow6432Path"}
                      if (Test-Path "HKLM:$unistallPath" ) { Get-ChildItem "HKLM:$unistallPath" }
                      if (Test-Path "HKCU:$unistallWow6432Path") { Get-ChildItem "HKCU:$unistallWow6432Path"}
                      if (Test-Path "HKCU:$unistallPath" ) { Get-ChildItem "HKCU:$unistallPath" }
                      ) |
                      ForEach-Object { Get-ItemProperty $_.PSPath } |
                      Where-Object {
                        $_.DisplayName -eq $Cache:MyVariable -and !$_.SystemComponent -and !$_.ReleaseType -and !$_.ParentKeyName -and ($_.UninstallString -or $_.NoRemove)
                      } |
                      Sort-Object DisplayName |
                      Select-Object UninstallString 
                    }

    $UninstallString = $url.UninstallString
    $UninstallString = $UninstallString -replace '--uninstall' ,''
    Try{
    Invoke-Expression "cmd /c '$UninstallString'"  | Show-UDToast -Message "Uninstalled $Name Successfully via Powershell 1/2"
    }catch{
    Invoke-Expression "cmd /c '$UninstallString' --uninstall"  | Show-UDToast -Message "Uninstalled $Name Successfully via Powershell 2/2"
    }
    }
    Catch {
    Try{
        $ModuleName = $Cache:MyVariable
    Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object {$ModuleName -contains $_.DisplayName} | % {  $UninstallString = $_.UninstallString -replace '-runfromtemp -l0x0009anything -removeonly','-s -runfromtemp -l0x0409 anything -removeonly' -split ' ',2 # adds the -s to make the
 Invoke-Expression "cmd /c '$UninstallString'" 
 } 
  Show-UDToast -Message "Uninstalled $Name Successfully via CMD"

    }Catch
    {
    Show-UDToast -Message "Cannot Uninstall $Name via CMD"
    }

    }
    Finally {
    
    $Cache:Softwares = if (!([Diagnostics.Process]::GetCurrentProcess().Path -match '\\syswow64\\'))
        {
  $unistallPath = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
  $unistallWow6432Path = "\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"
  @(
  if (Test-Path "HKLM:$unistallWow6432Path" ) { Get-ChildItem "HKLM:$unistallWow6432Path"}
  if (Test-Path "HKLM:$unistallPath" ) { Get-ChildItem "HKLM:$unistallPath" }
  if (Test-Path "HKCU:$unistallWow6432Path") { Get-ChildItem "HKCU:$unistallWow6432Path"}
  if (Test-Path "HKCU:$unistallPath" ) { Get-ChildItem "HKCU:$unistallPath" }
  ) |
  ForEach-Object { Get-ItemProperty $_.PSPath } |
  Where-Object {
    $_.DisplayName -and !$_.SystemComponent -and !$_.ReleaseType -and !$_.ParentKeyName -and ($_.UninstallString -or $_.NoRemove)
  } |
  Sort-Object DisplayName |
  Select-Object DisplayName , InstallDate, EstimatedSize , DisplayVersion, UninstallString 
}
        }
    
    
                        })
               }


          }
 }
 }

function New-CheckCard{

    New-UDCard -Title "Software" -Content {
    New-UDLayout -Columns 1 -Content {New-UDTable -Title "Process Ids" -Header @("Select") -Content {
    foreach($s in $Cache:Softwares) {
    New-UDCheckbox -Label $s.DisplayName -OnChange {
    Show-UDToast -Message $EventData
}
    }}}
}
}

function New-OverviewCard {
    $OS = Get-WMIObject -Class Win32_OperatingSystem
    
    
    New-UDCard -Title "$Env:ComputerName Overview" -Content {
        New-UDLayout -Columns 1 -Content {
            New-UDElement -Tag "div" -Content {
                "  Boot Time: $($OS.ConvertToDateTime($OS.LastBootupTime))"
            }
            New-UDElement -Tag "div" -Content {
                "  OS: $($OS.Caption)"
            }
            New-UDElement -Tag "div" -Content {
                "  Logon Server: $Env:LOGONSERVER"
            }
            New-UDElement -Tag "div" -Content {
                "  User Domain: $Env:USERDOMAIN"
            }
            New-UDElement -Tag "div" -Content {
                "  Username: $Env:USERNAME"
            }
        }
    }
}

function New-NetworkCard {
    $EnabledAdapters = (Get-wmiObject Win32_networkAdapterConfiguration | ?{$_.IPEnabled})
    $DefaultGateway = $EnabledAdapters.DefaultIPGateway | Where-Object { -not [String]::IsNullOrEmpty($_)}
    $DHCPServer = $EnabledAdapters.DHCPServer | Where-Object { -not [String]::IsNullOrEmpty($_)}
    $IPAddress = $EnabledAdapters.IPAddress | Where-Object { -not [String]::IsNullOrEmpty($_)}
    $DNSServer = $EnabledAdapters.DNSServerSearchOrder | Where-Object { -not [String]::IsNullOrEmpty($_)}

    New-UDCard -Title "Network" -Content {
        New-UDLayout -Columns 1 -Content {
            New-UDElement -Tag "div" -Content {
                $IPAddress = [String]::Join(', ', $IPAddress)
                "  IP Address: $IPAddress "
            }
            New-UDElement -Tag "div" -Content {
                $DefaultGateway = [String]::Join(', ', $DefaultGateway)
                "  Default Gateway: $DefaultGateway"
            }
            New-UDElement -Tag "div" -Content {
                "  DHCP Server: $DHCPServer"
            }
            New-UDElement -Tag "div" -Content {
                $DNSServer = [String]::Join(', ', $DNSServer)
                "  DNS Server: $DNSServer"
            }
        }
    }
}

function New-StorageCard {
    $Disks = Get-WMIObject -Class Win32_LogicalDisk | Where {$_.DriveType -ne "5"}

    New-UDCard -Title 'Storage' -Content {
        foreach($disk in $disks) {
            New-UDElement -Tag "row" -Content {
                New-UDProgressMetric -Value ($Disk.FreeSpace /1GB) -Total ($Disk.Size / 1GB) -Metric "GBs" -Label "$($Disk.DeviceID) - Free Space" -HighIsGood
            }
        }
    }
}

function New-Resource {
    $OperatingSystem = Get-WMIObject -Class Win32_OperatingSystem
    $CPU = Get-WMIObject -Class Win32_Processor
    

    New-UDCard -Title "Host" -Content {
        New-UDElement -tag "h4" -Content {
            "System Information"
        }
        New-UDElement -tag "div" -Attributes @{ className = "row"} -Content {
            New-UDElement -Tag "i" -Attributes @{ className = "fa fa-windows"}
            "    "
            $OperatingSystem.Caption 
        }
        New-UDElement -Tag "div" -Attributes @{ className = "row"} -Content {
            New-UDProgressMetric -Value ($OperatingSystem.FreePhysicalMemory /1MB) -Total ($OperatingSystem.TotalVisibleMemorySize / 1MB) -Metric "GBs" -Label "Memory"
        }
        New-UDElement -Tag "div" -Attributes @{ className = "row"} -Content {
            New-UDProgress -Percent $CPU.LoadPercentage -Label "CPU Usage"
        }

        
    }
}