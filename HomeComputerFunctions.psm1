###################################  Host Computer Cache Variables Section #############################################

$Cache:Softwares = if (!([Diagnostics.Process]::GetCurrentProcess().Path -match '\\syswow64\\')) {
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

$Cache:MyVariable = 1

###################################   Host Computer Functions Section #####################################

function GetHostEndpointIP {
    $t = Get-NetIPAddress | Where-Object {$_.InterfaceAlias -eq "Wi-Fi" -and $_.AddressFamily -eq "IPv4"} | Select-Object IPAddress
    return $t.IPAddress
}


function New-ListSoftwareCard {
       New-UDTable -Title "Software" -Id "softwarelist" -Style striped -Header @("Name", "Installed On","Version", "Size") -BackgroundColor "#adc3ff" -Content {
    $Cache:Softwares | Out-UDTableData -Property @("DisplayName", "InstallDate","DisplayVersion", "EstimatedSize")
    }
}

function New-InstallSoftwareCard {

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
   
    }
}

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
     Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object {$ModuleName -contains $_.DisplayName} | ForEach-Object {  $UninstallString = $_.UninstallString -replace '-runfromtemp -l0x0009anything -removeonly','-s -runfromtemp -l0x0409 anything -removeonly' -split ' ',2 # adds the -s to make the
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

    New-UDLayout -Columns 1 -Content {
        New-UDTable -Title "Process Ids" -Header @("Select") -Content {
            foreach($s in $Cache:Softwares) {
                New-UDCheckbox -Label "$($s.DisplayName)" -OnChange {
                    Show-UDToast -Message "$($s.DisplayName)"
                }
            }
        }
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
    $EnabledAdapters = (Get-wmiObject Win32_networkAdapterConfiguration | Where-Object {$_.IPEnabled})
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
            Show-UDToast -Message "$($env:computername) $($IPAddress[0])"
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
    $Disks = Get-WMIObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -ne "5"}
    New-UDCard -Title 'Storage' -Content {
        foreach($disk in $disks) {
            New-UDElement -Tag "row" -Content {
                New-UDProgressMetric -Value ($Disk.Size / 1GB - $Disk.FreeSpace /1GB) -Total ($Disk.Size / 1GB) -Metric "GBs" -Label "$($Disk.DeviceID) - Space Used" 
            }
        }
    }
}

function New-Resource {
    $OperatingSystem = Get-WMIObject -Class Win32_OperatingSystem
    $CPU = Get-WMIObject -Class Win32_Processor
    

    New-UDCard -Title "Host" -Content {
        # New-UDElement -tag "div" -Attributes @{ className = "row"} -Content {
        #     New-UDElement -Tag "i" -Attributes @{ className = "fa fa-windows"}
        #     "    "
        #     $OperatingSystem.Caption 
        # }
        New-UDElement -Tag "row" -Content {
            New-UDProgressMetric -Value ($OperatingSystem.TotalVisibleMemorySize/1MB -$OperatingSystem.FreePhysicalMemory /1MB) -Total ($OperatingSystem.TotalVisibleMemorySize / 1MB) -Metric "GBs" -Label "Memory"
        }
        New-UDElement -Tag "row" -Content {
            New-UDProgress -Percent $CPU.LoadPercentage -Label "CPU Usage"
        }
        
    }
}
function CPU_Monitor{
    New-UdMonitor -Title "CPU (% processor time)" -Type Line -DataPointHistory 20 -RefreshInterval 5 -ChartBackgroundColor '#80FF6B63' -ChartBorderColor '#FFFF6B63'  -Endpoint {
        Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue | Out-UDMonitorData
   }
}
function Memory_Monitor{
    New-UdMonitor -Title "Memory Usage %" -Type Line -DataPointHistory 20 -RefreshInterval 5 -ChartBackgroundColor '#9591eb' -ChartBorderColor '#3459eb'  -Endpoint {
        Get-Counter '\memory\% committed bytes in use' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue | Out-UDMonitorData
   }
}
function Disk_Monitor{
    New-UdMonitor -Title "Disk Usage (Metric TBA)" -Type Line -DataPointHistory 20 -RefreshInterval 5 -ChartBackgroundColor '#9aeb91' -ChartBorderColor '#46eb34'  -Endpoint {
        Get-Counter '\physicaldisk(_total)\% disk time' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue | Out-UDMonitorData
   }
}

function Network_Monitor{
    New-UdMonitor -Title "Network Usage (Up + Down) (Metric TBA)" -Type Line -DataPointHistory 20 -RefreshInterval 5 -ChartBackgroundColor '#fad678' -ChartBorderColor '#e3b029'  -Endpoint {
    Get-Counter "\Network Adapter(*)\Bytes Total/sec" | Select-Object -ExpandProperty CounterSamples | Where-Object {$_.CookedValue -ne 0} | Select-Object -ExpandProperty CookedValue | Out-UDMonitorData
    }
}
function Get_Processes{
    New-UdGrid -Title "Processes" -Headers @("Name", "ID", "Working Set", "CPU") -Properties @("Name", "Id", "WorkingSet", "CPU") -AutoRefresh -RefreshInterval 60 -Endpoint {
        Get-Process | Select-Object Name,ID,WorkingSet,CPU | Out-UDGridData
 }
}

function RetrieveNetwork {
    $endpoints = Import-csv "./endpoints.csv"
    $network = @() 
    foreach ($endpoint in $endpoints)
    {
        $status = @{ "IP" = $endpoint.IP}
        $status.Password=$endpoint.Password
        if (Test-Connection $endpoint.IP -Count 1 -ea 0 -Quiet)
        {
            $status["Results"] = "Up"
        }else
        {
            $status["Results"] = "Down"
        }
        $serverStatus = New-Object -TypeName PSObject -Property $status
        $network += $serverStatus
    }
    $Cache:network =  $network
}

function DisplayNetworkEndpoints {
    foreach ($endpoint in $Cache:network) 
    {
        New-UDColumn -Size 3 -Content {
            if ($endpoint.Results -eq "Up")
            {
                $text = $null
                $BackgroundColor = $null
                $hostIP = GetHostEndpointIP
                if ($endpoint.IP -eq $hostIP){
                    $text = "Host Computer"
                    $BackgroundColor = "#6eff9b"
                }
                else{
                    $text = "Remote Computer"
                    $BackgroundColor = "#a6ffc2"
                }
                New-UDCard -Title "$($endpoint.IP)" -Text $text -BackgroundColor $BackgroundColor -Links @(
                    New-UDLink -OpenInNewWindow True -Url ("http://localhost:7777/"+"$($endpoint.IP)").toString() -Text "Go to the Endpoint's Homepage"
                    )            
            }else
            {
                New-UDCard -Title "$($endpoint.IP)"  -BackgroundColor "#ffa6a6"  -Content {
                        New-UDButton -Text "Wake-on-LAN" -OnClick (
                            New-UDEndpoint -Endpoint {Wake_on_LAN } )}
            }
        }
    }  
    
}



###################################   Common Functions Section #####################################

function New-UDProgressMetric {
    param( $Value,$Total, $Metric, $Label, [Switch]$HighIsGood)

    $Percent = [Math]::Round(($Value / $Total) * 100)
    New-UDElement -Tag "h5" -Content { $Label }

    New-UDElement -Tag "div" -Attributes @{ className = "row" ;style = @{
        height = "20px"    }} -Content {
        New-UDElement -Tag "span" -Attributes @{ className = "grey-text lighten-1"} -Content { "$Percent% - $($Value.ToString('N')) of $($Total.ToString('N')) $Metric" }
    } 

    if ($HighIsGood) {
        if ($Percent -lt 20) {
            $Color = 'red'
        }
        elseif ($Percent -gt 20 -and $Percent -lt 80) {
            $Color = 'yellow'
        } else {
            $Color = 'green'
        }
    
    } else {
        if ($Percent -gt 80) {
            $Color = 'red'
        }
        elseif ($Percent -gt 50 -and $Percent -lt 80) {
            $Color = 'yellow'
        } else {
            $Color = 'green'
        }
    
    }


    New-UDElement -Tag "div" -Attributes @{ className = 'progress grey' ;style = @{
        height = "20px"    }} -Content {
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

    New-UDElement -Tag "div" -Attributes @{ className = "row" ;style = @{
        height = "20px"    }} -Content {
        New-UDElement -Tag "span" -Attributes @{ className = "grey-text lighten-1" } -Content { "$Percent%" }
    } 

    New-UDElement -Tag "div" -Attributes @{ className = 'progress grey'  ;style = @{
        height = "20px"    }} -Content {
        New-UDElement -Tag "div" -Attributes @{ className = "determinate $color"; style = @{ width = "$Percent%"}  }
    }    
}

function ConvertTo-Fahrenheit {
    param($Value)

    (($value /10 -273.15) *1.8 +32)
}

