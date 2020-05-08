
###################################   Remote Computer Functions Section #####################################

function Wake_on_LAN {
    <# 
    .SYNOPSIS  
        Send a WOL packet to a broadcast address
    .PARAMETER mac
    The MAC address of the device that need to wake up
    .PARAMETER ip
    The IP address where the WOL packet will be sent to
    .EXAMPLE 
    Wake-on-LAN -mac 00:11:32:21:2D:11 -ip 192.168.8.255 
    #>
    Show-UDToast -Message "Dummy Message: Waking.."

    # [CmdletBinding()]
    # param(
    # [Parameter(Mandatory=$True,Position=1)]
    # [string]$mac,
    # [string]$ip="255.255.255.255", 
    # [int]$port=9
    # )
    # $broadcast = [Net.IPAddress]::Parse($ip)
    
    # $mac=(($mac.replace(":","")).replace("-","")).replace(".","")
    # $target=0,2,4,6,8,10 | % {[convert]::ToByte($mac.substring($_,2),16)}
    # $packet = (,[byte]255 * 6) + ($target * 16)
    
    # $UDPclient = new-Object System.Net.Sockets.UdpClient
    # $UDPclient.Connect($broadcast,$port)
    # [void]$UDPclient.Send($packet, 102) 

}

function RemoteDesktop {
    Show-UDToast -Message "Initiating Remote Desktop Connection tp $($Cache:RemoteCompIP)"
    mstsc /v:"$($Cache:RemoteCompIP)"
}

function RemoteLock {
    Show-UDToast -Message "Dummy Function"
    # Invoke-Command -ScriptBlock {Invoke-Expression 'cmd /c "C:\Windows\System32\rundll32.exe user32.dll,LockWorkStationname"'} -computername "172.16.75.206" -Credential $Cred
}

function RemoteRestart {
    Show-UDToast -Message "Dummy Function"
    # Invoke-Command -Session $Session -ScriptBlock {Restart-Computer -Force}
}

function RemoteShutdown {
    Show-UDToast -Message "Dummy Function"
    # Invoke-Command -Session $Session -ScriptBlock {Stop-Computer -Force}
}

function ListSoftwareCard_Away {
    New-UDTable -Title "Software" -Id "softwarelist" -Style striped -Header @("Name", "Installed On","Version", "Size") -BackgroundColor "#adc3ff" -Content {

        $Cache:SoftwaresAway | Out-UDTableData -Property @("DisplayName", "InstallDate","DisplayVersion", "EstimatedSize")}
}

function InstallSoftwareCard_Away {
    #$Session1 = New-PSSession -ComputerName $Cache:RemoteCompIP -Credential $Cache:Cred
    
    #$computername = Invoke-Command -ScriptBlock {hostname} -Session $Session1
    Show-UDToast -Message "$($Cache:RemoteCompIP)"
    New-UDInput -Title "Install Software" -SubmitText "Install" -Content {
        New-UDInputField -Type binaryFile -Name file 
        } -Endpoint {
            param($File)
            $fileStream = [IO.File]::Create($File.FileName) 
            Show-UDToast -Message "$($File.FileName)"
            $stream = $File.OpenReadStream()
            $stream.CopyTo($fileStream)
            $fileStream.Dispose()
            $stream.Dispose()
            $installstring = $File.FileName

            Show-UDToast -Message "Copying file to Remote Computer"
            Copy-Item -Path $installstring -ToSession $Cache:Session -Destination 'C:\'
            Show-UDToast -Message "Preparing to Install"
            $t = "C:\"+"$($installstring)"
            Invoke-Command  -ScriptBlock {
                param($installstring)
                $t = "C:\"+"$($installstring)"
                Invoke-Expression "cmd /c '$($t)' /silent"
                #Start-Process "$($t)"  -ArgumentList '/silent'
                    } -ArgumentList $installstring.Split("\")[-1]  -Session $Cache:Session
                    # add code to Remove $Session1 
            Show-UDToast -Message "Installation Completed Successfully."
        } 
    
}

function UninstallSoftwareCard_Away {
    $Session = New-PSSession -ComputerName $Cache:RemoteCompIP -Credential $Cache:Cred

    New-UDCard -Title "Uninstall Software" -Id "acard" -Content {

        New-UDRow{
            New-UDColumn -Size 10 -Content {
            New-UDSelect -Label "Softwares"  -Option {
                    foreach($s in $Cache:SoftwaresAway) 
                    {
                            $a = $s.DisplayName
                            New-UDSelectOption -Name $a -Value $a
                    }
                    }-OnChange{
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
                            Try
                            {
                                $url = $Cache:SoftwaresAway | where DisplayName -eq $Cache:MyVariable
                                $UninstallString = $url.UninstallString
                                    #$UninstallString = $UninstallString -replace '--uninstall' ,''
                                Invoke-Command -ScriptBlock {Invoke-Expression "cmd /c '$UninstallString'" } -ArgumentList $UninstallString -Session $Session 
                                Show-UDToast -Message "Uninstalled $Name Successfully via Powershell 1/2"
                            } Catch {
                                Try
                                {
                                    $ModuleName = $Cache:MyVariable
                                    Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object {$ModuleName -contains $_.DisplayName} | % {  $UninstallString = $_.UninstallString -replace '-runfromtemp -l0x0009anything -removeonly','-s -runfromtemp -l0x0409 anything -removeonly' -split ' ',2 }# adds the -s to make the
                                    Invoke-Command -ScriptBlock {Invoke-Expression "cmd /c '$UninstallString'" } -ArgumentList $UninstallString -Session $Session  
                                    Show-UDToast -Message "Uninstalled $Name Successfully via CMD"
                                }Catch {
                                    Show-UDToast -Message "Cannot Uninstall $Name via CMD"
                                }

                            } Finally {
                            
                                $Cache:SoftwaresAway = Invoke-Command -ScriptBlock {
                                    if (!([Diagnostics.Process]::GetCurrentProcess().Path -match '\\syswow64\\'))
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
                                } -Session $Session
                            }
                    }
                )
            }
        }
    }
}

function CheckCard_Away {
    New-UDCard -Title "Software" -Content {
        New-UDLayout -Columns 1 -Content {New-UDTable -Title "Process Ids" -Header @("Select") -Content 
            {
                foreach($s in $Cache:SoftwaresAway) 
                    {
                        New-UDCheckbox -Label $s.DisplayName -OnChange { Show-UDToast -Message $EventData } 
                    }
            }            
        }
    }
}

function OverviewCard_Away {

        # $RemOSLastBootupTime = Invoke-Command -ScriptBlock {Powershell "(Get-CimInstance -ClassName win32_operatingsystem | select lastbootuptime)"} -Session $Session
        # $RemOSCaption = Invoke-Command -ScriptBlock {Powershell "(Get-CimInstance -ClassName win32_operatingsystem | select caption)"} -Session $Session
        $RemComputerName = Invoke-Command -ScriptBlock {"$env:ComputerName"} -computername $Cache:RemoteCompIP -Credential $Cache:Cred
        $RemLOGONSERVER =  Invoke-Command -ScriptBlock {"$env:LOGONSERVER"} -computername $Cache:RemoteCompIP -Credential $Cache:Cred
        $RemUSERDOMAIN = Invoke-Command -ScriptBlock {"$env:USERDOMAIN"}-computername $Cache:RemoteCompIP -Credential $Cache:Cred
        $RemUSERNAME = Invoke-Command -ScriptBlock {"$env:USERNAME"} -computername $Cache:RemoteCompIP -Credential $Cache:Cred
        New-UDCard -Title "$RemComputerName Overview" -Content {
        New-UDLayout -Columns 1 -Content {
            # New-UDElement -Tag "div" -Content {
            #      "  Boot Time: $($RemOSLastBootupTime)"
            # } -ArgumentList 
            # New-UDElement -Tag "div" -Content {
            #     "  OS: $($RemOSCaption)"
            # }
            New-UDElement -Tag "div" -Content {
                "  Logon Server: $RemLOGONSERVER"
            }
            New-UDElement -Tag "div" -Content {
                "  User Domain: $RemUSERDOMAIN"
            }
            New-UDElement -Tag "div" -Content {
                "  Username: $RemUSERNAME"
            }
        }
    }
}

function NetworkCard_Away {
    $EnabledAdapters = Invoke-Command -computername $Cache:RemoteCompIP -Credential $Cache:Cred -ScriptBlock {(Get-wmiObject Win32_networkAdapterConfiguration | ?{$_.IPEnabled})}
    $DefaultGateway = $EnabledAdapters.DefaultIPGateway | Where-Object { -not [String]::IsNullOrEmpty($_)}
    $DHCPServer = $EnabledAdapters.DHCPServer | Where-Object { -not [String]::IsNullOrEmpty($_)}
    $IPAddress = $EnabledAdapters.IPAddress | Where-Object { -not [String]::IsNullOrEmpty($_)}
    $DNSServer = $EnabledAdapters.DNSServerSearchOrder | Where-Object { -not [String]::IsNullOrEmpty($_)}

    New-UDCard -Title "Network" -Content {
        New-UDLayout -Columns 1 -Content {
            New-UDElement -Tag "div" -Content {
                $IPAddress = [String]::Join(', ', $IPAddress)
                "  IP Address: $IPAddress "
            Show-UDToast -Message "$($computername) $($IPAddress.split(','))"

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

function StorageCard_Away {
    $Disks = Invoke-Command -computername $Cache:RemoteCompIP -Credential $Cache:Cred -ScriptBlock {(Get-WMIObject -Class Win32_LogicalDisk | Where {$_.DriveType -ne "5"})}

    New-UDCard -Title 'Storage' -Content {
        foreach($disk in $disks) {
            New-UDElement -Tag "row" -Content {
                New-UDProgressMetric -Value ($Disk.Size / 1GB - $Disk.FreeSpace /1GB) -Total ($Disk.Size / 1GB) -Metric "GBs" -Label "$($Disk.DeviceID) - Space Used" 
            }
        }
    }
}

function Resource_Away {
    $OperatingSystem = Invoke-Command -computername $Cache:RemoteCompIP -Credential $Cache:Cred -ScriptBlock {Get-WMIObject -Class Win32_OperatingSystem} 
    $CPU = Invoke-Command -computername $Cache:RemoteCompIP -Credential $Cache:Cred -ScriptBlock {Get-WMIObject -Class Win32_Processor} 
    

    New-UDCard -Title "Host" -Content {
        New-UDElement -Tag "row"  -Content {
            New-UDProgressMetric -Value ($OperatingSystem.TotalVisibleMemorySize / 1MB - $OperatingSystem.FreePhysicalMemory /1MB) -Total ($OperatingSystem.TotalVisibleMemorySize / 1MB) -Metric "GBs" -Label "Memory Used"
        }
        New-UDElement -Tag "row" -Content {
            New-UDProgress -Percent $CPU.LoadPercentage -Label "CPU Usage"
        }   
    }
}

function CPUMonitor_Away{
    New-UdMonitor -Title "CPU (% processor time)" -Type Line -DataPointHistory 20 -RefreshInterval 5 -ChartBackgroundColor '#80FF6B63' -ChartBorderColor '#FFFF6B63'  -Endpoint {
        $t =  Invoke-Command -computername $Cache:RemoteCompIP -Credential $Cache:Cred  -ScriptBlock {   Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue 
    }
    $t | Out-UDGridData
 } 
}

function MemoryMonitor_Away{
    New-UdMonitor -Title "Memory Usage %" -Type Line -DataPointHistory 20 -RefreshInterval 5 -ChartBackgroundColor '#9591eb' -ChartBorderColor '#3459eb'  -Endpoint {
        $t =  Invoke-Command -computername $Cache:RemoteCompIP -Credential $Cache:Cred -ScriptBlock {   Get-Counter '\memory\% committed bytes in use' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
    }
    $t | Out-UDGridData
 } 
}

function DiskMonitor_Away{
    New-UdMonitor -Title "Disk Usage (Metric TBA)" -Type Line -DataPointHistory 20 -RefreshInterval 5 -ChartBackgroundColor '#9aeb91' -ChartBorderColor '#46eb34'  -Endpoint {
        $t =  Invoke-Command -Session $Cache:Session2 -ScriptBlock {   Get-Counter '\physicaldisk(_total)\% disk time' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
    }
    $t | Out-UDGridData
 } 
}

function NetworkMonitor_Away{
    $t =  Invoke-Command -Session $Cache:Session2  -ScriptBlock {Get-Counter "\Network Adapter(*)\Bytes Total/sec" | Select-Object -ExpandProperty CounterSamples | where {$_.CookedValue -ne 0} | Select-Object -ExpandProperty CookedValue
 }
    New-UdMonitor -Title "Network Usage (Up + Down) (Metric TBA)" -Type Line -DataPointHistory 20 -RefreshInterval 5 -ChartBackgroundColor '#fad678' -ChartBorderColor '#e3b029'  -Endpoint {
    $t | Out-UDGridData
 } 
}

function ProcessViewer_Away{
    New-UdGrid -Title "Processes" -Headers @("Name", "ID", "Working Set", "CPU") -Properties @("Name", "Id", "WorkingSet", "CPU") -AutoRefresh -RefreshInterval 60 -Endpoint {
    $t =  Invoke-Command -Session $Cache:Session2 -ScriptBlock { Get-Process | Select Name,ID,WorkingSet,CPU   
    }
    $t | Out-UDGridData
 } 
}


