Get-UDDashboard | Stop-UDDashboard

Import-Module (Join-Path $PSScriptRoot 'HomeComputerFunctions.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'RemoteComputerFunctions.psm1') -Force

$HomePageContent = {
    New-UDCard  -Content {
        New-UDHeading -Text "Network Scan" -Size 5

        New-UDHeading -Size 6 -Content { "Retrieve the list of available computers on this network, using one of the 2 options" } 
        
        # New-UDTabContainer starts
        New-UDTabContainer -Tabs {
            # New-UDTab starts
            New-UDTab -Text "Upload a CSV containing IPs and Passwords" -Content {
                New-UDInput -Title "Browse" -SubmitText "Upload" -BackgroundColor "white" -Id "networkscan" -Content {
                    New-UDInputField -Type binaryFile -Name file 
                     } -Endpoint {
                    param($File)
                    Show-UDToast -Message "Dummy"
                }            
            }
            # New-UDTab ends
            
            # New-UDTab starts
            New-UDTab -Text "Scan the Network" -Content {
                New-UDRow -Endpoint {
                    New-UDColumn -Endpoint {
                        New-UDButton -Text "Scan Network" -OnClick {
                            Show-UDToast -Message "Retrieving Network Details"
                            RetrieveNetwork
                            Show-UDToast -Message "Refresh the Page"
                        }
                    }
                }
            }
            # New-UDTab ends
        }
        # New-UDTabContainer ends

    }
    
    New-UDCard -Content {
        New-UDHeading -Text "List of Available Computers" -Size 5
        # New-UDPreloader -ProgressColor green
        New-UDRow -Endpoint {
            if($Cache:network -eq $null)
            {
                New-UDPreloader -ProgressColor green

                RetrieveNetwork
                DisplayNetworkEndpoints
            }else{
                Show-UDToast -Message "Loading directly from cache"
                DisplayNetworkEndpoints
            }
        }
    }
}        

$Content_HostEndpointStaticPage =  {
        New-UDRow -Endpoint {    New-InstallSoftwareCard    } 
        
        New-UDRow -Endpoint {
            New-UninstallSoftwareCard
            } -AutoRefresh -RefreshInterval 60

        New-UDRow -Endpoint {
            New-ListSoftwareCard
            } -AutoRefresh -RefreshInterval 5
        
        
        #New-UDRow -Endpoint { New-CheckCard } 

        New-UDRow -Endpoint {
            New-UDColumn -Size 6 -Content {
                New-OverviewCard 
            }
            New-UDColumn -Size 6 -Content {
                New-NetworkCard
            } 
        } -AutoRefresh -RefreshInterval 60

        New-UDRow -Endpoint {
            New-UDColumn -Size 6 -Content {
                New-StorageCard
            } 
            New-UDColumn -Size 6 -Content {
                New-Resource
            } 
        } -AutoRefresh -RefreshInterval 1
        New-UDRow -Endpoint {
            New-UDColumn -Size 12 -Content {
                Get_Processes
            } 
        }
        New-UDRow -Endpoint {
            New-UDColumn -Size 6 -Content {
                CPU_Monitor
            } 
            New-UDColumn -Size 6 -Content {
                Memory_Monitor
            } 
        }
        New-UDRow -Endpoint {
            New-UDColumn -Size 6 -Content {
                Disk_Monitor
            } 
            New-UDColumn -Size 6 -Content {
                Network_Monitor
            } 
        }
}

$AuthenticationMethod = New-UDAuthenticationMethod -Endpoint {
    param([PSCredential]$Credentials)

    if ($Credentials.UserName -eq "sachin" -and $Credentials.GetNetworkCredential().Password -eq "vitcc") {
        New-UDAuthenticationResult -Success -UserName "sachin"
    }

    New-UDAuthenticationResult -ErrorMessage "You are not Sachin Tendulkar !"
}

$LoginPage = New-UDLoginPage -AuthenticationMethod $AuthenticationMethod -PageBackgroundColor "#3f51b5"

$Cache:hostIP = GetHostEndpointIP

$HomePage = New-UDPage -Name "Home" -Icon home -Content $HomePageContent
$HostEndpointStaticPage = New-UDPage -Name "$($Cache:hostIP)" -Icon "laptop" -Content $Content_HostEndpointStaticPage 

    
$RemoteEndpointDynamicPage = New-UDPage -Url "/:IP" -Title "Remote Computer Page" -Icon "cloud" -Endpoint {
    param(
        [Parameter(
            Mandatory = $true
        )]
        $IP
    )
    # $Cache:RemoteCompIP = "192.168.0.150"
    # $Cache:RemoteCompUser = "hulk"
    # $Cache:RemoteCompPwd = "LukaModric10"
    
    ###################################  Remote Computer : Cache Variables Section #############################################

    $t = $Cache:network | Where-Object IP -eq $IP
    $Cache:RemoteCompIP = $IP
    $Cache:RemoteCompUser = $t.User
    $Cache:RemoteCompPwd = $t.Password
    
    $Cache:password = ConvertTo-SecureString $Cache:RemoteCompPwd  -AsPlainText -Force
    $Cache:Cred  = New-Object System.Management.Automation.PSCredential ($Cache:RemoteCompUser, $Cache:password)
    
    
    $Cache:Session = New-PSSession -ComputerName $Cache:RemoteCompIP -Credential $Cache:Cred
    $Cache:Session2 = New-PSSession -ComputerName $Cache:RemoteCompIP -Credential $Cache:Cred
    
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
    } -Session $Cache:Session
    
    $Cache:MyVariable = 1

    ###################################  Remote Computer : UD Variables Section #############################################

    New-UDRow -Endpoint {
        New-UDColumn -Size 2 -Content {
            New-UDButton -Text "Remote Desktop" -OnClick (
                New-UDEndpoint -Endpoint {
                    Show-UDToast -Message "Initiaing Remote Desktop connection !"
                    RemoteDesktop 
                                        } )
        }
        New-UDColumn -Size 2 -Content {
            New-UDButton -Text "Lock Computer" -OnClick (
                New-UDEndpoint -Endpoint {
                        Show-UDToast -Message "Initiaing RemoteLock !"
                        RemoteLock 
                } 
            )
        }
        New-UDColumn -Size 2 -Content {
            New-UDButton -Text "Restart Computer" -OnClick (
                New-UDEndpoint -Endpoint {
                    Show-UDToast -Message "Initiaing Remote Desktop connection !"
                    RemoteRestart 
                                        } )
                                }
        New-UDColumn -Size 2 -Content {
            New-UDButton -Text "Shutdown Computer" -OnClick (
                New-UDEndpoint -Endpoint {
                    Show-UDToast -Message "Initiaing Remote Desktop connection !"
                    RemoteShutdown 
                                        } )     
                                    }                        
    }

    New-UDRow -Endpoint { InstallSoftwareCard_Away } 

    New-UDRow -Endpoint { UninstallSoftwareCard_Away } 

    New-UDRow -Endpoint {
        ListSoftwareCard_Away
        } -AutoRefresh -RefreshInterval 5

    New-UDRow -Endpoint {
        New-UDColumn -Size 6 -Content {
            OverviewCard_Away 
        }
        New-UDColumn -Size 6 -Content {
            NetworkCard_Away
        } 
    } -AutoRefresh -RefreshInterval 60

    New-UDRow -Endpoint {
        New-UDColumn -Size 6 -Content {
            StorageCard_Away
        } 
        New-UDColumn -Size 6 -Content {
            Resource_Away
        } 
    } -AutoRefresh -RefreshInterval 1
    # New-UDRow -Endpoint {
    #     New-UDColumn -Size 12 -Content {
    #         ProcessViewer_Away
    #     } 
    # }
    # New-UDRow -Endpoint {
    #     New-UDColumn -Size 6 -Content {
    #         CPUMonitor_Away
    #     } 
    #     New-UDColumn -Size 6 -Content {
    #         MemoryMonitor_Away
    #     } 
    # }-AutoRefresh -RefreshInterval 2
    # New-UDRow -Endpoint {
    #     New-UDColumn -Size 6 -Content {
    #         DiskMonitor_Away
    #     } 
    #     New-UDColumn -Size 6 -Content {
    #         NetworkMonitor_Away
    #     } 
    # }
}

$EndpointInitialization = New-UDEndpointInitialization -Module @("$PSScriptRoot\HomeComputerFunctions.psm1","$PSScriptRoot\RemoteComputerFunctions.psm1")

$Dashboard  = New-UDDashboard -Title "Apache Heimdall - Endpoint Configuration Tool by @npranav10" -Pages @($HomePage,$HostEndpointStaticPage,$RemoteEndpointDynamicPage) -EndpointInitialization $EndpointInitialization #-LoginPage $LoginPage 

Start-UDDashboard -Port 7777 -Dashboard $Dashboard -AdminMode -AutoReload -AllowHttpForLogin