<#
 Win500 Assignment 1
 Created by William Chi & Yifeng Zheng
#>

Clear-Host

#Initial definitions
$option = 0
$choice = 0
$computers = Get-ADcomputer -filter * | Select -ExpandProperty Name
$path_name= "C:\Temp"

#Cmdlet sub-menu for #7
$p7cmdlets = @(
    "1. Get Computer Info `n",
    "2. Add New User `n",
    "3. Get User's Last Login Info `n",
    "4. Restrict Login Access `n",
    "5. Exit"
    )

#Part 1: Main Menu
function MainMenu()
{
    Do {
        Clear-Host
        "          Win500 - Assignment 1 Fall 2020         " 
        "-------------------------------------------------"
        Write-Host "
        1. Get Servers Informations `n
        2. Restart all the servers `n
        3. Sessions `n
        4. Remote functions `n
        5. Create  / Modify / Delete User `n
        6. Cmdlets `n
        7. Endpoint `n
        8. JPG Files `n
        9. Firewall Status `n
        10. Exit `n" 
     
        [int]$option = Read-Host "Enter option "

        Switch ($option) {
            '1' {Clear-Host;GetAdComputersInfo}
            '2' {Clear-Host;RestartServers}
            '3' {Clear-Host;Sessions}
            '4' {Clear-Host;RemoteFunction}
            '5' {Clear-Host;UsersGroups}
            '6' {Clear-Host;cmdlets}
            '7' {Clear-Host;Endpoint}
            '8' {Clear-Host;jpg}
            '9' {Clear-Host;exit}
            '10'{Clear-Host;exit}
            Default {Write-Host "Invalid option"}
        }
    } until ($option -eq 10) 
}

#Part 2: Server Inventory System
function GetAdComputersInfo()
{
    
    $adComputers = Get-ADcomputer -filter * | Select -ExpandProperty Name
    $onComputers = @()
    $offComputers = @()
    foreach ($comp in $adComputers)
    {
      if(-Not (Test-Connection -ComputerName $comp -Count 1 -Quiet))
        {
            $("$comp Not Available") | Out-File C:\temp\ConnectionTest.txt 
          $offComputers += $comp
      }
      else{
         Test-Connection -ComputerName $comp -Count 1 
           $onComputers += $comp
        }
    }

    $ADComputerInfo = @()
    foreach ($comp in $onComputers)
    {
        $pc = @{}
        $diskInfo = Get-CimInstance  -ClassName Win32_LogicalDisk -ComputerName $comp  | ? {$_.DriveType -eq 3}
        
        $system = Get-CimInstance Win32_OperatingSystem -ComputerName $comp
        $pc.Add("Server", $system.CSName)
        $pc.Add("Type", $system.Caption)
        $pc.Add("Serial Number", $system.SerialNumber)
        $pc.Add("Device", $diskInfo.DeviceID)
        $pc.Add("Disk Size","$([math]::round($diskinfo.Size /1MB))" + " MB" )
        $pc.Add("Free Space","$([math]::round($diskinfo.Freespace /1MB))" + " MB" )
        $pc.Add("RAM","$([math]::round($raminfo.TotalPhysicalMemory /1GB))" + " GB")
    
        $ADComputerInfo += New-Object psobject -Property $pc | Select-Object "Server", "Type", "Serial Number", "Device", "Disk Size", "Free Space", "RAM" 
    }

    $ADComputerInfo | Format-Table | Out-File C:\temp\ADComputerInfo.txt
    $ADComputerInfo | ConvertTo-Html | Out-file C:\temp\ADComputerInfo.html

    if ($offComputers.Count -ne 0)
    {
        foreach ($comp in $offComputers)
        {
            Write-Output "Server Unavailable: $comp" | Out-File C:\temp\ADComputerInfo.html -Append
        }
    } 
    start C:\temp\ADComputerInfo.html
}

#Part 3: Restart All Servers (except this one)
function RestartServers()
{
    $server_list = Get-ADComputer -Filter 'Name -notlike "SRV1-AD"' | Select-Object -ExpandProperty Name

    Foreach ($server in $server_list)
    {
        Restart-Computer -ComputerName $server -Force
        sleep 5
        do {
            Write-Host "Server $server is restarting. Please wait, this can take a few minutes. `n"
        }until (Test-Connection $server -Quiet)
     
        Write-Host "Server restart finished System confirmation details: "   
        sleep 4
        $ip_address = (Test-Connection -ComputerName $server -ErrorAction SilentlyContinue).IPV4Address.IPaddresstostring[0]
        $startup = (Get-CimInstance -ComputerName $server -ClassName Win32_OperatingSystem).LastBootUpTime

        Write-Host "Server $server "
        Write-Host "Status:  Running"
        Write-Host "IP Address: $ip_address"
        Write-Host "Startup Time: $startup `n"
    
    }
    Pause
}

#Part 4: Sessions
function Sessions()
{
    $sessionName = Read-Host "Enter the name of the session "
    $sessionComputer = Read-Host "Enter computer you wish to connect to "
    New-PSSession -ComputerName $sessionComputer -Name $sessionName 

    Enter-PSSession -ComputerName $sessionComputer
    Pause

    Get-PSSession

    Remove-PSSession -Name $sessionName
    Write-host "Session $sessionName has been removed."

    Pause
}

#Part 5: Remote Function
function RemoteFunction()
{
    Clear-Host
    
    $user = Read-Host "Enter username"

    #DSQuery finds users in AD who match the search criteria.
    if (dsquery user -samid $user) {
        if ((Get-ADUser -Identity $user).Enabled) {    #If $user is enabled (active)
             #Example: Administrator
             Write-Host "`n$user is an active account. `n"
             $login_history = (Get-ADUser -Identity $user -Properties "LastLogonDate").LastLogonDate
             #If a login history exists, account is active and display. Else, state that the account has never logged in.
             if ($login_history) {
                Write-Host "$user's last login time is $login_history `n"
              }else {
                Write-Host "$user has never logged in. `n"
              }
         }else {
             #Example: Guest account
             Write-Host "`n$user is not active. `n"
         }
    }else {
        #Example: Non-existent account
        Write-Host "$user is not found in the Active Directory database. `n"
    }
    Pause
    
}

#Part 6: User Groups
function UsersGroups()
{
    $user = Read-Host "Enter username of user to be added "

    while ([bool] (Get-ADUser -Filter {SamAccountName -eq $user}))
    {
        $user = Read-Host "User already exists, enter another username "
    }

    New-ADUser -SamAccountName $user -Name $user -Enabled $true -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd" -Force)

    $group = Read-Host "Enter group for user to be added in"

    while ([bool] (Get-ADGroup -filter {Identity -eq $group}))
    {
        $group = Read-Host "Group already exists, enter another group name "
    }

    New-ADGroup -name $group -GroupScope Global -SamAccountName $group
    Add-ADGroupMember -Identity $group -Members Administrator
    Add-ADGroupMember -Identity $group -Members $user
    
    Write-Host "`n$user has been added to group $group"   
    Write-Host "Only users in group $group may use Powershell"

    Pause
}

#Part 7: Get cmdlets
function cmdlets()
{
    #Import module
    Import-Module mycmdlets -Force

    Write-Host "Importing module.. please wait."
    #Sleep 1
    Write-Host "Imported Module mycmdlets.psm1 successfully." -ForegroundColor Green; Pause

    #Set Aliases
    Set-Alias -name gcinfo -Value Get-Computerinfo
    Set-Alias -name anu -Value Add-NewUser
    Set-Alias -name ll -Value Get-LastLogin

    do {
        Clear-Host
        $p7cmdlets
        "`n"
        [int]$choice = Read-Host "Enter choice "
    
        switch ($choice) {
        '1' {gcinfo;Pause}
        '2' {anu;Pause}
        '3' {ll;Pause}
        '4' {slt;Pause}
        '5' {MainMenu}
        Default {"Wrong Choice"}
        }    
    } until ($choice -eq 4)
}

#Part 8: Endpoints
function Endpoint() 
{
    Register-PSSessionConfiguration -Path "C:\scripts\endpoints.pssc" -name a1Endpoints -Force
    Write-Host "Endpoint has been sucessfully created."
    Pause
}

#Part 9: JPG Files
function jpg() {

    foreach ($server in $computers) {
        $path = "\\$server\c$\Temp\Picture"

        if (-not(Test-Path $path)) {
            Write-Host "Picture folder doesn't exist on $server, creating Picture folder."
            Invoke-Command -ComputerName $server -ScriptBlock {New-Item -Path C:\Temp\Picture -ItemType Directory -Force}
        } else {
            Write-Host "$server already has Picture folder, it will not be recreated."
        }
    }
    
    $scriptblock = {
        $picture = Get-ChildItem -Path C:\Temp\Picture
        remove-item C:\Temp\Picture\* -Force
        sleep 2
        
        $allfiles = Get-ChildItem -Recurse -Include *jpg -path C:\Users | Where Directory -NotLike "*Picture*" 
    
        foreach ($i in $allfiles) {
            if ($i.Name -notin $picture.Name) {
                Copy-Item $i.FullName -Destination "C:\Temp\Picture" -Force
                Write-Output $i.Name
            }
        }
    }

    $final = @()

    foreach ($server in $computers) {
        $serverblock = Invoke-Command -ComputerName $server -ScriptBlock $scriptblock 

        foreach ($file in $serverblock) {
            $final += New-Object psobject -Property @{
            Server = $server
            Files = $file
            } | Select Server, Files
        }
    }

    Pause
}

#Start Script
MainMenu