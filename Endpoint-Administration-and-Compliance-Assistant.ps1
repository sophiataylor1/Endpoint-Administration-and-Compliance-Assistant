<#
    .SYNOPSIS
        Helpdesk Automation & Compliance Assistant
    .DESCRIPTION
        Modular CLI utility for Active Directory management, endpoint compliance checks,
        and security agent lifecycle remediation.
    .NOTES
        Requires appropriate administrative execution rights and a configured PowerShell
        Execution Policy (e.g., RemoteSigned or Bypass) for operational testing.
#>


####################################################################################################################
##### SOFTWARE #####
#The location of the folders "CarbonBlack" and "DigitalGuardian" containing their respective file(s) listed below
$Programs = "C:\Temp\Programs"
# Carbon Black version in folder "$Programs\CarbonBlack"
$CBmsiName = "CarbonBlack4.2.0.3361.msi"
# Digital Guardian file names in folder "$Programs\DigitalGuardian"
$DGmsi = "DG_WinWS_794.msi"
$DGTerm = "Terminator.exe"
$DGClean = "DGCleaner.exe"

##### TEMPLATES #####
#Location of Laptop checklist and New user info templates
$templatesfolder ="C:\Temp\Templates"
#Laptop checklist template name in $templatesfolder
$ltcheckfilename ="2026 PC Build Checklist Template.dotx"

##### SAVE LOCATIONS #####
#laptop checklist
$checklistsave = "C:\Temp"
#New user info
$userinfosave = "C:\Temp"
#Event Viewer .csv
$eventsave = "C:\Temp"
####################################################################################################################
####### MAIN SCRIPT ######

Write-Host "PREREQUISITES:
 Folder at C:\Temp for generated documents
 Templates at C:\Temp\Templates for generated new user login info and laptop checklist
 Software at C:\Temp\Programs for DG and CB installs
 *These default locations can be changed by editing the variable paths at the top of your personal Helpdesk_Assistant_V2.ps1 file"


#Main menu label for returning to main menu
:TopLevel while($true){
    #Closes and clears existing PS sessions if they remain
        if ($session) {
            Remove-PSSession $session -ErrorAction SilentlyContinue
            $session = $null
        }
        #Restart Services
        if ($s) {
            Remove-PSSession $s -ErrorAction SilentlyContinue
            $s = $null
        }
    #Defining functions
    #Function combines Read-Host with ability to type "exit" to return to main menu
    function ReadHostTop {
        param([string]$prompt) #placeholder
            $userinput = Read-Host $prompt
        if ($userinput -eq "exit"){
            Write-Host "Exiting to main menu..." -ForegroundColor Yellow
            Continue TopLevel
        }
        return $userinput
    }
    
 # Main Menu
    Write-Host " "
    Write-Host "Welcome to the Helpdesk command-line compiler. Please select what you would like to do: 

    ACTIVE DIRECTORY
   
    (2)  Machine       - Configure/View machine properties and policies
    (3)  New User      - Configure/View user properties and download new user documents
    (4)  Signature     - Modify MBTI, Gallup strengths, and designations
    (5)  Sign in       - View password expiration date and last authentication date
  
    
    MACHINE (local or remote)

    (8)  CMD           - Run commands on remote computer
    (9)  Event Viewer  - Filter and export events to .csv
    (12) Restart Services
    (13) Show Uptime
    (14) Software      - Manage DG and CB installs 
    (15) Storage       - Check and clean up space
    
    (16) EXIT

    NOTE: Enter 'Exit' at any point to return to this menu
          
    "
    $InitialQuestion = ReadHostTop ">"
### ACTIVE DIRECTORY ###
#(2) Machine 
    elseif($InitialQuestion -eq '2'){
        Write-Host "___________________"
        Write-Host "Machine Properties " -ForegroundColor Yellow
        Write-Host "___________________"

        $vieworconfig = ReadHostTop "Choose an option:
        (1) View given machine's current OU and AD groups
        (2) Configure various machine properties
             - Rename Registry.pol
             - Run GPUpdate
             - Check Bitlocker status
             - View Bitlocker key and sync it to Entra
             - Add ISE prevention reg key
             - Allow Windows updates by moving machine OU
        (3) Exit
              "
        
        #Function to update machine group policy; See usergp for more comments
        function machinegp {
            $start = Get-Date
            $done = $null
            Write-Host "Please wait, machine group policy update command sent to $compinput at $start"
            Write-Host "Timeout will occur in 10 minutes if completion confirmation is not received before then."
            $job = Start-Job -Credential $cred -ArgumentList $compinput -ScriptBlock {
                    param($compinput)
                    Import-Module GroupPolicy
                    Invoke-GPUpdate -Computer $compinput -Target Computer -RandomDelayInMinutes 0 -Force
                }
            while (-not $done -and (Get-Date) -lt $start.AddMinutes(10)) {
                Start-Sleep -Seconds 2
                if ($job.State -eq 'Failed') {
                    Write-Host "The Group Policy update job failed." -ForegroundColor Red
                    Receive-Job $job
                    break
                }
                # Look for event viewer notification that says it is done
                $done = Invoke-Command -Session $session -ArgumentList $start -ScriptBlock {
                    param($start)
                    Get-WinEvent -FilterHashtable @{
                        LogName   = "Microsoft-Windows-GroupPolicy/Operational"
                        Id        = 8004
                        StartTime = $start
                    } -MaxEvents 1 -ErrorAction SilentlyContinue
                }
            }
            if ($done) {
                Write-Host $done.Message -ForegroundColor Green
            }
            else {
                Write-Host "Group Policy did not confirm completion within 10 minutes." -ForegroundColor Red
            }
        }
        #Function to update user group policy
        function usergp {
            $start = Get-Date
            $done = $null
            Write-Host "Please wait, user group policy update command sent to $compinput at $start"
            Write-Host "Timeout will occur in 10 minutes if completion confirmation is not received before then."
            #Uses job so remote user does not need Import-Module GroupPolicy on their machine, references your own machine
            $job = Start-Job -Credential $cred -ArgumentList $compinput -ScriptBlock {
                param($compinput) #uses local variable on remote machine
                Import-Module GroupPolicy #If PS module isn't there, imports it
                #Updates user group policy, with no delay
                Invoke-GPUpdate -Computer $compinput -Target User -RandomDelayInMinutes 0 -Force
            }
            # Time out loop;
            while (-not $done -and (Get-Date) -lt $start.AddMinutes(10)) {
                Start-Sleep -Seconds 2
                 #If job immediately fails, don't wait for time out
                if ($job.State -eq 'Failed') {
                    Write-Host "The Group Policy update job failed." -ForegroundColor Red
                    Receive-Job $job
                    break
                }
                # Look for event viewer notification that says it is done
                $done = Invoke-Command -Session $session -ArgumentList $start -ScriptBlock {
                    param($start)
                    Get-WinEvent -FilterHashtable @{ #way to organize filters/make more readable
                        LogName   = "Microsoft-Windows-GroupPolicy/Operational"
                        Id        = 8005
                        StartTime = $start
                    } -MaxEvents 1 -ErrorAction SilentlyContinue
                }
            }
            if ($done) {
                Write-Host $done.Message -ForegroundColor Green #event viewer message confirmation
            }
            else {
                Write-Host "User group policy did not confirm completion within 10 minutes." -ForegroundColor Red
            }
        }

        #view machine OU and AD groups       
        if ($vieworconfig -eq 1){
            :viewtop while($true){
                Write-Host "- View Machine OU and AD Groups -"
                $CompInput = ReadHostTop -Prompt "Enter the name of the computer (lastnamef-lt)"
                $CompAD = $null
                $CompAD = Get-ADComputer -Filter "Name -eq '$CompInput'" -Properties CanonicalName, MemberOf -ErrorAction SilentlyContinue

                #If name isn't resolved, give error message. Else, output OU and AD groups.
                if (-not $CompAD) {
                    Write-Host "Computer not found, please try again." -ForegroundColor Red
                }else {
                    #Outputs AD group names only in a list
                    Write-Host "- AD Groups -" -ForegroundColor Yellow
                    $CompAD.MemberOf | Get-ADGroup | Select-Object -ExpandProperty Name 
                    
                    #Outputs OU
                    Write-Host ""
                    Write-Host "- OU -"-ForegroundColor Yellow
                    $CompAD.CanonicalName
                    Write-Host " "
                    
                    #Go back to main menu, or restart to enter computer name
                    $exityn = ReadHostTop "Do you want to view another machine's OU and AD groups? (y/n)"
                    if($exityn -eq 'n'){
                        Continue TopLevel
                    }else{
                        Continue viewtop
                    }  
                }
            }
        }
        #configure machine properties
        elseif ($vieworconfig -eq 2){
            :pingtop while($true){
                $compinput = ReadHostTop "What is the name of the machine?"
                $ping = Test-Connection -ComputerName $compinput -Count 1 -Quiet -ErrorAction SilentlyContinue
                #if the computer is connected
                if ($ping -eq $true){
                    :cred while ($true){
                        $session = $null #ensures failed session attempts aren't stored
                        $username = "DOMAIN\adminacct" #for credentials. Decreases time because it isn't creating a new user profile at c:\users
                        $credyn = ReadHostTop "Continue to enter adminacct password? (y/n)" #Stop in case password is entered wrong. Prevents lockout from only one incorrect attempt
                        if($credyn -eq 'y'){
                            #prompts for credentials with adminacct autofilled with the message enter password for adminacct
                            $cred = Get-Credential -Username $Username -Message "Enter password for adminacct"
                            #creates new pssession on remote computer using entered credentials
                            $session = New-PSSession -ComputerName $compinput -Credential $cred -ErrorAction SilentlyContinue
                            #Continues if session can be connected (password is valid, computer is connected)
                            if ($session){
                                break
                            }
                            #Takes back to enter credentials again. Prevents rest of script authenticating with wrong password and locking out
                            else{
                                Write-Host "Unable to establish session. Please verify password and computer connectivity." -ForegroundColor Red
                                Continue cred
                            }
                        }else{
                            Continue TopLevel
                        }
                    }

                    :Entra while ($true){
                        $entrachoice = ReadHostTop "Choose an option below for $($compinput):
                        (1) Rename Registry.pol for machine
                        (2) Run GPUpdate
                        (3) Check Bitlocker status
                        (4) View and/or upload Bitlocker key to Entra
                        (5) Add ISE prevention reg key
                        (6) Allow Windows updates by moving machine OU

                        (7) Configure properties of a different machine
                        (8) Exit
                        "
                        #Rename GPO files
                        if ($entrachoice -eq 1){
                            $choice1 = ReadHostTop "Rename Registry.pol to Registry.pol.bak for machine on $($compinput)? (y/n)"
                            if ($choice1 -eq 'y'){
                                Write-Host "Attempting to rename Registry.pol to Registry.pol.bak"
                                Invoke-Command -Session $session -ScriptBlock {
                                    Rename-Item "C:\Windows\System32\GroupPolicy\Machine\Registry.pol" "Registry.pol.bak"}
                            }
                            Continue Entra
                        }
                        #Update group policy
                        elseif ($entrachoice -eq 2){
                            Write-Host "Choose which group policy to update:
                            (1) Machine
                            (2) User
                            (3) Exit"
                            
                            $gpchoice = ReadHostTop "   >"
                            if ($gpchoice -eq 1){
                                $gpmconfirm = ReadHostTop "Silently update $compinput's machine group policy? (y/n)"
                                if ($gpmconfirm -eq 'y'){
                                       machinegp
                                }
                            }elseif($gpchoice -eq 2){
                                Write-Host 'WARNING: When ran, user will see terminal window that says "Updating policy...."'
                                Write-Host "Once it has processed, they will see the normal output, then be prompted to sign off."
                                Write-Host "You can send the below to the user:"
                                Write-Host 'I will be running a command on your computer that may open a new window that says "Updating policy..."'
                                Write-Host 'If you do get this window and it does not disappear on its own you can minimize it [-] for now, but only hit [X] to close it once you see it say "OK to log off? (Y/N)"'
                                Write-Host 'This usually takes less than 10 minutes.'
                                $gpuserconfirm = ReadHostTop "Update $compinput's user group policy? (y/n)"
                                if ($gpuserconfirm -eq 'y'){
                                    usergp
                                }
                            }
                            Continue Entra
                        }
                        #View Bitlocker Status
                        elseif ($entrachoice -eq 3) {
                            #get bitlocker info
                            $BitLocker = Invoke-Command -Session $session -ScriptBlock {
                                Get-BitLockerVolume -MountPoint "C:"
                            }
                            Write-Host "$compinput BitLocker Status:"
                            #get specific bitlocker info
                            $BitLocker |
                                Select-Object MountPoint, VolumeStatus,
                                    EncryptionPercentage, ProtectionStatus |
                                Format-Table -AutoSize
                            
                            ###Bitlocker logic tree (courtesy Copilot)
                                #If bitlocker is encrypted and on
                            if ($BitLocker.VolumeStatus -eq "FullyEncrypted" -and
                                $BitLocker.ProtectionStatus -eq "On") {
                                Write-Host "BitLocker is encrypted and protection is on." -ForegroundColor Green
                            }
                            elseif ($BitLocker.VolumeStatus -eq "FullyEncrypted" -and
                                    $BitLocker.ProtectionStatus -eq "Off") {
                                Write-Host "The drive is encrypted, but BitLocker protection is suspended." 
                                Write-Host "Please have the user reboot to install potential firmware updates before manually resuming protection."
                                    -ForegroundColor Yellow
                                $BitLockerYN = ReadHostTop "Would you like to resume BitLocker protection? (y/n)"
                                if ($BitLockerYN -eq 'y') {
                                    Invoke-Command -Session $session -ScriptBlock {
                                        Resume-BitLocker -MountPoint "C:" | Out-Null
                                    }
                                    Write-Host "BitLocker protection was resumed." -ForegroundColor Green
                                }
                            }
                            elseif ($BitLocker.VolumeStatus -eq "FullyDecrypted") {
                                Write-Host "The drive is not encrypted." -ForegroundColor Yellow
                                $BitLockerYN = ReadHostTop "Would you like to enable BitLocker? (y/n)"
                                if ($BitLockerYN -eq 'y') {
                                    Invoke-Command -Session $session -ScriptBlock {
                                        Enable-BitLocker 
                                            -MountPoint "C:" 
                                            -RecoveryPasswordProtector 
                                            -SkipHardwareTest | Out-Null
                                    } 
                                    Write-Host "BitLocker encryption was started." -ForegroundColor Green
                                }
                            }
                            elseif ($BitLocker.VolumeStatus -eq "EncryptionInProgress") {
                                Write-Host "BitLocker encryption is already in progress." 
                                    -ForegroundColor Yellow
                            }
                            elseif ($BitLocker.VolumeStatus -eq "DecryptionInProgress") {
                                Write-Host "BitLocker decryption is currently in progress." 
                                    -ForegroundColor Yellow
                            }
                            else {
                                Write-Host "BitLocker is in an unexpected state: $($BitLocker.VolumeStatus)" 
                                    -ForegroundColor Yellow
                            }
                            Continue Entra
                        }
                        #Backup Bitlocker key to Entra
                        elseif ($entrachoice -eq 4){
                            # Check computer
                            $LocalKey = Invoke-Command -Session $session -ScriptBlock {
                                #Gets Bitlocker key from machine if there is one
                                (Get-BitLockerVolume C:).KeyProtector |
                                    Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"}
                            }
                            if ($LocalKey) {
                                Write-Host "BitLocker key found on local machine:" -ForegroundColor Green
                                Write-Host $LocalKey.RecoveryPassword #writes recovery key
                                $backup = Read-Host "Would you like to back up the key to Entra? (y/n)"
                                if ($backup -eq 'y') {
                                    Invoke-Command -Session $session -ScriptBlock {
                                        #Gets recovery key, then backs up to AD
                                        $key = (Get-BitLockerVolume C:).KeyProtector |
                                            Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"}
                                        BackupToAAD-BitLockerKeyProtector C: $key.KeyProtectorId 
                                    }
                                    Write-Host "Attempted to write key to Entra. Please check the website and refresh." -ForegroundColor Green
                                }
                                Continue Entra
                            }
                            else{
                                Write-Host "Key not found on computer, check that Bitlocker is enabled." -ForegroundColor Red
                                Continue Entra
                            }
                        }
                        #Write ISE prevention registry key
                        elseif ($entrachoice -eq 5){
                            $choice5 = ReadHostTop "Add BlockNtlmv1SSO reg key to $($compinput)? (y/n)"
                            if ($choice5 -eq 'y'){
                            Write-Host "Attempting to add BlockNtlmv1SSO reg key to $compinput"
                            #runs command on the remote computer
                            Invoke-Command -Session $session -ScriptBlock {
                                #adds reg key
                                New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "BlockNtlmv1SSO" -PropertyType DWord -Value 0 -Force}
                            }
                            Continue Entra
                        }
                        #allow windows updates
                        elseif($entrachoice -eq 6){
                            :updatetop while ($true){
                                Write-Host "- Allow Windows Updates -"
                                $CompAD = $null #ensures variable is fresh
                                $CompAD = Get-ADComputer -Filter "Name -eq '$CompInput'" -Properties CanonicalName, MemberOf -ErrorAction SilentlyContinue #get readable OU
                                #Outputs OU
                                #gets original OU to be reverted back to if needed
                                $ogoumove = $CompAD.DistinguishedName.Split(',',2)[1] #takes the machine name off the OU for when it is promtped to move back
                                #More readable name with / instead of OU=
                                $ogou = $compAD.CanonicalName
                                Write-Host ""
                                Write-Host "- Current OU -"-ForegroundColor Yellow
                                Write-Host "$ogou"
                                Write-Host " "

                                $updateyn = ReadHostTop "Would you like to move $CompInput's OU to allow it to receive Windows updates? (y/n)"
                                if($updateyn -eq 'y'){
                                    #Moves machine to OU to allow Windows updates
                                    Get-ADComputer -Identity "$compinput" | Move-ADObject -TargetPath "OU=placeholder,OU=placeholder,OU=!placeholder,OU=placeholder,DC=placeholder,DC=local"
                                    #Checks AD again for current OU
                                    $CompAD = Get-ADComputer -Identity $compinput -Properties CanonicalName
                                    Write-Host "- Current OU -"-ForegroundColor Yellow
                                    Write-Host "$($CompAD.CanonicalName)"
                                    Write-Host ""
                                    $updategp = ReadHostTop "Would you like to update $compinput's machine (only) group policy? (y/n)"
                                    if ($updategp -eq 'y'){
                                        #Run gpupdate
                                        machinegp #function defined above
                                    }
                                    $revertgp = ReadHostTop "Would you like to change $compinput's OU back to $($ogou)? (y/n)"
                                    if ($revertgp -eq 'y'){
                                        #Move back to machine's original OU
                                        Get-ADComputer -Identity "$compinput" | Move-ADObject -TargetPath "$ogoumove"
                                        Write-Host "- Current OU -"-ForegroundColor Yellow
                                        #Get current OU to confirm change
                                        $CompAD = Get-ADComputer -Identity $compinput -Properties CanonicalName
                                        Write-Host "$($CompAD.CanonicalName)"
                                        $updategp = ReadHostTop "Would you like to update $compinput's machine group policy? (y/n)"
                                        if ($updategp -eq 'y'){
                                            #Update gp
                                            machinegp#function defined above
                                        }
                                    }
                                } 
                                #Go back to main menu, or restart to enter computer name
                                $exityn = ReadHostTop "Do you want to exit? (y/n)"
                                if($exityn -eq 'y'){
                                    Continue TopLevel
                                }else{
                                    Continue updatetop
                                }  
                            
                            }
                        }
                        #view a different machine
                        elseif($entrachoice -eq 7){
                            Continue pingtop
                        }
                        #exit
                        else{
                            if($session){
                                Remove-PSSession $session
                            }
                            Continue TopLevel
                        }
                    }
                }
                else{
                    Write-Host "Unable to connect to machine. Please verify spelling and connectivity." -ForegroundColor Red
                    Continue pingtop
                }
            }
        }
        #exit
        else{
            Write-Host "Returning to main menu..."
            Continue Toplevel
        }
    }
# (3) New/View User
    elseif($InitialQuestion -eq '3'){
        Write-Host "_______________________________"    
        Write-Host "Configure/View User Properties" -ForegroundColor Yellow
        Write-Host "_______________________________"
        
        #Loop to ensure it does not continue if invalid sam
        :samverify while ($true){
            $samin = ReadHostTop "What is the user's sam account? (ab1234)"
            if ($null -eq $samin){
                Write-Host "No input detected, please try again." -ForegroundColor Red
                Continue samverify
            }
            $sam = $samin.Trim()
            $verify = Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue
            if ($verify){
                break
            }
            else{
                Write-Host "User not found. Please try again." -ForegroundColor Red
                Continue samverify
            }
        }
        $setupyn = ReadHostTop "Which would you like to do?
        (1) Set up new user
        (2) View user properties, documents, and templates"

        if ($setupyn -eq '1'){
            
            #Define full name and display name format
            $user = Get-AdUser -Identity $sam -Properties GivenName, Surname
            $fullname = "$($User.Surname), $($User.GivenName)"
            $displayname = "$($User.GivenName) $($User.Surname)"
            Write-Host "Display name and full name reformatted in AD."

            ###### Description ######
            $descr1= ReadHostTop "Choose the appropriate description:
            (1) HO User
            (2) HO User - Temp
            "
            #Maps user inputs to variable
            switch ($descr1){
                1 {$descr2 = "HO User"}
                2 {$descr2 = "HO User - Temp"}
                default {$descr2 = "HO User"}
            }

            ###### Phone Numbers ######
            ### Ask to add RC extension ###
            $extyn= ReadHostTop "Do you want to add the user's RingCentral extension? (y/n)"

            #Set the Telephone Number, Home Phone, and IP Phone
            if ($extyn -eq "y") {
                $extin=ReadHostTop "What is the user's four digit phone extension?"
                $ext = $extin.Trim()
                Set-ADUser -Identity $sam -Replace @{
                telephoneNumber = "$ext"
                homePhone = "(402) 437-$ext"
                ipPhone = "$ext"
                } -ErrorAction SilentlyContinue
                Write-Host "Extension updated in all relevant fields."
            }
            ### Prompt to enter Mobile (other) ###
            $mobileyn= ReadHostTop "Do you want to add the user's mobile number? (y/n)"
            ### Set Mobile (Other) ###
            if ($mobileyn -eq "y") {
                $mobilein = ReadHostTop "What is the user's mobile phone number?"
                $mobile = $mobilein.Trim()
                Set-AdUser -Identity $sam -Replace @{
                    otherMobile = "$mobile"
                } -ErrorAction SilentlyContinue
                Write-Host "Mobile (other) has been updated."
            }
            ###### Organization ######
            ### Job Title ###
            while ($true){    
                $titlein = ReadHostTop "Enter the user's job title"
                $title = $titlein.Trim() -replace '—', '-'
                $titlematch = Get-ADUser -Filter "Title -eq '$title'" -ResultSetSize 1 -ErrorAction SilentlyContinue
                if($titlematch){
                    break
                }
                $titleyn= ReadHostTop "No other user has this job title. Continue anyway? (y/n)"
                if ($titleyn -eq "y"){
                    break
                }
            }
            ### Department ###
            while($true){
                $deptin = ReadHostTop "Enter the user's department name"
                $dept = $deptin.Trim() -replace '—', '-'
                $deptmatch = Get-ADUser -Filter "Department -eq '$dept'" -ResultSetSize 1 -ErrorAction SilentlyContinue
                    if($deptmatch){
                        break
                    }
                    $deptyn= ReadHostTop "No other user is in this department. Continue anyway? (y/n)"
                    if ($deptyn -eq "y"){
                        break
                    }
            }
            ### Manager ###
            $supin = ReadHostTop "Enter the Firstname Lastname or sam (ab1234) of the user's supervisor"

            #Loop ensures manager name is correct
            while($true){
                $suptrim = $supin.Trim()
                #splits first and lastname and assigns variables
                $names = $suptrim -split '\s+'
                $first = $names[0]
                $last = $names[-1]
                $sup = Get-ADUser -Filter "((GivenName -eq '$first') -and (Surname -eq '$last')) -or (SamAccountName -eq '$first')" -ErrorAction SilentlyContinue
                if ($sup){
                    Set-ADUser -Identity $sam -Manager $sup.DistinguishedName
                    Write-Host "Supervisor set for user."
                    break
                }
                else{
                    $supin = ReadHostTop "Supervisor not found. Please check spelling and enter the Firstname Lastname or sam of the user's supervisor"
                }
            }
            #Reformats name
            Rename-ADObject -Identity $user.DistinguishedName -NewName $fullname
            ###### Map AD properties to variables ######
                $SetParameters = @{
                DisplayName = "$displayname"
                Description = "$descr2"
                Title = "$title"
                department = "$dept"
                scriptPath = "logon.vbs"
            }
            ### Make changes above in AD ###
            Set-ADUser -Identity $sam @SetParameters -ErrorAction SilentlyContinue
            Write-Host "Modified user description, job title, department, and logon script."
        }
        ###### AD Confirmation/ Review ######
        #Get current user properties
        $GetUser = Get-ADUser -Identity $sam -Properties Name, GivenName, Surname, DisplayName, initials, Description, title, department, telephoneNumber, homePhone, ipPhone, otherMobile, scriptpath, extensionAttribute3, extensionAttribute6, extensionAttribute7, CanonicalName -ErrorAction SilentlyContinue
        #Manager variables so format is firstname lastname
        $managerlast = (Get-ADUser (Get-ADUser -Identity "$sam" -Properties Manager).Manager -ErrorAction SilentlyContinue).Surname 
        $managerfirst =(Get-ADUser (Get-ADUser -Identity "$sam" -Properties Manager).Manager -ErrorAction SilentlyContinue).GivenName 
        $currentmanager ="$($managerfirst) $($managerlast)"
        ### Output values pulled from AD for review ###
        Write-Host ""
        Write-Host "CONFIRMATION QUERY FROM AD" -ForegroundColor Yellow
        Write-Host "__________________________" -ForegroundColor Yellow
        Write-Host ""
        #General tab
        Write-Host "- General -" -ForegroundColor Yellow
        Write-Host "Full Name: $($GetUser.Name)"
        Write-Host "Initials: $($GetUser.initials)" 
        Write-Host "Display Name: $($GetUser.DisplayName)"
        Write-Host "Description: $($GetUser.Description)"
        Write-Host "Telephone Number: $($GetUser.telephoneNumber)"
        Write-Host ""
        #Object tab
        Write-Host "- Object -" -ForegroundColor Yellow
        Write-Host "OU: $($GetUser.CanonicalName)"
         Write-Host ""
        #Telephones tab
        Write-Host "- Telephones -" -ForegroundColor Yellow
        Write-Host "Home: $($GetUser.homePhone)"
        Write-Host "IP Phone: $($GetUser.ipPhone)"
        Write-Host "Mobile (Other): $($GetUser.otherMobile)"
        Write-Host ""
        #Organization tab
        Write-Host "- Organization -" -ForegroundColor Yellow
        Write-Host "Job Title: $($GetUser.Title)"
        Write-Host "Department: $($GetUser.department)"
        Write-Host "Manager: $currentmanager"
        Write-Host ""
        #Profile tab
        Write-Host "- Profile -" -ForegroundColor Yellow
        Write-Host "Logon Script: $($GetUser.scriptPath)"
        Write-Host "Home Folder > Connect: " -NoNewLine
        Write-Host "If new user, copy the path below and set drive letter to U:" -ForegroundColor Red
        Write-Host "\\DOMAIN.local\placeholder\placeholder\$sam" 
        Write-Host ""
        #extAttributes
        Write-Host "- Attributes -" -ForegroundColor Yellow
        Write-Host "Strengths: $($GetUser.extensionAttribute6)"
        Write-Host "MBTI: $($GetUser.extensionAttribute7)"
        Write-Host "Designations:$($GetUser.extensionAttribute3)"
        Write-Host ""

        ###### Formatting and defining variables not previously defined for templates ######
        $F = $GetUser.GivenName[0] #First letter of firstname
        $L = $GetUser.Surname[0] #first letter of lastname
        $surname = $GetUser.Surname #define lastname only
        $flow = "$F".ToLower() #Lowercase first letter of firtname
        $ltnameup = "$surname$f-lt" #laptopname with uppercases
        $surnamelow = "$($surname.ToLower())" #lowercase surname
        $ltname = $ltnameup.ToLower() #laptopname all lowercase
        $currentyear = (Get-Date).Year #current year
        $adtele = "$($GetUser.telephoneNumber)" #user phone number
        $deptAD = $($GetUser.department) #user department
        $titleAD = $($GetUser.Title) #User job title

        ###### Predicted LP Coder ######
        ### Map department name to LP coder letter ###
        switch -Wildcard ($deptAD) {
            "Business Transformation" { $D = "T" }
            "Claims*" { $D = "C" }
            "Inforce Administration" { $D = "Y(Ruth) or P(Amy)" }
            "Customer Connections" { $D = "F" }
            "Underwriting*" { $D = "G" }
            "Licensing & Contracting" { $D = "B" }
            "Product &*" { $D = "Z" }
            "Corporate Actuarial" { $D = "V" }
            "Worksite &*" { $D = "E" }
            "Case Specialists" { $D = "H" }
            "Internal Audit" { $D = "A" }
            "*Accounting*" { $D = "A" }
            "Product Management" { $D = "J" }
            "New Business Processing" { $D = "Q" }
            "IT*" {$D = "M"}
            "Information Technology Services" {$D = "I"}
            default { $D = $null }
        }
        #Set coder variable to department letter, 1, first initial, last initial
        $LPCoder = "$($D)1$F$L"
        $SamUp = $sam.ToUpper() #capitalize for coder

        ###### Creating Docs ######
        $docyn = ReadHostTop "Generate an autofilled first day login info document and laptop checklist for the user? (y/n)"
        if($docyn -eq 'y'){
            ### Pause while docs are created ###
            Write-Host "Creating documents..."
            Write-Host ""
            ### Create new word doc that isn't visible ###
            $newdoc = New-Object -ComObject Word.Application
            $newdoc.Visible = $false

            ###### First Day Login Info ######
            ### Create new word doc based on defined template path ###
            $defaultpath = "$templatesfolder\First Day Login Info Template.dotx"
            $basicpath ="$templatesfolder\First Day Login Info Template Basic.dotx"
            $CCpath = "$templatesfolder\First Day Login Info Template CC.dotx"
            $Agentpath = "$templatesfolder\First Day Login Info Template Agent.dotx"

            ### Chooses a first day login info template with relevant fields based on department ###
            switch -Wildcard ($deptAD){
                "Customer*" {$nctemplate = $CCpath}
                "Inforce*" {$nctemplate = $Agentpath}
                "Worksite &*" {$nctemplate = $Agentpath}
                "Licensing & Contracting" {$nctemplate = $Agentpath}
                "Accounting Corporate" {$nctemplate = $Agentpath}
                "*Sales*" {$nctemplate = $basicpath}
                "*Marketing*" {$nctemplate = $basicpath}
                "*Maintenance*" {$nctemplate = $basicpath}
                default  {$nctemplate = $defaultpath}
            }
            $ncdoc = $newdoc.Documents.Add($nctemplate)

            ### Assign template placeholders to variables ###
            $placeholder = @{
                "[surname]" = "$($GetUser.Surname)"
                "[sam]" = "$sam"
                "[year]" = "$currentyear"
                "[F]" = "$F"
                "[L]" = "$L"
                "[ext]" = "$adtele"
                "[flow]" = "$flow"
                "[surnamelow]" = "$surnamelow"
                "[laptopname]" = "$ltname"
                "[LP]" ="$LPCoder"
            }

            ### Replace placeholders in template with variable with the below rules ###
            foreach ($key in $placeholder.keys) {
                $newdoc.Selection.Find.Execute($key, # Finds each placeholder
                $true, #Finds only if matched case
                $true, #Ensure whole placeholder is present
                $false, #Prevents wild cards
                $false,#Disregards "sounds like" words 
                $false, #Disregards different tense/forms words
                $true, #Search document from top to bottom
                1, #Searches again after getting to bottom of document
                $false, #Ignores whether the text is bold or italic
                $placeholder[$key], # Replaces the placeholders with the variables
                2) | Out-Null  #Ensures it replaces all matching instances in the document  #Doesn't output true/false for each of the above
            }
            ### Save template and close Word ###
            $ncpath = "$userinfosave\$($GetUser.DisplayName) First Day Login Info.docx" #Save location and name
            $ncdoc.SaveAs([ref]$ncpath) # Saves document directly to $ncpath
            $ncdoc.Close() # Closes document
            

            ###### Create Laptop Checklist ######
            $ltpath ="$checklistsave\$ltname.docx" #save location and name
            $lttemplate = "$templatesfolder\$ltcheckfilename" #template location
            $ltdoc = $newdoc.Documents.Add($lttemplate) #create new doc based on template
            $ltdoc.SaveAs([ref]$ltpath) # Saves document directly to $ltpath
            $ltdoc.Close() #Closes document

            $newdoc.Quit() #Quits Word

            ###### Clean up processes ######
            ### Silently Break connection between Powershell and Word ###
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($newdoc) | Out-Null
            ### Cleans memory; prevent multiple instances if script is ran again ####
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()

            ###### Output save location and document names ######
            Write-Host "Documents saved: " -ForegroundColor Yellow
            Write-Host "$($ltname).docx" 
            Write-Host "$($GetUser.DisplayName) First Day Login Info.docx"
            Write-Host ""
        }
        ###### View copy and paste items ######
        $viewmore = ReadHostTop "View predicted LifePro coder, autofilled tickets, and other items to copy and paste? (y/n)"
        if ($viewmore -eq "y"){
            ### Zendesk tickets title formatting ###
            #Employee number last 4 digits of $sam
            $employeenum = $sam.Substring($sam.Length - 4)
            Write-Host ""
            Write-Host "- Zendesk Tickets -" -ForegroundColor Yellow
            Write-Host "New Hire - $($GetUser.DisplayName) #$employeenum Title: $titleAD Start Date:"
            Write-Host "Email/Processing -- New Hire: $($GetUser.DisplayName) #$employeenum Title: $titleAD Start Date:"
            #Output Agent ticket if user is in a department that uses it
            if ($deptAD -like "Customer*" -or
                $deptAD -like "Inforce*" -or
                $deptAD -like "Worksite &*" -or
                $deptAD -like "Licensing & Contracting" -or
                $deptAD -like  "Accounting Corporate"){
                Write-Host "Agent -- New Hire: $($GetUser.DisplayName) #$employeenum Title: $titleAD Start Date:"
                Write-Host "Please add new user $($GetUser.DisplayName) to the necessary M365 group and give them access to the following:
                Job Title: $($GetUser.Title)
                Supervisor: $currentmanager
                Extension #: $($GetUser.ipPhone)
                UPN: $sam@DOMAIN.com
                Thanks!" 
            }
            ### Global access ticket: output if dept isn't Sales or Marketing ###
            if ($deptAD -notlike "*Sales*" -and 
                $deptAD -notlike "*Marketing*"){
                Write-Host ""
                Write-Host "- Software Development -" -ForegroundColor Yellow
                Write-Host "Global Access - New Hire: $($GetUser.DisplayName) #$employeenum Title: $titleAD Start Date:"
                Write-Host "Please provide Global access to new hire $($GetUser.DisplayName) ($sam) modeled after the attached user in Prod, Test, and Dev, if applicable. Thanks!"
            }
            ### Hubspot email template if user is in sales ###
            if ($deptAD -like "*Sales*"){
                Write-Host ""
                Write-Host "- Email to Beth Bruss -" -ForegroundColor Yellow
                Write-Host "Hubspot License Allocation Request"
                Write-Host "Hi Beth,"
                Write-Host "Could you please allocate a HubSpot license with $deptAD access to new user, $($GetUser.DisplayName) ($sam@DOMAIN.com, $F$surname@DOMAIN.com)?" 
                Write-Host "$($GetUser.Givenname) is going to be a $titleAD under $currentmanager. Please let me know if you have any questions. Thanks!"
            }
            ### Zendesk new user fields ###
            Write-Host ""
            Write-Host "- Zendesk New User -" -ForegroundColor Yellow
            Write-Host "$($GetUser.DisplayName)"
            Write-Host "$sam@DOMAIN.com"
            Write-Host "$F$surname@DOMAIN.com"
            Write-Host 
            
            ### IT User Inventory fields ###
            Write-Host "- IT User Inventory -" -ForegroundColor Yellow
            Write-Host "$($Getuser.GivenName)" 
            Write-Host "$($GetUser.Surname)"
            Write-Host "$sam"
            Write-Host "$($GetUser.ipPhone)"
            Write-Host "$deptAD"
            Write-Host ""
            
            ### Predicted LifePro Coder ###
            if ($deptAD -notlike "*Sales*" -and $deptAD -notlike "*Marketing*"){
                Write-Host "- Predicted LifePro Coder -" -ForegroundColor Yellow
                Write-Host "DOMAIN\$SamUp"
                Write-Host "$LPcoder
                "
            }
        }
        #Exit to main menu with any keepress
        $exityn = ReadHostTop "Exit? (y/n)"
        if($exityn -eq 'y'){
            Continue TopLevel  
        }else{
            Continue samverify
        }
    }
# (4) Signature (extAttributes)
    elseif($InitialQuestion -eq '4'){
        Write-Host "_______________________________"    
        Write-Host "Set ExtAttributes for Signature" -ForegroundColor Yellow
        Write-Host "_______________________________"
        Write-Host "What would you like to do?"
        Write-Host " "
        Write-Host "(1) Set strengths and MBTI" 
        Write-Host "(2) Set designations"
        Write-Host "(3) Exit"
        Write-Host " "
        $attribute = ReadHostTop "  >"

    ###Strengths and MBTI
        if ($attribute -eq 1){
            :bulkmenu while($true){
                Write-Host "Set strengths and MBTI for:"
                Write-Host " "
                Write-Host "(1) Multiple users"
                Write-Host "(2) One user"
                Write-Host "(3) Exit to main menu"
                Write-Host " "
                $bulkyn =ReadHostTop "  >"
                #Copy bulk table from ticket
                if ($bulkyn -eq 1){
                    :bulkusertop while($true){
                        #Prompt user to copy table from ticket
                        $continue = ReadHostTop "Copy the table from the ticket. Continue? (y/n)"
                        #if y, process clipboard data
                        if ($continue -eq 'y'){
                            Write-Host "_____________________________________________"
                            Write-Host "Preview" -ForegroundColor Yellow

                            #Assign clipboard data to clipboard
                            $table = Get-Clipboard -Raw
                            #Splits data from clipboard into lines, detects which are blank fields
                            $data = $table -split "`t|`r?`n" | Where-Object { $_.Trim() -ne '' }
                            #Starting at 0, until you run out of data, group every 8 pieces of data together, and do the below for each group
                            for ($i = 0; $i -lt $data.Count; $i += 8){
                                #Trim ensures there is no white space on either side of the variable
                                $first = $data[$i].Trim() 
                                $last = $data[$i+1].Trim() 
                                $MBTI = $data[$i+2].Trim() 
                                $s1 = $data[$i+3].Trim() 
                                $s2 = $data[$i+4].Trim() 
                                $s3 = $data[$i+5].Trim() 
                                $s4 = $data[$i+6].Trim() 
                                $s5 = $data[$i+7].Trim()
                                #Verifies if MBTI is in valid form to prevent mismatched variables and prevents continuing
                                if ($MBTI -notmatch '^[EI][NS][FT][JP]$'){
                                    Write-Host "--------------------------------"
                                    Write-Host "User: $first $last"
                                    Write-Host "MISSING OR INVALID MBTI" -ForegroundColor Red
                                    Write-Host "Paste the table from the ticket into a text editor, fix the mistake, copy it all, and then try again."
                                    Write-Host "--------------------------------"
                                    Continue bulkusertop
                                }
                                #Verifies name can be matched to a user in AD
                                $user = Get-ADUser -Filter "GivenName -eq '$first' -and Surname -eq '$last'" 
                                if(-not $user){
                                    Write-Host "--------------------------------"
                                    Write-Host "USER NOT FOUND" -ForegroundColor Red
                                    Write-Host "User: $first $last"
                                    Write-Host "Paste the table from the ticket into a text editor, fix the mistake, copy it all, and then try again."
                                    Write-Host "--------------------------------"
                                    Continue bulkusertop
                                }
                                #Assigns strengths from data to one variable with the correct formatting
                                $strengths = "$s1 | $s2 | $s3 | $s4 | $s5"
                                #Output the values that will be set in AD for preview
                                Write-Host "--------------------------------"
                                Write-Host "User: $first $last"
                                Write-Host "Strengths (extensionAttribute6): $strengths"
                                Write-Host "MBTI (extensionAttribute7): $MBTI"
                            }
                            
                            #Confirmation that the values previewed looked good
                            $continue2 = ReadHostTop "Set these attributes for the users? (y/n)"
                            if($continue2 -eq 'y'){
                                Write-Host "_____________________________________________"
                                #Using same process above, but this time set the varaibles to matching attributes
                                Write-Host "Confirmation AD Query" -ForegroundColor Yellow
                                #Assign clipboard data to clipboard
                                $table = Get-Clipboard -Raw
                                #Splits data from clipboard into lines, detects which are blank fields
                                $data = $table -split "`t|`r?`n" | Where-Object { $_.Trim() -ne '' }
                                for ($i = 0; $i -lt $data.Count; $i += 8){
                                    $first = $data[$i].Trim()
                                    $last = $data[$i+1].Trim()
                                    $MBTI = $data[$i+2].Trim()
                                    $s1 = $data[$i+3].Trim()
                                    $s2 = $data[$i+4].Trim()
                                    $s3 = $data[$i+5].Trim()
                                    $s4 = $data[$i+6].Trim()
                                    $s5 = $data[$i+7].Trim()
                                    $strengths = "$s1 | $s2 | $s3 | $s4 | $s5"
                                    # Matches first and last name to sam account to be able to write attributes
                                    $user = Get-ADUser -Filter "GivenName -eq '$first' -and Surname -eq '$last'" -Properties SamAccountName
                                    $sam= $user.SamAccountName
                                    #Set the attributes for each user as defined in the data from the clipboard
                                    Set-ADUser -Identity $sam -Replace @{extensionAttribute6 =$strengths; extensionAttribute7 =$MBTI}
                                    #Get fields again from AD to confirm what was written with Set-ADUser
                                    $user = Get-ADUser -Filter "GivenName -eq '$first' -and Surname -eq '$last'" -Properties extensionAttribute6, extensionAttribute7, DisplayName
                                    Write-Host "--------------------------------"
                                    Write-Host "User: $($user.DisplayName)"
                                    Write-Host "SAM: $sam"
                                    Write-Host "Strengths (extensionAttribute6): $($user.extensionAttribute6)"
                                    Write-Host "MBTI (extensionAttribute7): $($user.extensionAttribute7)"
                                }
                            }else{
                                Continue bulkusertop
                            }
                            Write-Host "_____________________________________________"
                            Write-Host "Attributes were written to AD  as shown above" -ForegroundColor Green
                            Write-Host "_____________________________________________"
                            #Brings back to start of loop asking if data was copied
                        }else{
                            Write-Host "Returning to main menu." -ForegroundColor Yellow
                            Continue TopLevel
                        }
                    }
                }
                #One user
                if ($bulkyn -eq 2){
                    $fullname = ReadHostTop "Enter the Firstname Lastname or sam (ab1234) of the user whose strengths and/or MBTI you would like to modify"
                    #Named loop so it can come back to top
                    :mbtitop while($true){ 
                        #eliminates white space from name
                        $fulltrim = $fullname.Trim()
                        #splits first and lastname and assigns variables
                        $names = $fulltrim -split '\s+'
                        $first = $names[0]
                        $last = $names[-1]
                        $user = Get-ADUser -Filter "((GivenName -eq '$first') -and (Surname -eq '$last')) -or (SamAccountName -eq '$first')" -Properties SamAccountName, extensionAttribute3, extensionAttribute6, extensionAttribute7 -ErrorAction SilentlyContinue
                        $sam = $user.SamAccountName
                        #If a user is found
                        if ($user){
                            :oneusertop while($true){
                                $user = Get-ADUser -Identity $sam -Properties extensionAttribute6, extensionAttribute3, extensionAttribute7
                                Write-Host "Select what to modify for $($fullname):"
                                Write-Host " "
                                Write-Host "(1) Strengths"
                                Write-Host "(2) MBTI"
                                Write-Host "(3) Modify a different user"
                                Write-Host " "
                                $opt12 = ReadHostTop "  >"
                                if ($opt12 -eq 1){
                                    Write-Host "Current strengths:$($user.extensionAttribute6)"
                                    $ext6 = (ReadHostTop "What would you like the new strengths to be?").Trim() 
                                    #accounts for blank input
                                    if ([string]::IsNullOrWhiteSpace($ext6)) {
                                        Write-Host "No strengths entered. No changes were made." -ForegroundColor Yellow
                                    }
                                    else {
                                       Set-ADUser -Identity $sam -Replace @{extensionAttribute6=$ext6} #changes ext6
                                    }
                                    $user = Get-ADUser -Identity $sam -Properties extensionAttribute6 -ErrorAction SilentlyContinue #requery                           
                                    Write-Host "Current strengths are now:$($user.extensionAttribute6)" -ForegroundColor Green
                                    Continue oneusertop
                                }
                                elseif ($opt12 -eq 2){
                                    Write-Host "Current MBTI:$($user.extensionAttribute7)"
                                    $ext7 = ReadHostTop "What would you like the new MBTI to be?" 
                                    #accounts for blank input
                                    if ([string]::IsNullOrWhiteSpace($ext7)) {
                                        Write-Host "No strengths entered. No changes were made." -ForegroundColor Yellow
                                    }
                                    else{
                                        Set-ADUser -Identity $sam -Replace @{extensionAttribute7=$ext7} #changes ext7
                                    }
                                    $user = Get-ADUser -Identity $sam -Properties extensionAttribute7 -ErrorAction SilentlyContinue #reuqery
                                    Write-Host "Current MBTI is now:$($user.extensionAttribute7)" -ForegroundColor Green
                                    Continue oneusertop
                                }
                                else{
                                    Continue bulkmenu
                                }
                            }
                        }else{ #error handling
                            $fullname=ReadHostTop "User not found. Please check spelling and enter the Firstname Lastname of the user"
                        }
                    }
                }
                if ($bulkyn -notin 1,2){
                    Continue TopLevel
                }
            }
        }
    ### Designations
        elseif ($attribute -eq 2){
            $fullname = ReadHostTop "Enter the Firstname Lastname or sam (ab1234) of the user whose designations you would like to change or add to"
            #Named loop so it can come back to top
            :destop while($true){ 
                #eliminates white space from name
                $fulltrim = $fullname.Trim()
                #splits first and lastname and assigns variables for ease of use
                $names = $fulltrim -split '\s+'
                $first = $names[0]
                $last = $names[-1]
                $user = Get-ADUser -Filter "((GivenName -eq '$first') -and (Surname -eq '$last')) -or (SamAccountName -eq '$first')" -Properties SamAccountName, extensionAttribute3 -ErrorAction SilentlyContinue
                $sam = $user.SamAccountName
                
                #If a user is found
                if ($user){
                    Write-Host "Current designation:$($user.extensionAttribute3)"
                    $ext3 = ReadHostTop "What would you like the new designation to be?" 
                    #only processes change if it starts with ', '
                    if ($ext3.StartsWith(", ")){
                        Set-ADUser -Identity $sam -Replace @{extensionAttribute3=$ext3} #sets new ext3
                        $user = Get-ADUser -Identity $sam -Properties extensionAttribute3 -ErrorAction SilentlyContinue #requeries user for current designation
                        Write-Host "Current designation is now:$($user.extensionAttribute3)" -ForegroundColor Green
                        $mainyn = ReadHostTop "Exit to main menu? (y/n)"
                        if($mainyn -eq 'y'){
                            Continue TopLevel #main menu
                        }
                        else{
                            Continue desTop #reenter designation
                        }
                    }
                    else{ #error handling
                        Write-Host "Please try again. Input does not start with comma space ', '" -ForegroundColor Red
                    }
                }    
                else{ #error handling
                    $fullname=ReadHostTop "User not found. Please check spelling and enter the Firstname Lastname of the user"
                }
                
            }
        }
        else{
            Write-Host "Returning to main menu..."
            Continue TopLevel
        }
    }
# (5) Sign in
    elseif($initialQuestion -eq '5'){
        :signtop while($true){
            $signopt = ReadHostTop "Choose an option:

            (1) Check password expiration date
            (2) View last time credentials were recorded to be successfully used
            (3) Exit to main menu 
            "
            #Check password expiration date
            if ($signopt -eq 1){
            :sign1top while ($true){
                    #Checks if username is valid
                    $userin = ReadHostTop "Enter the username (ab1234) of the user whose password expiration you would like to check" 
                    $verify = Get-ADUser -Identity $userin -ErrorAction SilentlyContinue

                    #if username is valid
                    if ($verify){
                        #Queries password expiration date, then converts it to a readable format. Native format is a 64 bit int Windows Filetime in nanoseconds
                        $usersign = Get-ADUser -Identity "$userin" -Server "DOMAIN.local" -Properties  "msDS-UserPasswordExpiryTimeComputed" | Select-Object "msDS-UserPasswordExpiryTimeComputed"
                        $expdate = [DateTime]::FromFileTime($usersign."msDS-UserPasswordExpiryTimeComputed")
                        Write-Host ""
                        Write-Host "Password expiration date: $expdate" -ForegroundColor Yellow
                        Write-Host ""
                        Continue signtop #back to submenu
                    }
                    #if username is not valid, brings back to top to try again
                    else{
                        Write-Host "User not found. Please try again (ab1234)" -ForegroundColor Red
                        Continue sign1top
                    }
                }
            }
            #View last authentication 
            elseif ($signopt -eq 2){
                :sign2top while ($true){
                    Write-Host "*Depending on sync with AD, it is possible the date/time listed is not the most recent."
                    $userin = ReadHostTop "Enter the username (ab1234) of the user whose last recorded successful sign in date you would like to check" 
                    $verify = Get-ADUser -Identity $userin -ErrorAction SilentlyContinue
                    
                    #if user exists
                    if ($verify){
                         #Queries password expiration date, then converts it to a readable format. Native format is a 64 bit int Windows Filetime in nanoseconds
                        $usersign = Get-ADUser -Identity "$userin" -Server "DOMAIN.local" -Properties  LastLogon | Select-Object LastLogon
                        #[Datatime] method :: calling property FromFileTime to convert FileTime to readable date referencing the data gathered from $usersign
                        $authdate = [DateTime]::FromFileTime($usersign.LastLogon)
                        Write-Host ""
                        Write-Host "Last recorded successful authentication: $authdate" -ForegroundColor Yellow
                        Write-Host ""
                        Continue signtop
                    }
                    #if user doesn't exist
                    else{
                        Write-Host "User not found. Please try again (ab1234)" -ForegroundColor Red
                        Continue sign2top
                    }
                }
            }
            #return to top with any input other than 1 or 2
            else{
                Continue TopLevel
            }
        }
    }
### MACHINE ###
# (8) CMD 
    elseif ($initialQuestion -eq '8'){
        :cmdtop While($true){
            #pings computer to test if it is online so script can run
            $computer = ReadHostTop "What is the name of the computer whose Command Prompt you would like to enter?"
            $ping = Test-Connection -ComputerName $computer -Count 1 -Quiet -ErrorAction SilentlyContinue
            #if the computer is connected
            if ($ping -eq $true){
                :cmdcred while ($true){
                    #
                    $session = $null #ensures failed session attempts aren't stored
                    $username = "DOMAIN\adminacct" #for credentials. Decreases time because it isn't creating a new user profile at c:\users
                    $credyn = ReadHostTop "Continue to enter adminacct password? (y/n)" #Stop in case password is entered wrong. Prevents lockout from only one incorrect attempt
                    if($credyn -eq 'y'){
                        #prompts for credentials with adminacct autofilled with the message enter password for adminacct
                        $cred = Get-Credential -Username $Username -Message "Enter password for adminacct"
                        #creates new pssession on remote computer using entered credentials
                        $session = New-PSSession -ComputerName $computer -Credential $cred -ErrorAction SilentlyContinue
                        #Continues if session can be connected (password is valid, computer is connected)
                        if ($session){
                            break
                        }
                        #Takes back to enter credentials again. Prevents rest of script authenticating with wrong password and locking out
                        else{
                            Write-Host "Unable to establish session. Please verify password and computer connectivity." -ForegroundColor Red
                            Continue cmdcred
                        }
                    }else{
                        Continue TopLevel
                    }

                }

                Write-Host "!WARNING!:" -ForegroundColor Yellow
                Write-Host "Commands and installers ran from this script may hang if they require any interaction from the console or a GUI."
                Write-Host "NOTE:" -ForegroundColor Yellow
                Write-Host "Commands will be executed from C:\HelpdeskFiles every time by default."
                Write-Host "To execute from a different directory, precede the command with the path in quotes like the example below."
                Write-Host '>>>: "C:\Program Files\Ivanti\Ivanti Cloud Agent\STAgentCTL.exe" dispatch --index 2'
                Write-Host "EXIT:" -ForegroundColor Yellow
                Write-Host "Enter 'exit' to return to main menu."
                Write-Host ""
                Write-Host "Entering CMD session on $computer..."
                Write-Host ""
                #Loop that will take terminal input, and execute it on the remote machine. If exit is type, ensures session is removed
                while ($true){
                    $userinputcmd = ReadHostTop "\\$computer\C$\HelpdeskFiles >>>"
                    #closes session if exiting
                    if ($userinputcmd -eq "exit"){
                        Remove-PSSession $session
                        Continue TopLevel
                    }
                    #Runs command from previously established session
                    else {Invoke-Command -Session $session -ScriptBlock{
                        #sets directory location to c:\HelpdeskFiles
                        Set-Location "C:\HelpdeskFiles"
                        #Tells remote computer to run cmd.exe with /c command and then user input
                        cmd.exe /c $using:userinputcmd
                        }
                    }
                }
            }
            #if laptop name isn't pingable, returns to entering computer name again
            else{
                Write-Host "Computer name is invalid or offline. Please verify spelling and connectivity, then try again." -ForegroundColor Red
                Continue cmdtop
            }
        }
    }
# (9) Event Viewer
    elseif($InitialQuestion -eq '9'){
        Write-Host "_______________________________________"
        Write-Host "Export Events From Event Viewer to CSV" -ForegroundColor Yellow
        Write-Host "_______________________________________"
        :Eventtop while($true){
            $compname = ReadHostTop "Enter computer name"
            if (-not $compname){
                Write-Host "No input detected, please try again" -ForegroundColor Red
                Continue Eventtop
            }
        ###### Verify computer connectivity or reprompt ######
            while($true) {
                $ping = Test-Connection -ComputerName $compname -Count 1 -Quiet -ErrorAction SilentlyContinue
                if ($ping){
                    Write-Host ""
                    Write-Host "Success: $compname is online" -ForegroundColor Green
                    Write-Host ""
                    break
                } else {
                    Write-Host "Computer not reachable on network. Please verify spelling and connectivity, then try again" -ForegroundColor Red
                    Continue Eventtop
                }
            }

        ####### Select Event Category ####### 
            $logcat = ReadHostTop "What categories of events would you like to collect?

            (1) Application
            (2) Security
            (3) Setup
            (4) System
            (5) Application and System (default)
            (6) All
            
            "
            ### Match user input to event type ###
            switch ($logcat) {
                1 {$logcat = $logname = "Application"}
                2 {$logcat = $logname = "Security"}
                3 {$logcat = $logname = "Setup"}
                4 {$logcat = $logname = "System"}
                5 {
                    $logcat = @("Application", "System")
                    $logname = "Application and System"
                }
                6 {
                    $logcat =@("Application", "Security", "Setup", "System")
                    $logname = "All"
                }
                default {
                    $logcat = @("Application", "System")
                    $logname = "Application and System"
                }
            }
        ####### Filter by severity ####### 
            $loglev = ReadHostTop "What level(s) severity of events would you like to collect? 

            (1) Critical
            (2) Error
            (3) Warning
            (4) Information
            (5) Critical and Error (default)
            (6) Critical, Error, and Warning
            (7) All 

            "
            ### Match user input to log severity level and name ###
            switch ($loglev) {
                1 {
                    $loglev=1
                    $logsev= "Critical"
                }
                2 {
                    $loglev=2
                    $logsev= "Error"
                }
                3 {
                    $loglev=3
                    $logsev= "Warning"
                }
                4 {
                    $loglev=4
                    $logsev= "Information"
                }
                5 {
                    $loglev=1,2
                    $logsev= "Critical and Error"
                }
                6 {
                    $loglev=1,2,3
                    $logsev= "Critical, Error, and Warning"
                }
                7 { 
                    $loglev=1,2,3,4
                    $logsev= "Events"
                    }
                default {
                    $loglev=1,2
                    $logsev= "Critical and Error"
                }
            }
        ###### Exporting events based on the user defined variables ######
            ### While loops to reprompt if invalid input ###
        
            while($true){
                #### Define date/time for file name ###
                $date= Get-Date -Format "MM-dd_hh.mm"
                ### Define how to filter events by time ###
                $scope=ReadHostTop "When would you like to get events from?
            (1) Get the most recent events
            (2) Get events from a specific time frame
            "
                ### If user entered 1, export most recent events based on defined max amount of events ###
                if ($scope -eq 1){
                    $logmax=ReadHostTop "Enter the max number of events you would like to collect"
                    ### Get events based on the user defined variables with the specified columns and output to a csv file named based on user input ###
                    $time = Get-Date
                    Write-Host "Exporting events since $time..."
                    $events = Get-WinEvent -ComputerName $compname -FilterHashtable @{
                        LogName=$logcat
                        Level=$loglev
                    } -MaxEvents $logmax -ErrorAction SilentlyContinue
                    if ($events){
                        $events | Select-Object TimeCreated, LogName, LevelDisplayName, ProviderName, Message, Id, ActivityId |Export-CSV -path "$eventsave\$compname $logname $logsev $date.csv" -ErrorAction SilentlyContinue
                        Write-Host "
                        Event export saved to $Eventsave
                        " -ForegroundColor Yellow
                        break
                    }else{
                        Write-Host "No events found matching this criteria." -ForegroundColor Red
                        
                        Continue Eventtop
                    }
                ### If user enters 2, prompt to define start date and time ###
                }elseif ($scope -eq 2){
                    ### If $start is in correct date format continue, if not give error message and reprompt ###
                    while($true){
                    $start=ReadHostTop "Enter the start date and time (MM/DD/YY HH:MM pm)"    
                    if ($start -as [DateTime]){
                        break
                        }else {
                            Write-Host "Invalid format. Enter the start date and time in format  MM/DD/YY HH:MM pm   Example: 7/20/26 2:00 pm" -ForegroundColor Red
                        }
                    }
                    ### If $end is in date format export the events, if not give error message and reprompt ###
                    while($true){
                    $end=ReadHostTop "Enter the end date and time (MM/DD/YY HH:MM pm)"
                    if ($end -as [DateTime]){
                        $time = Get-Date
                        Write-Host "Exporting events since $time..."
                        ### Get events based on the user defined variables with the specified columns and output to a csv file named based on user input ###
                        $events = Get-WinEvent -ComputerName $compname -FilterHashtable @{
                            LogName=$logcat
                            Level=$loglev
                            StartTime=$start
                            EndTime=$end
                        }  -ErrorAction SilentlyContinue
                        if($events){
                            
                            $events | Select-Object TimeCreated, LogName, LevelDisplayName, ProviderName, Message, Id, ActivityId |Export-CSV -path "$eventsave\$compname $logname $logsev $date.csv"
                            Write-Host "
                            Event export saved to $eventsave
                            " -ForegroundColor Yellow
                            break
                        }else{
                            Write-Host "No events found matching this criteria." -ForegroundColor Red
                            Continue Eventtop
                        }
                    }else{
                            Write-Host "Invalid format. Enter the end date and time in format MM/DD/YY HH:MM pm   Example: 7/20/26 2:00 pm" -ForegroundColor Red
                    }
                    
                    }
                break
                    ### Give error message and reprompt if user entered anything other than 1 or 2 ###
                }else{
                    Write-Host "Invalid input: Please enter 1 or 2" -ForegroundColor Red
                }    
            }
            $exityn =ReadHostTop "Exit? (y/n)"
            if ($exityn -eq 'y'){
                Continue TopLevel
            }else{
                Continue Eventtop
            } 
        }
    }
# (12) Restart Services
    elseif ($InitialQuestion -eq '12'){
        :restartservice while($true){
            $Computer = ReadHostTop "What computer do you want this script to run on?"
            $ping = Test-Connection -ComputerName $computer -Count 1 -Quiet -ErrorAction SilentlyContinue
            ###### Verify computer connectivity or reprompt ######
            if ($ping -eq "True"){
                Write-Host "Success: $computer is online" -ForegroundColor Green
                Write-Host "Listing services..."
                # Create session on remote computer
                $s = New-PSSession -ComputerName $Computer
                
                $remoteservices = Invoke-Command -Session $s {Get-CimInstance Win32_Service} | Select-Object Name, State,  ProcessID, StartMode, DisplayName
                #Output remote computer's services, and make each column fully visisble
                $remoteservices | format-table -autosize
                Write-Host "NOTE: Restarting a stopped service will start the service." -ForegroundColor Yellow
                Write-Host "      Restarting a service with startup type 'Disabled' will change the service startup type to 'Manual'" -ForegroundColor Yellow
                while($true){
                    $service = ReadHostTop "What is the name of the service you would like to restart?"
                    #Tries to match the user input to name of service on computer
                    $servcheck = $remoteservices | Where-Object {$_.Name -eq "$service"}
                    #Restarts service if service is valid name, otherwise prompts to reenter the name
                    if($servcheck){
                        $servcheck | Select-Object Name, State, ProcessID, StartMode, DisplayName | format-table -Autosize
                        #On the remote session
                        Invoke-Command -Session $s {
                            ### Stopping Service ###
                            Write-Host "Stopping service..." -ForegroundColor Yellow
                            # Scope modifier $using. allows the local variable to be used in remote session
                            $svc = Get-Service -Name $using:service
                            #gets pid
                            $svcpid =  Get-CimInstance Win32_Service -Filter "Name='$using:service'"
                            if ($svcpid.StartMode -eq "Disabled") {
                                    Write-Host "Service startup type is Disabled. Changing to Manual." -ForegroundColor Yellow
                                    Set-Service -Name $using:service -StartupType Manual #changes to manual to be able to start script
                            }
                            if($svcpid.ProcessID -gt 0){
                            #Query start time before stopping service, otherwise output is blank
                                $starttime = (Get-Process -ID (Get-CimInstance Win32_Service -Filter "Name='$using:service'").ProcessId).StartTime
                            }
                            else{
                                $starttime = $null
                            }
                            #Stops service
                            Stop-Service -Name $using:service -Force -WarningAction SilentlyContinue
                            $svc.WaitForStatus('Stopped', '00:04:00')
                            #Refreshes the vairables
                            $svc = Get-Service -Name $using:service
                            # Verification if the service was stopped, or already stopped
                            if ($starttime){
                                Write-Host "Service status: $($svc.Status)" 
                                Write-Host "Last time service was started: $starttime"
                            }
                            else{
                                Write-Host "Service was already stopped."
                            }
                            ### Starting Service ###
                            Write-Host "Starting service..." -ForegroundColor Yellow 
                            Start-Service -Name $using:service -WarningAction SilentlyContinue
                            $svc.WaitForStatus('Running', '00:04:00') #time out after 4 minutes
                            $svc = Get-Service -Name $using:service #query service again to get status
                            Write-Host "Service status: $($svc.Status)"
                            #Verification that service was started again
                            $starttime = (Get-Process -ID (Get-CimInstance Win32_Service -Filter "Name='$using:service'").ProcessId).StartTime
                            Write-Host "Service restarted at $starttime"
                        }
                        Remove-PSSession $s
                        $mainyn = ReadHostTop "Exit to main menu? (y/n)"
                        if($mainyn -eq 'n'){
                            Continue restartservice #Can restart another service
                        }
                        else{
                            Continue TopLevel #Return to main menu
                        }
                    }
                    else{
                        Write-Host "Invalid service name. Please enter the name (left column) of the service again." -ForegroundColor red
                    }
                }
                break
            }
            else {
                Write-Host "Computer not reachable on network. Please verify spelling and connectivity, then try again." -ForegroundColor Red
            }
        }
    }
# (14) Software
    elseif($initialQuestion -eq '14'){
        :softtop while ($true){

            #For end of process reference
            $Exitcodekey ="
                Exit Code Reference:
                0      Success
                1603   Fatal Error - Uninstallation in progress; Permission denied; Dependency missing
                1605   Program to be uninstalled not found (check version)
                1610   Another installation is already running
                1619   File not found, or could not be opened
                3010   Success, reboot required"

            #submenu 1
            $softchoice = ReadHostTop "Choose the software you would like to uninstall or install on a remote computer on the network:
            
            (1) Carbon Black
            (2) Digital Guardian
            (3) Exit
            
            NOTE: User will have no indication that anything is happening, nor be prompted to reboot
            "
            ### Carbon Black
            if ($softchoice -eq 1){
                :cbtop while($true){
                    $CBchoice = ReadHostTop "Choose an option:
                    (1) Remove Carbon Black
                    (2) Install Carbon Black
                    (3) Select a different program
                    "
                    if ($CBchoice -notin 1,2){
                        Continue softtop
                    }
                    # YOUR local copies's File Paths #
                    $CBPath = "$Programs\CarbonBlack" #Local folder name
                    $CBmsi = "$CBPath\$CBmsiName" #Full file path with msi file name 
                    #REMOTE computer's copy of the msi
                    $cbcopymsi = "C:\HelpdeskFiles\$CBmsiName" #path of cbmsi on remote computer
                    
                    #test computer is online with ping
                    $Comp = ReadHostTop "What is the name of the computer you would like to perform the action on?"
                    $ping = Test-Connection -ComputerName $comp -Count 1 -Quiet -ErrorAction SilentlyContinue
                    if ($ping -eq $true){
                        #Uninstall CB
                        #Defining where the file needs copied to 
                        $dest ="\\$comp\c$\HelpdeskFiles" 
                        If ($cbchoice -eq 1){
                            $cbuninstallyn = ReadHostTop "Remove Carbon Black from $($comp)? (y/n)"
                            if($cbuninstallyn -eq 'y'){
                                $date = Get-Date
                                Write-Host "Please wait, uninstalling Carbon Black from $($comp) since $date..."
                                Invoke-Command -ComputerName $comp -ScriptBlock{
                                    #Variable to get quotes being interpreted correctly
                                    #uninstall carbon black cloud without anything on user's screen
                                    $newarg =  '--uninstall --product cbc --quiet'
                                    #starts the CB uninstall program in user's program files with arguments above. 
                                    #-Wait makes the script wait until the process is finished -Windows Style Hidden ensures user doesn't see anything; PassThru ensures it captures the exit code
                                    $cbuninstallp = Start-Process -FilePath "C:\Program Files\Broadcom\Endpoint Security Agent\CurrentVersion\bin64\seasetup.exe" -ArgumentList "$newarg" -Wait -WindowStyle Hidden -PassThru
                                    #get the exit code of the process above
                                    $exitcode = $cbuninstallp.Exitcode
                                    Write-Host "NOTE: If the system cannot find the file specified, Carbon Black is likely not installed. 
                                    It references C:\Program Files\Broadcom\Endpoint Security Agent\CurrentVersion\bin64\seasetup.exe"
                                    Write-Host "$using:ExitCodeKey" #exit code reference
                                    Write-Host "Exit Code: $exitcode"
                                 
                                }
                                $mainyn = ReadHostTop "Exit to main menu? (y/n)"
                                if ($mainyn -eq 'n')
                                {
                                    Continue softtop
                                }
                                else{
                                    Continue TopLevel
                                }
                            }else{
                                Continue softtop
                            }
                        }
                        #Install CB
                        elseif ($cbchoice -eq 2){
                            $cbinstallyn = ReadHostTop "Install Carbon Black on $($comp)? (y/n)"
                            if ($cbinstallyn -eq 'y'){    
                                $date = Get-Date
                                Write-Host "Please wait, installing Carbon Black on $($comp) since $date..."
                                #copies CB msi from your computer, and pastes it to remote computers helpdeskfiles, 
                                Copy-Item -Path $cbmsi -Destination $dest
                                Invoke-Command -ComputerName $comp -ScriptBlock{
                                    #argument varaibles for quote interpretation; $using allows local variable to be used in remote session
                                    $cbinstallarg = $using:cbcopymsi
                                    #starts the ms installer with arguments to "/i install cbmsi with cb code qn quietly, does not prompt for restart"
                                    #-Wait for process to finish before moving on; Window-Style Hidden do not display anything for user; -PassThru captures exit code
                                    $cbinstallp = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $cbinstallarg $compcode /qn /norestart" -Wait -WindowStyle Hidden -PassThru
                                    Write-Host "$using:ExitCodeKey" #exit code reference
                                    Write-Host "Exit Code: $($cbinstallp.ExitCode)" #exit code of above process
                                }
                                $mainyn = ReadHostTop "Exit to main menu? (y/n)"
                                if ($mainyn -eq 'n')
                                {
                                    Continue softtop
                                }
                                else{
                                    Continue TopLevel
                                }
                            }else{
                                Continue softtop
                            }
     
                        }
                        else{
                            Continue softtop
                        }
                    }else{
                        Write-Host "Computer not reachable on network. Please check spelling and connectivity and try again." -ForegroundColor Red
                        Continue cbtop
                    }
                    
                }
            }    
            ### Digital Guardian
            elseif ($softchoice -eq 2){
                :dgtop While ($true){
                   
                    $DGchoice = ReadHostTop "Choose an option:
                    (1) Remove Digital Guardian
                    (2) Install Digital Guardian
                    (3) Select a different program
                    "
                    if ($DGchoice -notin 1,2){
                        Continue softtop
                    }
                    #Paths to YOUR local copies of the files
                    $DGPath = "$Programs\DigitalGuardian" #To folder containing the below
                    $DGmsiPath = "$($DGPath)\$($DGmsi)" #Full installer path with file name
                    $dgtermpath = "$DGPath\$DGTerm" #Full Terminator path with file name
                    $dgcleanpath ="$DGPath\$DGClean" #Full DGCleaner path with file name
                    
                    #Paths to the REMOTE computer's local copies of the files
                    $dgcopymsi = "C:\HelpdeskFiles\$DGmsi" #Remote computer's copy of installer
                    $dgcopyterm = "C:\HelpdeskFiles\$DGterm" #Remote computer's copy of Terminator
                    $dgcopyclean = "C:\HelpdeskFiles\$DGClean" #Remote computer's copy of DGCleaner
                    
                    $Comp = ReadHostTop "What is the name of the computer you would like to perform the action on?"
                    $ping = Test-Connection -ComputerName $comp -Count 1 -Quiet -ErrorAction SilentlyContinue
                    if ($ping -eq $true){
                    #Uninstall DG
                        $dest ="\\$comp\c$\HelpdeskFiles" 
                        If ($dgchoice -eq 1){
                            $dguninstallyn = ReadHostTop "Remove Digital Guardian from $($comp)? (y/n)"
                            if($dguninstallyn -eq 'y'){
                                $date = Get-Date
                                Write-Host "Please wait, uninstalling Digital Guardian from $($comp) since $date..."
                                #Copies DG terminator and cleaner to users computer from yours
                                Copy-Item -Path $dgtermpath -Destination $dest -ErrorAction SilentlyContinue
                                Copy-Item -Path $dgcleanpath -Destination $dest -ErrorAction SilentlyContinue
                                Invoke-Command -ComputerName $comp -ScriptBlock{
                                    #argument for quote interpretation; $using to use local variable on remote computer; refers to remote user's copy of the file
                                    $dgtermarg = $using:dgcopyterm
                                    #Runs the terminator.exe using the argument /c command at $dgtermarg file path with DG company code
                                    $dgtermp= Start-Process -FilePath "cmd.exe" -ArgumentList "/c $dgtermarg $dgcode" -Wait -WindowStyle Hidden -PassThru
                                    #argument for quote interpretation; $using to use local variable on remote computer; refers to remote user's copy of the file
                                    $dgcleanarg = $using:dgcopyclean
                                    #Runs the DGcleaner.exe using the argument /c command at $dgtermarg file path with DG company code -forces with -nr 
                                    $dgcleanp= Start-Process -FilePath "cmd.exe" -ArgumentList "/c $dgcleanarg -force -s -nr" -Wait -WindowStyle Hidden -PassThru
                                    Write-Host "$using:Exitcodekey"
                                    Write-Host "DG Terminator Exit Code: $($dgtermp.ExitCode)"
                                    Write-Host "DG Cleaner Exit Code: $($dgcleanp.ExitCode)"
                                }
                                $mainyn = ReadHostTop "Exit to main menu? (y/n)"
                                if ($mainyn -eq 'n')
                                {
                                    Continue softtop
                                }
                                else{
                                    Continue TopLevel
                                }
                            }else{
                                Continue softtop
                            }
                        }
                    #Install DG
                        elseIf ($dgchoice -eq 2){ 
                            $dginstallyn = ReadHostTop "Install Digital Guardian on $($comp)? (y/n)"    
                            if($dginstallyn -eq 'y'){
                                $date = Get-Date
                                Write-Host "Please wait, installing Digital Guardian on $($comp) since $date..."
                                #Copies DG msi from your computer and copies it user's computer
                                Copy-Item -Path $dgmsipath -Destination $dest -ErrorAction SilentlyContinue
                                #Runs ps command on remote computer
                                Invoke-Command -ComputerName $comp -ScriptBlock{
                                        #Variable for quote interpretation; $using allows local variable to be used remotely
                                        $dgcopyarg= $using:dgcopymsi
                                        #starts the ms installer with arguments to "/i install dgmsi qn quietly, does not prompt for restart"
                                        #-Wait for process to finish before moving on; Window-Style Hidden do not display anything for user; -PassThru captures exit code
                                        $dginstallp = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $dgcopyarg /qn /norestart" -Wait -WindowStyle Hidden -PassThru
                                        Write-Host "$using:exitcodekey"
                                        Write-Host "Exit Code: $($dginstallp.ExitCode)"
                                        Write-Host "If successful, have user restart to complete installation."
                                }
                                $mainyn = ReadHostTop "Exit to main menu? (y/n)"
                                if ($mainyn -eq 'n')
                                {
                                    Continue softtop
                                }
                                else{
                                    Continue TopLevel
                                }
                            }else{
                                Continue softtop
                            }
                        }
                        else{
                            Write-Host "Returning to menu."
                            Continue softtop                 
                        }   
                    }else{
                        Write-Host "Computer not reachable on network. Please check spelling and connectivity and try again." -ForegroundColor Red
                        Continue dgtop
                    } 
                }
            }
            else{
                Continue TopLevel
            }
        }
    }
# (15) Storage
    elseif($InitialQuestion -eq '15'){
                           
        #Function to convert units that are natively output into bits; Calls Round property of Math method to lessen decimal points
        function ConvertUnit {
            param($value)
            if ($null -eq $value) { #If storage value is empty, report it as 0KB
                "0 KB"
            }
            elseif ($Value -ge 1GB) { #If storage is bigger or equal to 1 GB output in units of GBs
                "$([math]::Round($value/ 1GB)) GB"
            }
            elseif ($Value -ge 1MB) { #If it isn't greater or equal to 1GB, check if it is greater or equal to 1 MB, if so output units in 1MB
                "$([math]::Round($value/ 1MB)) MB"
            }
            else {
                "$([math]::Round($value/ 1KB)) KB" #If it doesn't meet any of the conditions above, output size in units of KB
            }
        }
        #Calculates storage
        function Get-Size {
            param(
                [string]$Path # Allows to be used like Get-Size -Path $path
            )
            Invoke-Command -Session $session -ArgumentList $Path -ScriptBlock {
                param($Path) #allows local variable to be used in remote session like $using:variable
                #Get all of the files under a path, then measure their size and add that size all together
                (Get-ChildItem $Path -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
            }
        }
         #Deletes all files at given path
         
        function Delt{
            param (
                [string]$path
            )     
            if(-not [string]::IsNullOrWhiteSpace($Path)){
                Invoke-Command -Session $session -Argumentlist $path -ScriptBlock {
                    param($path)
                #Variable that will allow to check if item is folder or file
                    $itemtype = Get-Item $path -Force -ErrorAction Stop
                    #if item is a folder, delete all items within the folder
                    if($itemtype.PSIsContainer){
                        #delete all items within the folder
                        Remove-Item "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                    #if item is a file, delete the file
                    }else{
                            Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
                    }
                    Write-Host "If items remain, file may be in use."
                }
            } else{
                Write-Host "No items found to delete." -ForegroundColor Red
                Continue storagecalc
            }   
        }        
                    
        :storage while($true){
            $Computer = ReadHostTop "What is the name of the computer whose storage you would like to check?"
            $ping = Test-Connection -ComputerName $computer -Count 1 -Quiet -ErrorAction SilentlyContinue
            ###### Verify computer connectivity or reprompt ######

            if ($ping -eq "True"){
                Write-Host "Success: $computer is online" -ForegroundColor Green
                :storagecred while ($true){
                    $session = $null #ensures failed session attempts aren't stored
                    $username = "Domain\adminacct" #for credentials. Decreases time because it isn't creating a new user profile at c:\users
                    $credyn = ReadHostTop "Continue to enter adminacct password? (y/n)" #Stop in case password is entered wrong. Prevents lockout from only one incorrect attempt
                    if($credyn -eq 'y'){
                         #prompts for credentials with adminacct autofilled with the message enter password for adminacct
                        $cred = Get-Credential -Username $Username -Message "Enter password for ad"
                        #Continues if session can be connected (password is valid, computer is connected)
                        try{
                             #creates new pssession on remote computer using entered credentials
                            $session = New-PSSession -ComputerName $computer -Credential $cred -ErrorAction Stop
                            break
                        }
                        catch{
                            #Takes back to enter credentials again. Prevents rest of script authenticating with wrong password and locking out
                            Write-Host "Unable to establish session. Please verify password and computer connectivity." -ForegroundColor Red
                        }
                        
                    }else{
                        Continue Toplevel
                    }

                }
                
                :storagecalc while ($true){
                Write-Host " "  
                Write-Host "Calculating storage..."
                Write-Host " "    

                    $remotetotal = Invoke-Command -Session $session -ScriptBlock { 
                        #Get-CimInstance used for system info; DriveType=3 pulls only phsyical disks
                        $Disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
                        $Total = ($Disks | Measure-Object -Property Size -Sum).Sum #Calculates total Size of storage
                        $Free  = ($Disks | Measure-Object -Property FreeSpace -Sum).Sum #Calculates total Free space
                        $Used  = $Total - $Free #calculates used space from above variables

                        #Allows output to be output and used in local session
                        [PSCustomObject]@{
                            total = $total
                            used = $used
                            free = $free
                        }
                    }   

                    $installerpath = "C:\Windows\Installer"
                    $installer = Get-size $installerpath
                    $patchpath = "C:\ProgramData\Ivanti\Ivanti Cloud Agent\Agent\Patch\PatchData"
                    $patch = Get-size $patchpath
                    $adobepath = "C:\ProgramData\Adobe\ARM"
                    $adobe =  Get-size $adobepath
                    #$testpath = "C:\Temp\Test"
                    #$test = Get-size $testpath
                    
                    #Ost will work differently since it is an individual file, not a folder
                    $remoteculp = Invoke-Command -Session $session -ScriptBlock { 
                        #Finds file of all ost files, sorts them by highest size, then takes the first one of that list with the highest size and returns it
                        $ostfile= (Get-ChildItem -Path "C:\Users\*\AppData\Local\Microsoft\Outlook\*.ost" -File -Force -ErrorAction SilentlyContinue | Sort-Object -Property Length -Descending | Select-Object -First 1)
                        #If an ost file exists
                        if ($null -ne $ostfile){
                            $ostpath = $ostfile.FullName #finds full path of the ost file it found to be the largest
                            $ostpathtrim= $ostpath.Trim() -replace ':', '$' #Replaces file path colon for a dollar sign so path could easily be copied to File Explorer for hidden shared
                            $ost = (Get-Item $ostpath -ErrorAction SilentlyContinue).Length #Gets size of largest ost file
                            
                            #Allows variables above defined remotely, to be output in local session
                            [PSCustomObject]@{
                                ostfile = $ostfile
                                ostpath = $ostpath
                                ostpathtrim = $ostpathtrim
                                ost = $ost
                            }
                        }
                    }
                   
                    #Handles if there isn't an OST present
                    if ($null -eq $remoteculp.ostpath){
                        $ostout = "| $(ConvertUnit $remoteculp.ost) | OST: No OST Detected"
                    }
                    else{
                        $ostout = "| $(ConvertUnit $remoteculp.ost) | OST: \\$computer\$($remoteculp.ostpathtrim)"
                    }
                    
                    #Calculates every time it returns to this menu the below so it is updated when things delete
                    $delopt = ReadHostTop "
                    Choose an numbered option below:

                    Delete contents of...
                    (1) | $(ConvertUnit $adobe) | Adobe: \\$computer\C$\ProgramData\Adobe\ARM 
                    (2) | $(ConvertUnit $patch) | PatchData: \\$computer\C$\ProgramData\Ivanti\Ivanti Cloud Agent\Agent\Patch\PatchData
                    (3) $ostout
                    
                    (4) Exit to main menu
                    (5) Refresh data
                    ____________________________________________________________________
                    -------------------------- TOTAL STORAGE ---------------------------
                    Total | $(ConvertUnit $remotetotal.total)
                    Used  | $(ConvertUnit $remotetotal.used)
                    Info  | $(ConvertUnit $installer) | Installer: \\$computer\C$\Windows\Installer 
                    --------------------------------------------------------------------
                    FREE  | $(ConvertUnit $remotetotal.free)

                    "
                    #For testing and troubleshooting:
                    # (7) | $(ConvertUnit $test) | Test: \\$computer\$testpath
                    
                    # (1) Adobe
                    if($delopt -eq 1){
                        $delopt1 = ReadHostTop "Delete folder contents of \\$computer\C$\ProgramData\Adobe\ARM? (y/n)"
                        if($delopt1 -eq 'y'){
                            Write-Host "Deleting folder contents..."
                            Delt $adobepath #function to delete folder contents
                            $adobe = Get-size $adobepath #recalculate folder size after deletion for accurate submenu size
                            Continue storagecalc #back to submenu
                        }else{
                            Continue storagecalc
                        }
                        
                    }
                    # (2) PatchData
                    if($delopt -eq 2){
                        $delopt2 = ReadHostTop "Delete folder contents of \\$computer\C$\ProgramData\Ivanti\Ivanti Cloud Agent\Agent\Patch\PatchData? (y/n)"
                        if($delopt2 -eq 'y'){
                            Write-Host "Deleting folder contents..."
                            Delt $patchpath
                            $patch = Get-Size $patchpath
                            Continue storagecalc
                        }else{
                            Continue storagecalc
                        }
                    }
                    # (3) OST
                    if($delopt -eq 3){
   
                        $delopt3 = ReadHostTop "Delete OST at \\$computer\$($remoteculp.ostpathtrim)? (y/n)"
                        if($delopt3 -eq 'y'){
                            Write-Host "Deleting OST..."
                            #delete file
                            Delt $remoteculp.ostpath
                        }else{
                            Continue storagecalc
                        }
                    }   
                    # (4) Disk clean up and shadow copies

                    # (4) Exit                    
                    if($delopt -eq 4){
                        Remove-PSSession $session
                        Continue TopLevel
                    }
                    #Refresh, goes to start of loop to recalculate sizes
                    if($delopt -eq 5){
                        Continue storagecalc
                    }
                    #(7) C:\Temp\Test for testing
                    <# if($delopt -eq 7){
                        $delopt6 = ReadHostTop "Delete folder contents of \\$computer\C$\Temp\Test? (y/n)"
                        if($delopt6 -eq 'y'){
                            Write-Host "Deleting folder contents..."
                            Delt $testpath
                            Get-size $test
                            Write-Host "Folder contents deleted." -ForegroundColor Yellow
                            Continue delete
                        }else{
                            Continue delete
                        } 
                            
                    } #>     
                }
                $mainyn = ReadHostTop "Exit to main menu? (y/n)"
                if($mainyn -eq 'n'){
                    Continue storage
                }
                else{
                    Continue TopLevel
                }

            }else {
                Write-Host "Computer not reachable on network. Please verify spelling and connectivity, then try again." -ForegroundColor Red
            }
        }
    }
# (16) Exit
    elseif($initialQuestion -eq '16'){
        Return
    }
#Invalid Input
    else{
        Write-Host "Invalid input, please try again." -ForegroundColor Red
        Continue Toplevel
    }
}
