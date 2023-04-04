<#
    .SYNOPSIS
        Find virtual machine files that are no longer registered to a Hyper-V host or a virtual machine.

    .DESCRIPTION
        Some operations may leave the XML or VMCX definition file for a virtual machine orphaned, along with other files associated with a virtual machine.
        This script detects and returns those orphaned files.

        Use caution when interpreting results from a shared location. Files owned by a Hyper-V host that was not specified will be returned as a false positive.
        Use the Host parameter to specify other hosts to include in the same scan.

    .PARAMETER VMPath
        A path string or any object type having one of the following properties: 'Path' or 'FullName' or an array of the listed types.
        In this way, one or more directories can be specified for scanning. Subfolders will automatically be included into the scan.
        If not specified, registration, default, and existing virtual machine paths will be scanned.

    .PARAMETER VMHost
        A virtual machine host name string, Microsoft.HyperV.PowerShell.VMHost object, or any object with a 'Name' property or an array of the listed types.
        It can also contain cluster name(s). If not specified, the local host will be used.

    .PARAMETER IncludeDefaultPaths
        If the VMPath parameter is specified, use this parameter to indicate that the Hyper-V host registration and default directory should also be scanned.
        This parameter must not be set without specifying the VMPath parameter.

    .PARAMETER IncludeExistingPaths
        If the VMPath parameter is specified, use this parameter to indicate that the directories of existing VMs should also be scanned.
        This parameter must not be set without specifying the VMPath parameter.

    .PARAMETER ExcludeDefaultPaths
        If the VMPath parameter is not specified, use this parameter to prevent the Hyper-V host registration and default directories from being scanned.
        This parameter must not be set together with the VMPath or the ExcludeExistingPaths parameters.

    .PARAMETER ExcludeExistingPaths
        If the VMPath parameter is not specified, use this parameter to prevent the directories of existing VMs from being scanned.
        This parameter must not be set together with the VMPath or the ExcludeDefaultPaths parameters.

    .PARAMETER IgnoreClusterSharedVolumes
        Ordinarily, the script will determine if a computer is part of a cluster and scan the VMs of all nodes as a fail-safe.
        If this switch is set, only the specified system(s) will be scanned. Any directory involving '{SystemDrive}\ClusterStorage' will be skipped.

    .PARAMETER Credential
        The credential to use to connect to and scan remote hosts.
        Has no effect on shared storage locations. These will always be scanned as the locally logged-on account.

    .PARAMETER Force
        Most search operations in the file systems run with enabled -Force switch to also detect hidden files and folders.
        But, by default, the scan for orphaned files is limited to visible files and folders.
        This can be extended to hidden one with the -Force switch. However, in this case, script aborts due to violation of access permissions are more likely.

    .PARAMETER Verbose
        Additional information about the progress of the script is output.

    .PARAMETER Debug
        Includes verbose output. In addition detailed information about included and excludes files and directories will be provided.
        User confirmations ($DebugPreference = Inquire) are switched off.

    .INPUTS
        System.String[], System.IO.DirectoryInfo[], System.IO.FileSystemInfo[], Microsoft.HyperV.PowerShell.HardDiskDrive[], Microsoft.Vhd.PowerShell.VirtualHardDisk ...
        You can pipe one or more strings that contain paths to scan or objects with a 'Path' or 'FullName' property to the VMPath parameter.

        System.String[], Microsoft.HyperV.PowerShell.VMHost[], ...
        You can pipe one or more strings that contain virtual machine host names or VMHost objects to the VMHost parameter.

    .OUTPUTS
        An array of deserialized FileInfo objects or $null if no items are found. GetType() shows the generic PSObject type.

    .NOTES
        Version 3.0
        Author Olaf Ahrens
        Author of the initial versions 1.2 and 2.0: Eric Siron

    .LINK
        version 1.2: https://www.altaro.com/hyper-v/free-script-find-orphaned-hyper-v-vm-files

    .LINK
        version 2.0: https://github.com/ejsiron/Posher-V/blob/main/Standalone/Get-VMOrphanedFiles.ps1

    .LINK
        version 3.0: https://github.com/oahrens/Posher-V/blob/main/Standalone/Get-VMOrphanedFiles.ps1

    .EXAMPLE
        C:\PS> .\Get-VMOrphanedFiles

        Retrieves orphaned VM files in this host initial and default VM directory and those of VMs.

    .EXAMPLE
        C:\PS> .\Get-VMOrphanedFiles -Path D:\

        Retrieves orphaned VMs on this host contained anywhere on the D:\ drive.

    .EXAMPLE
        C:\PS> .\Get-VMOrphanedFiles -ExcludeExistingPaths

        Retrieves orphaned VM files in this host default VM directory, ignoring any directories of VMs that are outside the registration or default.

    .EXAMPLE
        C:\PS> .\Get-VMOrphanedFiles -ExcludeDefaultPaths

        Retrieves orphaned VM files in the directories of existing VMs except those contained in the host registration and default directory.

    .EXAMPLE
        C:\PS> .\Get-VMOrphanedFiles -VMHost svhv1, svhv2 -Path \\smbshare\vms

        Checks for VM files on the \\smbshare\vms that are not connected to any VMs registered to svhv1 or svhv2.

    .EXAMPLE
        C:\PS> .\Get-VMOrphanedFiles -VMHost svhv1, svhv2 -Path C:\

        Checks for VM files on the local C: drives of svhv1 and svhv2.

    .EXAMPLE
        C:\PS> Get-VMHost server1, server2, server3 | .\Get-VMOrphanedFiles

        Retrieves orphaned VM files in the registration, default and actual VM directories for hosts named server1, server2, and server3.

    .EXAMPLE
        C:\PS> .\Get-VMOrphanedFiles -VMHost svhv1 -Path C:\ -IgnoreClusterSharedVolumes

        Retrieves orphaned VM files on the C: drive of SVHV1, skipping the SystemDrive\ClusterStorage folder and not scanning any other hosts in the cluster.

    .EXAMPLE
        C:\PS> .\Get-VMOrphanedFiles -VMHost svhv1, svhv2 -Path -Credential (Get-Credential)

        Checks for orphaned VM files on svhv1 and svhv2 default directories using the credentials that you specify. Files on shared storage will be scanned
        using the credentials of the local session.
#>

using namespace System
using namespace System.Collections
using namespace System.Collections.Generic
using namespace System.Diagnostics.CodeAnalysis
using namespace System.IO
using namespace System.Management.Automation
using namespace System.Management.Automation.Runspaces
using namespace System.Text
using namespace System.Text.RegularExpressions

#requires -Version 5.1
#requires -RunAsAdministrator

[CmdletBinding(DefaultParameterSetName = 'Default')]
[OutputType([PSObject[]])]
[SuppressMessage('PSAvoidUsingWriteHost', '', Justification = 'Has no side effects')]
[SuppressMessage('PSReviewUnusedParameter', 'Force', Justification = 'Is used in functions')]
[SuppressMessage('PSReviewUnusedParameter', 'Credential', Justification = 'Is used in functions')]

param(
    <#
		Do not assign new values to script and function parameters! If a parameter is passed and a validation is assigned to it, this validation is performed
		again as soon as the parameter is used as a variable in the code and a new value is assigned to it. Validation is not performed if the parameter is
		not passed and is later assigned a value.
		https://social.technet.microsoft.com/Forums/ie/en-US/b6d6dbf5-b75a-4155-886e-bc31ef7a7d0d/powershell-parameter-validation-should-not-apply-beyond-the-param-block?forum=winserverpowershell
        Also, in advanced function with multiple calls, a new assigned parameter retains the value of this assignment on subsequent calls
        which may have unexpected effects.
        #>
    <#
        When checking the combination of variables used via parameter sets, only the use of a parameter is taken into account, not its value.
        Therefore, checking via parameter set is useless if parameter splatting is used or if a function or script is called with a passed parameter.
        This applies, for example, to switches that are explicitly set to false, or a string parameter that is explicitly passed as an empty string or null.
        For this reason, parameter sets are not specified here and the parameter combination is checked below by assessing the content of the parameters.
    #>
    [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [ValidateScript({ $_ -is [String] -or $_.Name})]
    [Alias('Host', 'HostName', 'Computer', 'ComputerName')]
    [PSObject[]]$VMHost = @($Env:ComputerName),
    [Parameter(ValueFromPipelineByPropertyName)]
    [ValidateScript({ $_ -is [String] -or $_.FullName -or $_.Path })]
    [Alias('VirtualMachinePath', 'Path')]
    [PSObject[]]$VMPath = @(),
    [Parameter(ValueFromPipelineByPropertyName)] [Alias('IncludeDefaultPath')] [Switch]$IncludeDefaultPaths,
    [Parameter(ValueFromPipelineByPropertyName)] [Alias('IncludeExistingPath', 'IncludeExistingVMPaths')] [Switch]$IncludeExistingPaths,
    [Parameter(ValueFromPipelineByPropertyName)] [Alias('ExcludeDefaultPath')] [Switch]$ExcludeDefaultPaths,
    [Parameter(ValueFromPipelineByPropertyName)] [Alias('ExcludeExistingPath', 'ExcludeExistingVMPaths')] [Switch]$ExcludeExistingPaths,
    [Parameter(ValueFromPipelineByPropertyName)] [Alias('IgnoreClusterMembership')] [Switch] $IgnoreClusterSharedVolumes,
    [Parameter(ValueFromPipelineByPropertyName)] [Switch]$Force,
    [Parameter()] [PSCredential]$Credential = $null
)

begin {
    #region preferences
    [PSObject]$Preferences = [PSCustomObject]@{
        <#
			.DESCRIPTION
				This PSObject contains the display preferences for the different scripts and for the remote sessions.
		#>
        ErrorAction       = [ActionPreference]::Stop
        Debug             = if ($DebugPreference -eq [ActionPreference]::Inquire) {
            [ActionPreference]::Continue
        } else {
            $DebugPreference
        }
        Verbose           = if ($DebugPreference -eq [ActionPreference]::Continue) {
            [ActionPreference]::SilentlyContinue
        } else {
            $VerbosePreference
        }
        WarningForeground = [ConsoleColor]::Red
        StrictModeVersion = [Version]::new(3, 0)
    }
    Set-StrictMode -Version $Preferences.StrictModeVersion
    $ErrorActionPreference = $Preferences.ErrorAction
    $DebugPreference = $Preferences.Debug
    $VerbosePreference = $Preferences.Verbose
    $Host.PrivateData.WarningForegroundColor = $Preferences.WarningForeground
    #endregion preferences

    #region types
    #region common types
    [Flags()]enum EHostTypes {
        <#
            .DESCRIPTION
                This bit flag enumeration is used to distinguish between a local or remote host that is also a virtual machine host
                and a local host that is not a virtual machine host.
        #>
        None = 0
        Local = 1
        VM = 2
    }

    [Flags()]enum EPathTypes {
        <#
            .DESCRIPTION
                This bit flag enumeration is used to distinguish the purpose that a file or directory serves for a virtual machine.
        #>
        None = 0
        Path = 1
        MetaFile = 2
        DiskFile = 4
        Configuration = 8
        ConfigurationFile = 10
        State = 16
        StateFile = 18
        SmartPaging = 32
        SmartPagingFile = 34
        Vhd = 64
        VhdFile = 68
        Floppy = 128
        FloppyFile = 132
    }

    enum EAvailable {
        <#
            .DESCRIPTION
                This enumeration is used to indicate whether a host, file, or directory exists and is also accessible or not or whether this fact has never been tested.
        #>
        Unknown = 0
        Yes = 1
        No = 2
    }

    enum EVhdFormat {
        <#
            .DESCRIPTION
                This enumeration is similar to Microsoft.Vhd.PowerShell.VhdFormat. The members may not be renamed.
        #>
        Unknown = 0
        VHD = 1
        VHDX = 2
    }

    enum EVhdType {
        <#
            .DESCRIPTION
                This enumeration is similar to Microsoft.Vhd.PowerShell.VhdType. The members may not be renamed.
        #>
        Unknown = 0
        Fixed = 1
        Dynamic = 2
        Differencing = 3
    }

    class HostInfo : IDisposable {
        <#
			.DESCRIPTION
				This class contains VM host information and its session and job administration. It implements the IDisposable interface and objects of this type
                should be disposed when no longer needed.
		#>
        [ValidateNotNullOrEmpty()] [String]$Name
        [ValidateNotNullOrEmpty()] [String]$QualifiedName
        [ValidateNotNullOrEmpty()] [PSSession]$Session
        [ValidateNotNull()] [Queue[Job]]$Jobs
        [Job]$RunningJob
        [ValidateNotNullOrEmpty()] [Version]$PSVersion
        [String]$Problem
        [EHostTypes]$Type
        [EAvailable]$Available
        hidden [Boolean]$IsDisposed

        HostInfo([String]$Name, [String]$QualifiedName, [EHostTypes]$Type) {
            $this.Init($Name, $QualifiedName, $Type, [String]::Empty)
        }
        HostInfo([String]$Name, [String]$QualifiedName, [EHostTypes]$Type, [String]$Problem) {
            $this.Init($Name, $QualifiedName, $Type, $Problem)
        }

        [void]SetProblem([String]$Problem) {
            if ($Problem) {
                $this.Problem = $Problem
                $this.Available = [EAvailable]::No
            }
        }
        [void]InvokeSession([HashTable]$Parameters) {
            $this.Session = New-PSSession @Parameters
        }
        [void]CancelSession() {
            if ($this.Session -and $this.Session.Availability -ne [RunspaceAvailability]::None) {
                $this.Session | Remove-PSSession -ErrorAction ([ActionPreference]::Continue)
            }
        }
        [void]StartJob([ScriptBlock]$Script) {
            $this.StartJob($Script, $null)
        }
        [void]StartJob([ScriptBlock]$Script, [PSObject[]]$Parameters) {
            if ($this.RunningJob) {
                $this.RunningJob | Wait-Job
            }
            $this.RunningJob = Invoke-Command -Session $this.Session -ScriptBlock $Script -ArgumentList $Parameters -AsJob
            $this.Jobs.Enqueue($this.RunningJob)
        }
        [void]StartJobNoSession([ScriptBlock]$Script, [PSObject[]]$Parameters) {
            if ($this.RunningJob) {
                $this.RunningJob | Wait-Job
            }
            $this.RunningJob = Start-Job -ScriptBlock $Script -ArgumentList $Parameters
            $this.RunningJob | Wait-Job
            $this.Jobs.Enqueue($this.RunningJob)
            $this.RunningJob = $null
        }
        [PSObject[]]GetJobsResults() {
            [List[PSObject]]$Results = [List[PSObject]]::new()
            if ($this.RunningJob) {
                $this.RunningJob | Wait-Job
                $this.RunningJob = $null
            }
            while ($this.HasJob()) {
                try {
                    $Result = $this.Jobs.Peek() | Receive-Job
                    if ($Result -is [Array]) {
                        $Results.AddRange([PSObject[]]$Result)
                    } elseif ($Result) {
                        $Results.Add([PSObject]$Result)
                    }
                } finally {
                    $this.Jobs.Dequeue() | Remove-Job -ErrorAction ([ActionPreference]::Continue)
                }
            }
            return $Results
        }
        [Boolean]NeedsOldDirectoryAndFileFormat([Version]$Comparand) {
            return $Comparand.Major -gt 5 -and $this.PSVersion.Major -eq 5
        }
        [Boolean]HasJob() {
            return $this.Jobs.Count
        }
        [Boolean]HasName([String]$Comparand) {
            return $this.Name, $this.QualifiedName -eq $Comparand
        }
        [String]ToString() {
            return $this.QualifiedName
        }
        [HostInfo]Clone() {
            $TempInfo = [HostInfo]::new($this.Name, $this.QualifiedName, $this.Type, $this.Problem)
            $TempInfo.Available = $this.Available
            if ($this.PSVersion) {
                $TempInfo.PSVersion = $this.PSVersion
            }
            return $TempInfo
        }
        hidden [void]Init([String]$Name, [String]$QualifiedName, [EHostTypes]$Type, [String]$Problem) {
            $this.Name = $Name
            $this.QualifiedName = $QualifiedName
            $this.Jobs = [Queue[Job]]::new()
            $this.Problem = $Problem
            $this.Type = $Type
            if ($this.Problem) {
                $this.Available = [EAvailable]::No
            } else {
                $this.Available = [EAvailable]::Yes
            }
        }
        [void]Dispose() {
            $this.Dispose($true)
        }
        hidden [void]Dispose([Boolean]$IsDisposing) {
            if (-not $this.IsDisposed -and $IsDisposing) {
                if ($this.Jobs) {
                    while ($this.HasJob()) {
                        $this.Jobs.Dequeue() | Remove-Job -ErrorAction ([ActionPreference]::Continue) -Force
                    }
                }
                $this.CancelSession()
                $this.IsDisposed = $true
            }
        }
    }

    class PathInfo {
        <#
			.DESCRIPTION
				This class contains basic directory and file informations like a simple variant of System.IO.FileSystemInfo.
				In addition it contains information on the VM host name, usage of the file or directory by the VM (i.e. meta- or diskfile),
				VM identifier (GUID), availability of the file or directory, and information regarding availability problems.
		#>
        [String]$HostName
        [ValidateNotNullOrEmpty()] [String]$FullName
        [ValidateNotNullOrEmpty()] [String]$DevicePath
        [ValidateNotNullOrEmpty()] [String]$Name
        [DateTime]$CreationTimeUtc
        [EPathTypes]$Type
        [Guid]$VMId
        [String]$Problem
        [EAvailable]$Available

        PathInfo([String]$HostName, [String]$FullName, [DateTime]$CreationTimeUtc, [EPathTypes]$Type, [Guid]$VMId, [EAvailable]$Available, [String]$Problem) {
            $this.HostName = $HostName
            $this.FullName = $FullName | ConvertTo-ProperPath
            if ($this.FullName -match $script:Regexes.SharedPath) {
                $this.DevicePath = $this.FullName -replace $script:Regexes.Root, $script:Regexes.SharedDeviceRootSubstitute
            } else {
                $this.DevicePath = $this.FullName -replace $script:Regexes.Root, $script:Regexes.LocalDeviceRootSubstitute
            }
            if ($this.FullName -match $script:Regexes.Drive) {
                $this.Name = $this.FullName
            } else {
                $this.Name = [Path]::GetFileName($this.FullName)
            }
            $this.CreationTimeUtc = $CreationTimeUtc
            $this.Type = $Type
            $this.VMId = $VMId
            $this.Problem = $Problem
            if ($Problem) {
                $this.Available = [EAvailable]::No
            } else {
                $this.Available = $Available
            }
        }

        [void]SetProblem([String]$Problem) {
            if (-not $this.Problem) {
                $this.Problem = $Problem
                $this.Available = [EAvailable]::No
            }
        }
        [String]ToString() {
            If ($this.HostName) {
                return "'$( $this.Fullname )' on '$( $this.HostName )'"
            } else {
                return "'$( $this.Fullname )' (shared)"
            }
        }
    }

    class PSEqualityComparer : EqualityComparer[Object] {
        <#
			.DESCRIPTION
				This is an universal equality comparer class. In PowerShell it's not possible to define a type-safe comparer class for user defined classes defined in the
				same script because 'PowerShell should compile a type before it can use it. So any recursion in type definition (direct or indirect) is impossible'.
			.LINK
				https://github.com/PowerShell/PowerShell/issues/10623
			.LINK
				https://stackoverflow.com/a/61390659/2883733
		#>
        hidden [ValidateNotNull()] [ScriptBlock]$HashScript
        hidden [ValidateNotNull()] [ScriptBlock]$CompareScript

        PSEqualityComparer([ScriptBlock]$HashScript, [ScriptBlock]$CompareScript) {
            $this.HashScript = $HashScript
            $this.CompareScript = $CompareScript
        }
        PSEqualityComparer([String]$HashScript, [String]$CompareScript) {
            $this.HashScript = [Scriptblock]::Create($HashScript)
            $this.CompareScript = [Scriptblock]::Create($CompareScript)
        }

        [Int32]GetHashCode([Object]$Obj) {
            return & $this.HashScript $Obj
        }
        [Boolean]Equals([Object]$Comparand0, [Object]$Comparand1) {
            return & $this.CompareScript $Comparand0 $Comparand1
        }
    }

    class ResultCollections {
        <#
            .DESCRIPTION
                This class is for collecting all the file and directory information from the local host and from remote hosts and for their processed results.
        #>
        [ValidateNotNull()] [HashSet[String]]$SharedScanPaths = [HashSet[String]]::new([StringComparer]::OrdinalIgnoreCase)
        [ValidateNotNull()] [HashSet[PathInfo]]$SharedScanDirectories = [HashSet[PathInfo]]::new([PSEqualityComparer]::new($ComparerScripts.NameHash, `
                    $ComparerScripts.FullNameEquality))
        [ValidateNotNull()] [HashSet[PathInfo]]$SharedMetafileDirectories = [HashSet[PathInfo]]::new([PSEqualityComparer]::new($ComparerScripts.NameHash, `
                    $ComparerScripts.FullNameTypeEquality))
        [ValidateNotNull()] [HashSet[PathInfo]]$SharedMetaFiles = [HashSet[PathInfo]]::new([PSEqualityComparer]::new($ComparerScripts.NameHash, `
                    $ComparerScripts.FullNameEquality))
        [ValidateNotNull()] [HashSet[PathInfo]]$SharedDiskFiles = [HashSet[PathInfo]]::new([PSEqualityComparer]::new($ComparerScripts.NameHash, `
                    $ComparerScripts.FullNameEquality))
        [ValidateNotNull()] [HashSet[PathInfo]]$RemoteScanDirectories = [HashSet[PathInfo]]::new([PSEqualityComparer]::new($ComparerScripts.NameHash, `
                    $ComparerScripts.HostFullNameEquality))
        [ValidateNotNull()] [List[PathInfo]]$RemoteMetaFiles = [List[PathInfo]]::new()
        [ValidateNotNull()] [List[PathInfo]]$RemoteDiskFiles = [List[PathInfo]]::new()
        [ValidateNotNull()] [HashSet[PSObject]]$OrphanedFiles = [HashSet[PSObject]]::new([PSEqualityComparer]::new($ComparerScripts.NameHash,
                $ComparerScripts.NameCreationTimeEquality))

        ResultCollections() {
        }

        [void]SetSharedScanDirectories([PathInfo[]]$Items) {
            $this.SharedScanDirectories = [HashSet[PathInfo]]::new(
                $Items,
                [PSEqualityComparer]::new($script:ComparerScripts.NameHash, $script:ComparerScripts.FullNameEquality)
            )
        }
        [void]SetRemoteScanDirectories([PathInfo[]]$Items) {
            $this.RemoteScanDirectories = [HashSet[PathInfo]]::new(
                $Items,
                [PSEqualityComparer]::new($script:ComparerScripts.NameHash, $script:ComparerScripts.HostFullNameEquality)
            )
        }
        [void]SetRemoteMetaFiles([PathInfo[]]$Items) {
            $this.RemoteMetaFiles = [List[PathInfo]]::new($Items)

        }
        [void]SetRemoteDiskFiles([PathInfo[]]$Items) {
            $this.RemoteDiskFiles = [List[PathInfo]]::new($Items)
        }
    }

    class VhdInfo {
        <#
            .DESCRIPTION
                This class is a simplified version of Microsoft.Vhd.PowerShell.VirtualHardDisk providing only the essential information about
                a VHD or VHDX file.
        #>
        [ValidateNotNullOrEmpty()] [String]$Path
        [String]$ParentPath
        [ValidateNotNullOrEmpty()] [String]$VhdFormat
        [ValidateNotNullOrEmpty()] [String]$VhdType

        VhdInfo() {
        }
        VhdInfo([PSObject]$Vhd) {
            $this.ParentPath = $Vhd.ParentPath
            $this.Path = $Vhd.Path
            $this.VhdFormat = $Vhd.VhdFormat
            $this.VhdType = $Vhd.VhdType
        }

        [String]ToString() {
            return "Path: '$( $this.Path )', VhdFormat: '$( $this.VhdFormat )', VhdType: '$( $this.VhdType )'"
        }
    }

    class BigEndianBitConverter {
        <#
            .DESCRIPTION
                This class is the big-endian counterpart of System.BitConverter for little-endian systems.
                It only implements static functions ToUInt32 and ToUInt64.
            .LINK
                https://stackoverflow.com/questions/8241060/how-to-get-little-endian-data-from-big-endian-in-c-sharp-using-bitconverter-toin
        #>
        hidden BigEndianBitConverter() {
        }

        static [UInt32]ToUInt32([Byte[]]$Data, [UInt64]$Offset) {
            return ([UInt32]$Data[$Offset++] -shl 24) -bor ([UInt32]$Data[$Offset++] -shl 16) `
                -bor ([UInt32]$Data[$Offset++] -shl 8) -bor [UInt32]$Data[$Offset]
        }
        static [UInt64]ToUInt64([Byte[]]$Data, [UInt64]$Offset) {
            return ([UInt64]$Data[$Offset++] -shl 56) -bor ([UInt64]$Data[$Offset++] -shl 48) `
                -bor ([UInt64]$Data[$Offset++] -shl 40) -bor ([UInt64]$Data[$Offset++] -shl 32) `
                -bor ([UInt64]$Data[$Offset++] -shl 24) -bor ([UInt64]$Data[$Offset++] -shl 16) `
                -bor ([UInt64]$Data[$Offset++] -shl 8) -bor [UInt64]$Data[$Offset]
        }
    }
    #endregion common types

    #region VHDX types
    class VhdxFile : IDisposable {
        <#
            .DESCRIPTION
                This class gets the essential information of a VHDX file provided by its path. If Validate() is true, this information can be received from
                its Info property. This class implements the IDisposable interface and objects of this type should be disposed when no longer needed.
        #>
        hidden [FileStream]$DiskStream
        hidden [String]$Path
        hidden [Boolean]$IsDisposed
        [VhdInfo]$Info

        VhdxFile([String]$Path) {
            $this.Path = $Path
            $this.DiskStream = [FileStream]::new($this.Path, [FileMode]::Open, [FileAccess]::Read, [FileShare]::ReadWrite)
        }

        [Boolean]Validate() {
            $Header = [VhdxHeader]::new($this.DiskStream)
            if ($Header.Validate()) {
                $this.Info = [VhdInfo]::new()
                $this.Info.VhdFormat = [EVhdFormat]::VHDX.ToString()
                foreach ($RegionTable in $Header) {
                    if ($RegionTable.Validate()) {
                        foreach ($RegionTableEntry in $RegionTable) {
                            if ($RegionTableEntry.Id.Equals([VhdxRegionTable]::MetadataId)) {
                                [VhdxFileParameters]$FileParameters = $null
                                [VhdxParentLocatorTable]$ParentTable = $null
                                foreach ($MetadataEntry in [VhdxMetadataTable]::new($this.DiskStream, $RegionTableEntry.RegionPosition)) {
                                    if ($MetadataEntry.Id.Equals([VhdxMetadataTableEntry]::FileParametersId)) {
                                        # $MetadataEntry.MetadataSize equals $FileParameters.Size
                                        [VhdxFileParameters]$FileParameters = [VhdxFileParameters]::new($this.DiskStream, `
                                                $RegionTableEntry.RegionPosition + $MetadataEntry.MetadataOffset, `
                                                $MetadataEntry.MetadataSize)
                                    } elseif ($MetadataEntry.Id.Equals([VhdxMetadataTableEntry]::ParentLocatorId)) {
                                        # $MetadataEntry.MetadataSize is larger than $ParentTable.Size
                                        [VhdxParentLocatorTable]$ParentTable = [VhdxParentLocatorTable]::new($this.DiskStream, `
                                                $RegionTableEntry.RegionPosition + $MetadataEntry.MetadataOffset, `
                                                $MetadataEntry.MetadataSize)
                                    }
                                    if ($FileParameters -and ($FileParameters.VhdType -ne [EVhdType]::Differencing -or $ParentTable)) {
                                        $this.Info.VhdType = $FileParameters.VhdType.ToString()
                                        if ($FileParameters.VhdType -eq [EVhdType]::Differencing) {
                                            foreach ($Parent in $ParentTable) {
                                                <#
                                                    An implementation has to evaluate the paths in a specific order to locate the parent:
                                                    relative_path, volume_path, and then absolute_path.
                                                    from: [MS-VHDX]: Virtual Hard Disk v2 (VHDX) File Format - Release: October 3, 2022
                                                #>
                                                if ($Parent.PathType -eq [VhdxParentLocator]::RelWinPathKey) {
                                                    <#
                                                        Join-Path or [Path]::Combine() don't work for '.\' or '..\' paths.
                                                        [Path]::GetFullPath({relative path}, {root path}) doesn't work in PowerShell 5.1.
                                                        So, this is the solution (from: https://github.com/PowerShell/PowerShell/issues/10278):
                                                    #>
                                                    $this.Info.ParentPath = [Path]::GetFullPath([Path]::Combine([Path]::GetDirectoryName($this.Path), `
                                                                $Parent.Path))
                                                    return $true
                                                } elseif ($Parent.PathType -eq [VhdxParentLocator]::AbsWinPathKey) {
                                                    $this.Info.ParentPath = $Parent.Path
                                                    return $true
                                                }
                                            }
                                            throw [InvalidDataException]::new("Can't find neither relative nor absolute VHDX parent locator path")
                                        } else {
                                            return $true
                                        }
                                    }
                                }
                                throw [InvalidDataException]::new("Can't find all metadata entries necessary for this VHDX type")
                            }
                        }
                        throw [InvalidDataException]::new("Can't find a VHDX region table metadata entry")
                    }
                }
                throw [InvalidDataException]::new("Can't find a valid VHDX region table")
            } else {
                return $false
            }
        }
        [void]Dispose() {
            $this.Dispose($true)
        }
        hidden [void]Dispose([Boolean]$IsDisposing) {
            if (-not $this.IsDisposed -and $IsDisposing) {
                if ($this.DiskStream) {
                    $this.DiskStream.Close()
                }
                $this.IsDisposed = $true
            }
        }
    }

    class VhdxHeader : IEnumerator <# [VhdxRegionTable] #> {
        <#
            .DESCRIPTION
                This class is for analyzing the header section of a VHDX file. If Validate() returns true it enumerates the two region tables
                of the header section by a non-generic IEnumerator.
            .LINK
                https://github.com/ReneNyffenegger/about-powershell/blob/master/language/statement/foreach/IEnumerator.ps1
            .LINK
                https://gist.github.com/Jaykul/dfc355598e0f233c8c7f288295f7bb56
        #>
        hidden static [Int32]$RegionTablesCt = 2

        hidden [FileStream]$DiskStream
        hidden [Int32]$RegionTableCtr
        hidden [VhdxRegionTable]$CurrentRegionTable

        VhdxHeader([FileStream]$DiskStream) {
            $this.DiskStream = $DiskStream
        }

        [Boolean]Validate() {
            [VhdxFileTypeIdentifier]$FileType = [VhdxFileTypeIdentifier]::new($this.DiskStream)
            if ($FileType.Validate()) {
                $this.Reset()
                return $true
            } else {
                return $false
            }
        }
        [Object]get_Current() {
            return $this.CurrentRegionTable
        }
        [Boolean]MoveNext() {
            if ($this.RegionTableCtr -lt [VhdxHeader]::RegionTablesCt) {
                $this.CurrentRegionTable = [VhdxRegionTable]::new($this.DiskStream, $this.RegionTableCtr)
                $this.RegionTableCtr++
                return $true
            } else {
                $this.CurrentRegionTable = $null
                return $false
            }
        }
        [void]Reset() {
            $this.RegionTableCtr = 0
            $this.CurrentRegionTable = $null
        }
    }

    class VhdxFileTypeIdentifier {
        <#
            .DESCRIPTION
                This class is for analyzing the file type identifier entry of a VHDX file's header.
        #>
        hidden static [UInt64]$Position = 0
        hidden static [Int32]$SignatureOffset = 0
        hidden static [Int32]$SignatureSize = 8
        hidden static [String]$SignatureValue = 'vhdxfile'

        hidden [FileStream]$DiskStream

        VhdxFileTypeIdentifier([FileStream]$DiskStream) {
            $this.DiskStream = $DiskStream
        }

        [Boolean]Validate() {
            [Byte[]]$BinaryData = [Byte[]]::new([VhdxFileTypeIdentifier]::SignatureSize)
            $this.DiskStream.Position = [VhdxFileTypeIdentifier]::Position + [VhdxFileTypeIdentifier]::SignatureOffset
            $this.DiskStream.Read($BinaryData, 0, [VhdxFileTypeIdentifier]::SignatureSize) |
                Assert-ReadByte -Comparand ([VhdxFileTypeIdentifier]::SignatureSize) -Location 'VHDX file type identifier'
            return ([Encoding]::UTF8.GetString($BinaryData, 0, [VhdxFileTypeIdentifier]::SignatureSize) -eq [VhdxFileTypeIdentifier]::SignatureValue)
        }
    }

    class VhdxRegionTable : IEnumerator <# [VhdxRegionTableEntry] #> {
        <#
            .DESCRIPTION
                This class is for analyzing the region table sections of a VHDX file's header. If Validate() returns true it enumerates the region table entries
                by a non-generic IEnumerator.
            .LINK
                https://github.com/ReneNyffenegger/about-powershell/blob/master/language/statement/foreach/IEnumerator.ps1
            .LINK
                https://gist.github.com/Jaykul/dfc355598e0f233c8c7f288295f7bb56
        #>
        hidden static [Int32[]]$Positions = @(192KB, 256KB)
        hidden static [Int32]$Size = 64KB
        hidden static [Int32]$SignatureOffset = 0
        hidden static [Int32]$SignatureSize = 4
        hidden static [String]$SignatureValue = 'regi'
        hidden static [Int32]$ChecksumOffset = 4
        hidden static [Int32]$EntriesCtOffset = 8
        hidden static [Int32]$EntriesOffset = 16
        static [Guid]$MetadataId = [Guid]::new('8B7CA206-4790-4B9A-B8FE-575F050F886E') # '06-A2-7C-8B-90-47-9A-4B-B8-FE-57-5F-05-0F-88-6E'

        hidden [UInt64]$Position
        hidden [FileStream]$DiskStream
        hidden [UInt32]$EntriesCt
        hidden [Int32]$EntryCtr
        hidden [VhdxRegionTableEntry]$CurrentEntry

        VhdxRegionTable([FileStream]$DiskStream, [Int32]$Nr) {
            $this.DiskStream = $DiskStream
            $this.Position = [VhdxRegionTable]::Positions[$Nr]
        }

        [Boolean]Validate() {
            [Byte[]]$BinaryData = [Byte[]]::new([VhdxRegionTable]::Size)
            $this.DiskStream.Position = $this.Position
            $this.DiskStream.Read($BinaryData, 0, [VhdxRegionTable]::Size) |
                Assert-ReadByte -Comparand ([VhdxRegionTable]::Size) -Location 'VHDX region table'
            if (([Encoding]::UTF8.GetString($BinaryData, [VhdxRegionTable]::SignatureOffset, [VhdxRegionTable]::SignatureSize) `
                        -eq [VhdxRegionTable]::SignatureValue) `
                    -and (Test-VhdxChecksum -BinaryData $BinaryData `
                        -Position 0 `
                        -Size ([VhdxRegionTable]::Size) `
                        -ChecksumOffset ([VhdxRegionTable]::ChecksumOffset))
            ) {
                $this.EntriesCt = [BitConverter]::ToUInt32($BinaryData, [VhdxRegionTable]::EntriesCtOffset)
                $this.Reset()
                return $true
            } else {
                return $false
            }
        }
        [Object]get_Current() {
            return $this.CurrentEntry
        }
        [Boolean]MoveNext() {
            if ($this.EntryCtr -lt $this.EntriesCt) {
                $this.CurrentEntry = [VhdxRegionTableEntry]::new($this.DiskStream, `
                        $this.Position + [VhdxRegionTable]::EntriesOffset + $this.EntryCtr * [VhdxRegionTableEntry]::Size)
                $this.EntryCtr++
                if ($this.CurrentEntry.RegionPosition -and $this.CurrentEntry.RegionSize) {
                    return $true
                } else {
                    return $this.MoveNext
                }
            } else {
                $this.CurrentEntry = $null
                return $false
            }
        }
        [void]Reset() {
            $this.EntryCtr = 0
            $this.CurrentEntry = $null
        }
    }

    class VhdxRegionTableEntry {
        <#
            .DESCRIPTION
                This class is for analyzing a single VHDX file region table's entry.
        #>
        hidden static [Int32]$Size = 32
        hidden static [Int32]$IdOffset = 0
        hidden static [Int32]$RegionPositionOffset = 16
        hidden static [Int32]$RegionSizeOffset = 24

        [Guid]$Id
        [UInt64]$RegionPosition
        [UInt32]$RegionSize

        VhdxRegionTableEntry([FileStream]$DiskStream, [UInt64]$Position) {
            [Byte[]]$BinaryData = [Byte[]]::new([VhdxRegionTableEntry]::Size)
            $DiskStream.Position = $Position
            $DiskStream.Read($BinaryData, 0, [VhdxRegionTableEntry]::Size) |
                Assert-ReadByte -Comparand ([VhdxRegionTableEntry]::Size) -Location 'VHDX region table entry'
            [Byte[]]$BinaryGuid = [Byte[]]::new($script:GuidSize)
            [Buffer]::BlockCopy($BinaryData, `
                    [VhdxRegionTableEntry]::IdOffset, `
                    $BinaryGuid, `
                    0, `
                    $script:GuidSize)
            $this.Id = [Guid]::new($BinaryGuid)
            $this.RegionPosition = [BitConverter]::ToUInt64($BinaryData, [VhdxRegionTableEntry]::RegionPositionOffset)
            $this.RegionSize = [BitConverter]::ToUInt32($BinaryData, [VhdxRegionTableEntry]::RegionSizeOffset)
        }
    }

    class VhdxMetadataTable : IEnumerator <# [VhdxMetadataTableEntry] #> {
        <#
            .DESCRIPTION
                This class is for analyzing the metatdata table of a VHDX file. If enumerates the metadata table's entries by a non-generic IEnumerator.
            .LINK
                https://github.com/ReneNyffenegger/about-powershell/blob/master/language/statement/foreach/IEnumerator.ps1
            .LINK
                https://gist.github.com/Jaykul/dfc355598e0f233c8c7f288295f7bb56
        #>
        hidden static [Int32]$Size = 64KB
        hidden static [Int32]$HeaderSize = 32
        hidden static [Int32]$SignatureOffset = 0
        hidden static [Int32]$SignatureSize = 8
        hidden static [String]$SignatureValue = 'metadata'
        hidden static [Int32]$EntriesCtOffset = 10
        hidden static [Int32]$EntriesCtSize = 2

        hidden [UInt64]$Position
        hidden [FileStream]$DiskStream
        hidden [UInt16]$EntriesCt
        hidden [Int32]$EntryCtr
        hidden [VhdxMetadataTableEntry]$CurrentEntry

        VhdxMetadataTable([FileStream]$DiskStream, [UInt64]$Position) {
            $this.DiskStream = $DiskStream
            $this.Position = $Position

            [Byte[]]$BinaryData = [Byte[]]::new([VhdxMetadataTable]::HeaderSize)
            $this.DiskStream.Position = $this.Position + [VhdxMetadataTable]::SignatureOffset
            $this.DiskStream.Read($BinaryData, 0, [VhdxMetadataTable]::HeaderSize) |
                Assert-ReadByte -Comparand ([VhdxMetadataTable]::HeaderSize) -Location 'VHDX metadata table signature'
            if ([Encoding]::ASCII.GetString($BinaryData, `
                        [VhdxMetadataTable]::SignatureOffset, `
                        [VhdxMetadataTable]::SignatureSize) `
                    -eq [VhdxMetadataTable]::SignatureValue
            ) {
                $this.EntriesCt = [BitConverter]::ToUInt16($BinaryData, [VhdxMetadataTable]::EntriesCtOffset)
                if ($this.EntriesCt) {
                    return
                } else {
                    throw [InvalidDataException]::new('No VHDX metadata entries are reported')
                }
            } else {
                throw [InvalidDataException]::new("Can't find VHDX metadata header signature")
            }
            $this.Reset()
        }

        [Object]get_Current() {
            return $this.CurrentEntry
        }
        [Boolean]MoveNext() {
            if ($this.EntryCtr -lt $this.EntriesCt) {
                $this.CurrentEntry = [VhdxMetadataTableEntry]::new($this.DiskStream,
                    $this.Position + [VhdxMetadataTable]::HeaderSize + $this.EntryCtr * [VhdxMetadataTableEntry]::Size)
                $this.EntryCtr++
                if ($this.CurrentEntry.Validate()) {
                    return $true
                } else {
                    return $this.MoveNext()
                }
            } else {
                $this.CurrentEntry = $null
                return $false
            }
        }
        [void]Reset() {
            $this.EntryCtr = 0
            $this.CurrentEntry = $null
        }
    }

    class VhdxMetadataTableEntry {
        <#
            .DESCRIPTION
                This class is for analyzing a single VHDX file metadata table's entry.
        #>
        hidden static [Int32]$Size = 32
        hidden static [Int32]$IdOffset = 0
        hidden static [Int32]$OffsetOffset = 16
        hidden static [Int32]$SizeOffset = 20
        static [Guid]$FileParametersId = [Guid]::new('CAA16737-FA36-4D43-B3B6-33F0AA44E76B') # '37-67-A1-CA-36-FA-43-4D-B3-B6-33-F0-AA-44-E7-6B'
        static [Guid]$ParentLocatorId = [Guid]::new('A8D35F2D-B30B-454D-ABF7-D3D84834AB0C') # '2D-5F-D3-A8-0B-B3-4D-45-AB-F7-D3-D8-48-34-AB-0C'

        hidden [FileStream]$DiskStream
        hidden [UInt64]$Position
        [Guid]$Id
        [UInt32]$MetadataOffset
        [UInt32]$MetadataSize

        VhdxMetadataTableEntry([FileStream]$DiskStream, [UInt64]$Position) {
            $this.DiskStream = $DiskStream
            $this.Position = $Position
        }

        [Boolean]Validate() {
            [Byte[]]$BinaryData = [Byte[]]::new([VhdxMetadataTableEntry]::Size)
            $this.DiskStream.Position = $this.Position
            $this.DiskStream.Read($BinaryData, 0, [VhdxMetadataTableEntry]::Size) |
                Assert-ReadByte -Comparand ([VhdxMetadataTableEntry]::Size) -Location 'VHDX metadata table entry ID'
            [Byte[]]$BinaryGuid = [Byte[]]::new($script:GuidSize)
            [Buffer]::BlockCopy($BinaryData, [VhdxMetadataTableEntry]::IdOffset, $BinaryGuid, 0, $script:GuidSize)
            $this.Id = [Guid]::new($BinaryGuid)
            $this.MetadataOffset = [BitConverter]::ToUInt32($BinaryData, [VhdxMetadataTableEntry]::OffsetOffset)
            $this.MetadataSize = [BitConverter]::ToUInt32($BinaryData, [VhdxMetadataTableEntry]::SizeOffset)
            <#
                If Length is zero, then Offset MUST also be zero, in which case the metadata item SHOULD be considered present but empty.
                from: [MS-VHDX]: Virtual Hard Disk v2 (VHDX) File Format - Release: October 3, 2022
            #>
            return $this.Id -and $this.MetadataOffset -and $this.MetadataSize
        }
    }

    class VhdxFileParameters {
        <#
            .DESCRIPTION
                This class is for analyzing the VHDX file metadata table's file parameters entry.
        #>
        hidden static [Int32]$Size = 8
        hidden static [Int32]$FlagsOffset = 4
        hidden static [Int32]$FlagsSize = 1
        hidden static [Int32]$DynamicFlag = 0
        hidden static [Int32]$FixedFlag = 1 # LeaveBlocksAllocated
        hidden static [Int32]$DifferencingFlag = 2 # HasParent

        [EVhdType]$VhdType

        VhdxFileParameters([FileStream]$DiskStream, [UInt64]$Position, [UInt32]$ReportedSize) {
            if ($ReportedSize -ge [VhdxFileParameters]::Size) {
                [Byte[]]$BinaryData = [Byte[]]::new([VhdxFileParameters]::FlagsSize)
                $DiskStream.Position = $Position + [VhdxFileParameters]::FlagsOffset
                $DiskStream.Read($BinaryData, 0, [VhdxFileParameters]::FlagsSize) |
                    Assert-ReadByte -Comparand ([VhdxFileParameters]::FlagsSize) -Location "VHDX file parameters' flags"
                [Byte]$Flags = $BinaryData[0] -band ([VhdxFileParameters]::FixedFlag -bor [VhdxFileParameters]::DifferencingFlag)
                if ($Flags -eq [VhdxFileParameters]::DynamicFlag) {
                    $this.VhdType = [EVhdType]::Dynamic
                } elseif ($Flags -band [VhdxFileParameters]::DifferencingFlag) {
                    $this.VhdType = [EVhdType]::Differencing
                } elseif ($Flags -band [VhdxFileParameters]::FixedFlag) {
                    <#
                        [FixedFlag is] ignored if HasParent is set.
                        from: [MS-VHDX]: Virtual Hard Disk v2 (VHDX) File Format - Release: October 3, 2022
                    #>
                    $this.VhdType = [EVhdType]::Fixed
                } else {
                    throw [InvalidDataException]::new("Can't find VHDX file parameters' VhdType")
                }
                return
            } else {
                throw [InvalidDataException]::new('VHDX metadata file parameters entry has the wrong size')
            }
        }
    }

    class VhdxParentLocatorTable : IEnumerator <# [VhdxParentLocator] #> {
        <#
            .DESCRIPTION
                This class is for analyzing the VHDX file metadata table's parent locator table. It enumerates the parent locators by a non-generic IEnumerator.
            .LINK
                https://github.com/ReneNyffenegger/about-powershell/blob/master/language/statement/foreach/IEnumerator.ps1
            .LINK
                https://gist.github.com/Jaykul/dfc355598e0f233c8c7f288295f7bb56
        #>
        hidden static [Int32]$HeaderSize = 20
        hidden static [Int32]$IdOffset = 0
        hidden static [Int32]$EntriesCtOffset = 18
        hidden static [Guid]$VhdxId = [Guid]::new('B04AEFB7-D19E-4A81-B789-25B8E9445913') # 'B7-EF-4A-B0-9E-D1-81-4A-B7-89-25-B8-E9-44-59-13'

        hidden [UInt64]$Position
        hidden [FileStream]$DiskStream
        hidden [UInt16]$EntriesCt
        hidden [Int32]$EntryCtr
        hidden [VhdxParentLocator]$CurrentParent

        VhdxParentLocatorTable([FileStream]$DiskStream, [UInt64]$Position, [UInt32]$ReportedSize) {
            $this.DiskStream = $DiskStream
            $this.Position = $Position

            [Byte[]]$BinaryData = [Byte[]]::new([VhdxParentLocatorTable]::HeaderSize)
            $this.DiskStream.Position = $this.Position
            $this.DiskStream.Read($BinaryData, 0, [VhdxParentLocatorTable]::HeaderSize) |
                Assert-ReadByte -Comparand ([VhdxParentLocatorTable]::HeaderSize) -Location 'Vhdx parent locator table ID and entries count'
            [Byte[]]$BinaryGuid = [Byte[]]::new($script:GuidSize)
            [Buffer]::BlockCopy($BinaryData, `
                    [VhdxParentLocatorTable]::IdOffset, `
                    $BinaryGuid, `
                    0, `
                    $script:GuidSize)
            if ([Guid]::new($BinaryGuid).Equals([VhdxParentLocatorTable]::VhdxId)) {
                $this.EntriesCt = [BitConverter]::ToUInt16($BinaryData, [VhdxParentLocatorTable]::EntriesCtOffset)
                if ($this.EntriesCt) {
                    if ($ReportedSize -ge [VhdxParentLocatorTable]::HeaderSize + [VhdxParentLocatorEntry]::Size * $this.EntriesCt) {
                        return
                    } else {
                        throw [InvalidDataException]::new('VHDX parent locator table has the wrong size')
                    }
                } else {
                    throw [InvalidDataException]::new('No VHDX parent locator entries are reported')
                }
            } else {
                throw [InvalidDataException]::new("VHDX parent locator is not of type 'VHDX'")
            }
            $this.Reset()
        }

        [Object]get_Current() {
            return $this.CurrentParent
        }
        [Boolean]MoveNext() {
            if ($this.EntryCtr -lt $this.EntriesCt) {
                [VhdxParentLocatorEntry]$CurrentEntry = [VhdxParentLocatorEntry]::new($this.DiskStream, `
                        $this.Position + [VhdxParentLocatorTable]::HeaderSize + $this.EntryCtr * [VhdxParentLocatorEntry]::Size)
                $this.CurrentParent = [VhdxParentLocator]::new($this.DiskStream, `
                        $this.Position + $CurrentEntry.KeyOffset, `
                        $CurrentEntry.KeySize, `
                        $this.Position + $CurrentEntry.ValueOffset, `
                        $CurrentEntry.ValueSize)
                $this.EntryCtr++
                return $true
            } else {
                $this.CurrentParent = $null
                return $false
            }
        }
        [void]Reset() {
            $this.EntryCtr = 0
            $this.CurrentParent = $null
        }
    }

    class VhdxParentLocatorEntry {
        <#
            .DESCRIPTION
                This class is for analyzing a single VHDX file metadata table's parent locator table entry.
        #>
        hidden static [Int32]$Size = 12
        hidden static [Int32]$KeyOffsetOffset = 0
        hidden static [Int32]$ValueOffsetOffset = 4
        hidden static [Int32]$KeySizeOffset = 8
        hidden static [Int32]$ValueSizeOffset = 10

        [UInt32]$KeyOffset
        [UInt32]$ValueOffset
        [UInt16]$KeySize
        [UInt16]$ValueSize

        VhdxParentLocatorEntry([FileStream]$DiskStream, [UInt64]$Position) {
            [Byte[]]$BinaryData = [Byte[]]::new([VhdxParentLocatorEntry]::Size)
            $DiskStream.Position = $Position
            $DiskStream.Read($BinaryData, 0, [VhdxParentLocatorEntry]::Size) |
                Assert-ReadByte -Comparand ([VhdxParentLocatorEntry]::Size) -Location 'VHDX parent locator entry'
            $this.KeyOffset = [BitConverter]::ToUInt32($BinaryData, [VhdxParentLocatorEntry]::KeyOffsetOffset)
            $this.ValueOffset = [BitConverter]::ToUInt32($BinaryData, [VhdxParentLocatorEntry]::ValueOffsetOffset)
            $this.KeySize = [BitConverter]::ToUInt16($BinaryData, [VhdxParentLocatorEntry]::KeySizeOffset)
            $this.ValueSize = [BitConverter]::ToUInt16($BinaryData, [VhdxParentLocatorEntry]::ValueSizeOffset)
            if ($this.KeyOffset -and $this.ValueOffset -and $this.KeySize -and $this.ValueSize) {
                return
            } else {
                throw [InvalidDataException]::new("Can't find VHDX parent locator entry key or value information")
            }
        }
    }

    class VhdxParentLocator {
        <#
            .DESCRIPTION
                This class is for analyzing a single VHDX file parent locator.
        #>
        static [String]$AbsWinPathKey = 'absolute_win32_path'
        static [String]$RelWinPathKey = 'relative_path'

        [String]$PathType
        [String]$Path

        VhdxParentLocator([FileStream]$DiskStream, [UInt64]$KeyPosition, [UInt16]$KeySize, [UInt64]$ValuePosition, [UInt16]$ValueSize) {
            [Byte[]]$BinaryKeyData = [Byte[]]::new($KeySize)
            $DiskStream.Position = $KeyPosition
            $DiskStream.Read($BinaryKeyData, 0, $KeySize) |
                Assert-ReadByte -Comparand $KeySize -Location 'VHDX parent locator key'
            # Encoding.GetString may return a string of nullchars, which isn't empty, null, or white space
            $this.PathType = [Encoding]::Unicode.GetString($BinaryKeyData, 0, $KeySize).TrimEnd([Char]::MinValue)

            [Byte[]]$BinaryValueData = [Byte[]]::new($ValueSize)
            $DiskStream.Position = $ValuePosition
            $DiskStream.Read($BinaryValueData, 0, $ValueSize) |
                Assert-ReadByte -Comparand $ValueSize -Location 'VHDX parent locator value'
            if ($this.PathType -eq [VhdxParentLocator]::AbsWinPathKey) {
                $this.Path = [Encoding]::Unicode.GetString($BinaryValueData, 0, $ValueSize).TrimEnd([Char]::MinValue) `
                    -replace $script:Regexes.DevicePathPrefix
            } else {
                $this.Path = [Encoding]::Unicode.GetString($BinaryValueData, 0, $ValueSize).TrimEnd([Char]::MinValue)
            }
            if ($this.Path -and $this.PathType) {
                return
            } else {
                throw [InvalidDataException]::new("Can't find VHDX parent locator path information")
            }
        }
    }
    #endregion VHDX types

    #region VHD types
    class VhdFile : IDisposable {
        <#
            .DESCRIPTION
                This class gets the essential information of a VHD file provided by its path. If Validate() is true, this information can be received from
                its Info property. This class implements the IDisposable interface and objects of this type should be disposed when no longer needed.
        #>
        hidden [FileStream]$DiskStream
        hidden [String]$Path
        hidden [Boolean]$IsDisposed
        hidden [VhdInfo]$Info

        VhdFile([String]$Path) {
            $this.Path = $Path
            $this.DiskStream = [FileStream]::new($this.Path, [FileMode]::Open, [FileAccess]::Read, [FileShare]::ReadWrite)
        }

        [Boolean]Validate() {
            foreach ($Footer in [VhdFooters]::new($this.DiskStream)) {
                if ($Footer.Validate()) {
                    $this.Info = [VhdInfo]::new()
                    $this.Info.VhdFormat = [EVhdFormat]::VHD.ToString()
                    $this.Info.VhdType = $Footer.VhdType.ToString()
                    if ($Footer.VhdType -eq [EVhdType]::Differencing) {
                        foreach ($Parent in [VhdDynamicHeader]::new($this.DiskStream, $Footer.DynamicHeaderPosition)) {
                            if ($Parent.PathType -eq [VhdParentLocatorEntry]::RelWinPathKey) {
                                <#
                                    Join-Path or [Path]::Combine() don't work for '.\' or '..\' paths.
                                    [Path]::GetFullPath({relative path}, {root path}) doesn't work in PowerShell 5.1.
                                    So, this is the solution (from: https://github.com/PowerShell/PowerShell/issues/10278):
                                #>
                                $this.Info.ParentPath = [Path]::GetFullPath([Path]::Combine([Path]::GetDirectoryName($this.Path), $Parent.Path))
                                return $true
                            } elseif ($Parent.PathType -eq [VhdParentLocatorEntry]::AbsWinPathKey) {
                                $this.Info.ParentPath = $Parent.Path
                                return $true
                            }
                        }
                        throw [InvalidDataException]::new("Can't find neither relative nor absolute VHD parent locator")
                    } else {
                        return $true
                    }
                }
            }
            return $false
        }
        [void]Dispose() {
            $this.Dispose($true)
        }
        hidden [void]Dispose([Boolean]$IsDisposing) {
            if (-not $this.IsDisposed -and $IsDisposing) {
                if ($this.DiskStream) {
                    $this.DiskStream.Close()
                }
                $this.IsDisposed = $true
            }
        }
    }

    class VhdFooters : IEnumerator <# [VhdFooter] #> {
        <#
            .DESCRIPTION
                This class is for finding the valid footer or header sections of a VHD file. If enumerates these valid footer or header section by a non-generic IEnumerator.
            .LINK
                https://github.com/ReneNyffenegger/about-powershell/blob/master/language/statement/foreach/IEnumerator.ps1
            .LINK
                https://gist.github.com/Jaykul/dfc355598e0f233c8c7f288295f7bb56
        #>
        hidden static [Int32]$Ct = 3

        hidden [FileStream]$DiskStream
        hidden [VhdFooter]$CurrentFooter
        hidden [Int32]$FooterCtr

        VhdFooters([FileStream]$DiskStream) {
            $this.DiskStream = $DiskStream
            $this.Reset()
        }

        [Object]get_Current() {
            return $this.CurrentFooter
        }
        [Boolean]MoveNext() {
            if ($this.FooterCtr -lt [VhdFooters]::Ct) {
                $this.CurrentFooter = [VhdFooter]::new($this.DiskStream, $this.FooterCtr)
                $this.FooterCtr++
                return $true
            } else {
                $this.CurrentFooter = $null
                return $false
            }
        }
        [void]Reset() {
            $this.FooterCtr = 0
            $this.CurrentFooter = $null
        }
    }

    class VhdFooter {
        <#
            .DESCRIPTION
                This class is analyzing a single VHD file footer or header. It provides this information if Validate() is true.
        #>
        hidden static [Int32[]]$Sizes = @(512, 511, 512)
        hidden static [Int32]$CookieOffset = 0
        hidden static [Int32]$CookieSize = 8
        hidden static [String]$CookieValue = 'conectix'
        hidden static [Int32]$FixedType = 2
        hidden static [Int32]$DynamicType = 3
        hidden static [Int32]$DifferencingType = 4
        hidden static [Int32]$NextDataOffset = 16
        hidden static [Int32]$TypeOffset = 60
        hidden static [Int32]$ChecksumOffset = 64

        hidden [FileStream]$DiskStream
        hidden [UInt64]$Position
        hidden [Int32]$Size
        [EVhdType]$VhdType
        [UInt64]$DynamicHeaderPosition

        VhdFooter([FileStream]$DiskStream, [Int32]$Nr) {
            $this.DiskStream = $DiskStream
            [Int32]$this.Size = [VhdFooter]::Sizes[$Nr]
            if (0, 1 -eq $Nr) {
                [UInt64]$this.Position = $this.DiskStream.Length - $this.Size
            } else {
                [UInt64]$this.Position = 0
            }
        }

        [Boolean]Validate() {
            [Byte[]]$BinaryData = [Byte[]]::new($this.Size)
            $this.DiskStream.Position = $this.Position
            $this.DiskStream.Read($BinaryData, 0, $this.Size) |
                Assert-ReadByte -Comparand $this.Size -Location 'VHD footer'
            if ([Encoding]::ASCII.GetString($BinaryData, [VhdFooter]::CookieOffset, [VhdFooter]::CookieSize) `
                    -eq [VhdFooter]::CookieValue `
                    -and (Test-VhdChecksum -BinaryData $BinaryData -Position 0 -Size $this.Size `
                        -ChecksumOffset ([VhdFooter]::ChecksumOffset))
            ) {
                switch ([BigEndianBitConverter]::ToUInt32($BinaryData, [VhdFooter]::TypeOffset)) {
                        ([VhdFooter]::FixedType) {
                        $this.VhdType = [EVhdType]::Fixed
                        continue
                    } ([VhdFooter]::DynamicType) {
                        $this.VhdType = [EVhdType]::Dynamic
                        continue
                    } ([VhdFooter]::DifferencingType) {
                        $this.VhdType = [EVhdType]::Differencing
                        $this.DynamicHeaderPosition = [BigEndianBitConverter]::ToUInt64($BinaryData, [VhdFooter]::NextDataOffset)
                        continue
                    } default {
                        throw [InvalidDataException]::new("Can't find VHD footer VHD type")
                    }
                }
                return $true
            } else {
                return $false
            }
        }
    }

    class VhdDynamicHeader : IEnumerator <# [VhdParentLocator] #> {
        <#
            .DESCRIPTION
                This class is for analyzing the dynamic header section of a VHD file. If enumerates the parent locators by a non-generic IEnumerator.
            .LINK
                https://github.com/ReneNyffenegger/about-powershell/blob/master/language/statement/foreach/IEnumerator.ps1
            .LINK
                https://gist.github.com/Jaykul/dfc355598e0f233c8c7f288295f7bb56
        #>
        hidden static [Int32]$Size = 1KB
        hidden static [Int32]$CookieOffset = 0
        hidden static [Int32]$CookieSize = 8
        hidden static [String]$CookieValue = 'cxsparse'
        hidden static [Int32]$ChecksumOffset = 36
        hidden static [Int32]$EntriesOffset = 576
        hidden static [Int32]$EntriesCt = 8

        hidden [UInt64]$Position
        hidden [FileStream]$DiskStream
        hidden [Int32]$EntryCtr
        hidden [VhdParentLocator]$CurrentParent

        VhdDynamicHeader([FileStream]$DiskStream, [UInt64]$Position) {
            $this.DiskStream = $DiskStream
            $this.Position = $Position
            $this.Reset()

            [Byte[]]$BinaryData = [Byte[]]::new([VhdDynamicHeader]::Size)
            $this.DiskStream.Position = $this.Position
            $this.DiskStream.Read($BinaryData, 0, [VhdDynamicHeader]::Size) |
                Assert-ReadByte -Comparand ([VhdDynamicHeader]::Size) -Location 'VHD dynamic header'

            if ([Encoding]::ASCII.GetString($BinaryData, [VhdDynamicHeader]::CookieOffset, [VhdDynamicHeader]::CookieSize) `
                    -eq [VhdDynamicHeader]::CookieValue `
                    -and (Test-VhdChecksum -BinaryData $BinaryData -Position 0 -Size ([VhdDynamicHeader]::Size) `
                        -ChecksumOffset ([VhdDynamicHeader]::ChecksumOffset))
            ) {
                return
            } else {
                throw [InvalidDataException]::new("Can't find valid VHD dynamic header")
            }
        }

        [Object]get_Current() {
            return $this.CurrentParent
        }
        [Boolean]MoveNext() {
            if ($this.EntryCtr -lt [VhdDynamicHeader]::EntriesCt) {
                [VhdParentLocatorEntry]$CurrentEntry = [VhdParentLocatorEntry]::new($this.DiskStream, `
                        $this.Position + [VhdDynamicHeader]::EntriesOffset + $this.EntryCtr * [VhdParentLocatorEntry]::Size)
                $this.EntryCtr++
                if ($CurrentEntry.PathType) {
                    $this.CurrentParent = [VhdParentLocator]::new($this.DiskStream, `
                            $CurrentEntry.ParentLocatorPosition, `
                            $CurrentEntry.ParentLocatorSize, `
                            $CurrentEntry.PathType)
                    return $true
                } else {
                    return $this.MoveNext()
                }
            } else {
                $this.CurrentParent = $null
                return $false
            }
        }
        [void]Reset() {
            $this.EntryCtr = 0
            $this.CurrentParent = $null
        }
    }

    class VhdParentLocatorEntry {
        <#
            .DESCRIPTION
                This class is for analyzing a single VHD file dynamic header parent locator table entry.
        #>
        hidden static [Int32]$Size = 24
        hidden static [Int32]$PlatformCodeOffset = 0
        hidden static [Int32]$PlatformCodeSize = 4
        hidden static [Int32]$SizeOffset = 8
        hidden static [Int32]$PositionOffset = 16
        static [String]$AbsWinPathKey = 'W2ku'
        static [String]$RelWinPathKey = 'W2ru'

        [String]$PathType
        [UInt64]$ParentLocatorPosition
        [UInt32]$ParentLocatorSize

        VhdParentLocatorEntry([FileStream]$DiskStream, [UInt64]$Position) {
            [Byte[]]$BinaryData = [Byte[]]::new([VhdParentLocatorEntry]::Size)
            $DiskStream.Position = $Position
            $DiskStream.Read($BinaryData, 0, [VhdParentLocatorEntry]::Size) |
                Assert-ReadByte -Comparand ([VhdParentLocatorEntry]::Size) -Location 'VHD parent locator entry'
            # Encoding.GetString may return a string of nullchars, which isn't empty, null, or white space
            $this.PathType = [Encoding]::ASCII.GetString($BinaryData, `
                    [VhdParentLocatorEntry]::PlatformCodeOffset, `
                    [VhdParentLocatorEntry]::PlatformCodeSize).TrimEnd([Char]::MinValue)
            $this.ParentLocatorPosition = [BigEndianBitConverter]::ToUInt64($BinaryData, [VhdParentLocatorEntry]::PositionOffset)
            $this.ParentLocatorSize = [BigEndianBitConverter]::ToUInt32($BinaryData, [VhdParentLocatorEntry]::SizeOffset)
            if (-not $this.PathType -or ($this.PathType -and $this.ParentLocatorPosition -and $this.ParentLocatorSize)) {
                return
            } else {
                throw [InvalidDataException]::new("Can't find VHD parent locator position or size")
            }
        }
    }

    class VhdParentLocator {
        <#
            .DESCRIPTION
                This class is for analyzing a single VHD file parent locator.
        #>
        hidden static [Int32]$Offset = 0

        [String]$PathType
        [String]$Path

        VhdParentLocator([FileStream]$DiskStream, [UInt64]$Position, [UInt32]$Size, [String]$PathType) {
            $this.PathType = $PathType
            [Byte[]]$BinaryData = [Byte[]]::new($Size)
            $DiskStream.Position = $Position
            $DiskStream.Read($BinaryData, 0, $Size) |
                Assert-ReadByte -Comparand $Size -Location 'VHD parent locator'
            # Encoding.GetString may return a string of nullchars, which isn't empty, null, or white space
            $this.Path = [Encoding]::Unicode.GetString($BinaryData, [VhdParentLocator]::Offset, $Size).TrimEnd([Char]::MinValue) `
                -replace $script:Regexes.DevicePathPrefix
            if ($this.Path) {
                return
            } else {
                throw [InvalidDataException]::new("Can't find VHD parent locator path")
            }
        }
    }
    #endregion VHD types
    #endregion types

    #region variables
    [PSObject]$ComparerScripts = [PSCustomObject]@{
        <#
			.DESCRIPTION
				This PSObject contains different scripts for the PSEqualityComparer.
		#>
        HostFullNameEquality     = {
            $args[0].HostName -eq $args[1].HostName -and $args[0].FullName -eq $args[1].FullName
        }
        FullNameEquality         = {
            $args[0].FullName -eq $args[1].FullName
        }
        FullNameTypeEquality     = {
            $args[0].FullName -eq $args[1].FullName -and $args[0].Type -eq $args[1].Type
        }
        NameCreationTimeEquality = {
            $args[0].CreationTimeUtc -eq $args[1].CreationTimeUtc -and $args[0].Name -eq $args[1].Name
        }
        NameHash                 = {
            $args[0].Name.ToUpperInvariant().GetHashCode()
        }
    }
    [List[String[]]]$ClusterNames = [List[String[]]]::new()
    [PSObject]$Regexes = [PSCustomObject]@{
        <#
			.DESCRIPTION
				This PSObject contains different regex strings and some replacements for regex matches. The regex strings are escaped, the replacements are not.
		#>
        ConfigurationFileExtension    = '\.(xml|vmcx)$'
        StateFileExtension            = '\.(vsv|bin|vm[rg]s)$'
        SmartPagingFileExtension      = '\.slp$'
        MetafileExtension             = '\.(xml|vmcx|vsv|bin|vm[rg]s|slp)$'
        DiskFileExtension             = '\.(a?vhdx?|vfd)$'
        SharedPath                    = '^\\\\[^?.]' # matches on shared paths but not raw volume identifiers
        Guid                          = '^[\dabcdef]{8}-[\dabcdef]{4}-[\dabcdef]{4}-[\dabcdef]{4}-[\dabcdef]{12}'
        ClusterStoragePath            = ':\\ClusterStorage'
        ClusterVolumePath             = '(:|\\\\[.?]\\Volume\{.*\})\\ClusterStorage'
        TrailingBackslash             = '\\$'
        WrongRawVolumeIdentifier      = '^\\\\\?'
        RawVolumeIdentifierSubstitute = '\\.'
        RawVolumeIdentifier           = '^\\\\\.'
        DevicePathPrefix              = '(?<=^\\\\)\?\\UNC\\|^\\\\\?\\(?!UNC\\)'
        Root                          = '(^[A-Z]:\\|(?<=^\\\\)[^\\]+\\)'
        LocalDeviceRootSubstitute     = '\\?\$1'
        SharedDeviceRootSubstitute    = '?\UNC\$1'
        Quote                         = '["'']'
        Drive                         = '^[A-Z]:\\$'
        WrongDrive                    = '([A-Z]:)(?!\\)'
        DriveSubstitute               = '$1\'
        WrongBackslash                = '/'
        BackslashSubstitute           = '\'
    }
    [String]$ScriptUsing = @'
using namespace System
using namespace System.Collections
using namespace System.Collections.Generic
using namespace System.Diagnostics.CodeAnalysis
using namespace System.IO
using namespace System.Management.Automation
using namespace System.Text
using namespace System.Text.RegularExpressions
'@
    [String]$ScriptLocation = '[Main script]'
    [List[HostInfo]]$ProblematicVMHosts = [List[HostInfo]]::new()
    [List[PathInfo]]$ProblematicPaths = [List[PathInfo]]::new()
    [Int32]$GuidSize = 16
    [Int32]$ChecksumSize = 4
    #endregion variables

    #region script blocks
    [ScriptBlock]$ScriptTypes = {
        [Flags()]enum EPathTypes {
            <#
                .DESCRIPTION
                    This bit flag enumeration is used to distinguish the purpose that a file or directory serves for a virtual machine.
            #>
            None = 0
            Path = 1
            MetaFile = 2
            DiskFile = 4
            Configuration = 8
            ConfigurationFile = 10
            State = 16
            StateFile = 18
            SmartPaging = 32
            SmartPagingFile = 34
            Vhd = 64
            VhdFile = 68
            Floppy = 128
            FloppyFile = 132
        }

        [Flags()]enum EHostTypes {
            <#
                .DESCRIPTION
                    This bit flag enumeration is used to distinguish between a local or remote host that is also a virtual machine host
                    and a local host that is not a virtual machine host.
            #>
            None = 0
            Local = 1
            VM = 2
        }

        enum EAvailable {
            <#
                .DESCRIPTION
                    This enumeration is used to indicate whether a host, file, or directory exists and is also accessible or not or whether this fact has never been tested.
            #>
            Unknown = 0
            Yes = 1
            No = 2
        }

        class PathInfo {
            <#
                .DESCRIPTION
                    This class contains basic directory and file informations like a simple variant of System.IO.FileSystemInfo.
                    In addition it contains information on the VM host name, usage of the file or directory by the VM (i.e. meta- or diskfile),
                    VM identifier (GUID), availability of the file or directory, and information regarding availability problems.
            #>
            [String]$HostName
            [ValidateNotNullOrEmpty()] [String]$FullName
            [ValidateNotNullOrEmpty()] [String]$DevicePath
            [ValidateNotNullOrEmpty()] [String]$Name
            [DateTime]$CreationTimeUtc
            [EPathTypes]$Type
            [Guid]$VMId
            [String]$Problem
            [EAvailable]$Available

            PathInfo([String]$HostName, [String]$FullName, [DateTime]$CreationTimeUtc, [EPathTypes]$Type, [Guid]$VMId, [EAvailable]$Available, [String]$Problem) {
                $this.HostName = $HostName
                $this.FullName = $FullName | ConvertTo-ProperPath
                if ($this.FullName -match $script:Regexes.SharedPath) {
                    $this.DevicePath = $this.FullName -replace $script:Regexes.Root, $script:Regexes.SharedDeviceRootSubstitute
                } else {
                    $this.DevicePath = $this.FullName -replace $script:Regexes.Root, $script:Regexes.LocalDeviceRootSubstitute
                }
                if ($this.FullName -match $script:Regexes.Drive) {
                    $this.Name = $this.FullName
                } else {
                    $this.Name = [Path]::GetFileName($this.FullName)
                }
                $this.CreationTimeUtc = $CreationTimeUtc
                $this.Type = $Type
                $this.VMId = $VMId
                $this.Problem = $Problem
                if ($this.Problem) {
                    $this.Available = [EAvailable]::No
                } else {
                    $this.Available = $Available
                }
            }

            [void]SetProblem([String]$Problem) {
                if (-not $this.Problem) {
                    $this.Problem = $Problem
                    $this.Available = [EAvailable]::No
                }
            }
            [String]ToString() {
                If ($this.HostName) {
                    return "'$( $this.Fullname )' on '$( $this.HostName )'"
                } else {
                    return "'$( $this.Fullname )' (shared)"
                }
            }
        }

        class PSEqualityComparer : EqualityComparer[Object] {
            <#
                .DESCRIPTION
                    This is an universal equality comparer class. In PowerShell it's not possible to define a type-safe comparer class for user defined classes defined in the
                    same script because 'PowerShell should compile a type before it can use it. So any recursion in type definition (direct or indirect) is impossible'.
                .LINK
                    https://github.com/PowerShell/PowerShell/issues/10623
                .LINK
                    https://stackoverflow.com/a/61390659/2883733
            #>
            hidden [ValidateNotNull()] [ScriptBlock]$HashScript
            hidden [ValidateNotNull()] [ScriptBlock]$CompareScript

            PSEqualityComparer([ScriptBlock]$HashScript, [ScriptBlock]$CompareScript) {
                $this.HashScript = $HashScript
                $this.CompareScript = $CompareScript
            }
            PSEqualityComparer([String]$HashScript, [String]$CompareScript) {
                <#
                    A parameter of type ScriptBlock is implicitly converted to String when transfered remotely.
                    Therefore the comparer has a constructor working with strings.
                #>
                $this.HashScript = [Scriptblock]::Create($HashScript)
                $this.CompareScript = [Scriptblock]::Create($CompareScript)
            }

            [Int32]GetHashCode([Object]$Obj) {
                return & $this.HashScript $Obj
            }
            [Boolean]Equals([Object]$Comparand0, [Object]$Comparand1) {
                return & $this.CompareScript $Comparand0 $Comparand1
            }
        }

        class VhdInfo {
            <#
                .DESCRIPTION
                    This class is a simplified version of Microsoft.Vhd.PowerShell.VirtualHardDisk providing only the essential information about a VHD or VHDX file.
            #>
            [String]$ParentPath
            [ValidateNotNullOrEmpty()] [String]$Path
            [ValidateNotNullOrEmpty()] [String]$VhdFormat
            [ValidateNotNullOrEmpty()] [String]$VhdType

            VhdInfo() {
            }
            VhdInfo([PSObject]$Vhd) {
                $this.ParentPath = $Vhd.ParentPath
                $this.Path = $Vhd.Path
                $this.VhdFormat = $Vhd.VhdFormat
                $this.VhdType = $Vhd.VhdType
            }

            [String]ToString() {
                return "Path: '$( $this.Path )', VhdFormat: '$( $this.VhdFormat )', VhdType: '$( $this.VhdType )'"
            }
        }
    }

    [ScriptBlock]$InitializeSessionScript = {
        <#
            .DESCRIPTION
                This script does initialize a PSSession at a client with all types and functions needed by the other scripts.
                It checks whether Hyper-V module is available if needed and returns the version of the PS host.
        #>
        # The following comment is for functional reasons. It must not be renamed or removed.
        #ScriptUsing
        [OutputType([Version])]

        param(
            [Parameter(Mandatory)] [String]$HostName,
            [Parameter(Mandatory)] [Boolean]$NeedsHyperVModule,
            [Parameter(Mandatory)] [PSObject]$Preferences,
            [Parameter(Mandatory)] [HashTable]$ScriptFunctions,
            [Parameter(Mandatory)] [PSObject]$Regexes,
            [Parameter(Mandatory)] [PSObject]$ComparerScripts
        )

        begin {
            #region preferences
            Set-StrictMode -Version $Preferences.StrictModeVersion
            $ErrorActionPreference = $Preferences.ErrorAction
            $DebugPreference = $Preferences.Debug
            $VerbosePreference = $Preferences.Verbose
            #endregion preferences

            #region types
            # The following comment is for functional reasons. It must not be renamed or removed.
            #ScriptTypes
            #endregion types

            #region script functions
            foreach ($ScriptFunction in $ScriptFunctions.GetEnumerator()) {
                New-Item -Path "Function:$( $ScriptFunction.Key )" -Value $ScriptFunction.Value | Out-Null
            }
            #endregion script functions

            #region functions
            function Add-Directory {
                <#
                    .DESCRIPTION
                        This function can take System.IO.DirectoryInfo, Microsoft.HyperV.PowerShell.HardDiskDrive, Microsoft.HyperV.PowerShell.VMFloppyDiskDrive,
                        Microsoft.Vhd.PowerShell.VirtualHardDisk, or PathInfo objects or absolute path strings at its Path parameter.
                        Shared directory paths are stored directly without checking.
                        For local directory paths existance and availablity of the directory is checked and a PathInfo object is stored.
                        In case of a failed check the Problem property of the PathInfo object contains further information about the error.
                #>
                [CmdletBinding()]
                [OutputType([void])]

                param(
                    [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)] [PSObject[]]$Path,
                    [Parameter()] [Switch]$RemoveFileName,
                    [Parameter()] [String]$VMNameToRemove = $null,
                    [Parameter(Mandatory)] [Boolean]$IsShared
                )

                begin {
                } process {
                    foreach ($P in $Path) {
                        [DirectoryInfo]$PathObject = $null
                        [String]$PathString = $null
                        if ($P | Get-Member -Name 'LastAccessTime') {
                            # type DirectoryInfo
                            $PathObject = $P
                            $PathString = $P.FullName
                        } elseif ($P | Get-Member -Name 'Available') {
                            # type PathInfo
                            $PathString = $P.FullName
                        } elseif ($P | Get-Member -Name 'Path') {
                            # type HardDiskDrive, VMFloppyDiskDrive, or VirtualHardDisk
                            $PathString = $P.Path
                        } else {
                            # type String
                            $PathString = $P
                        }
                        $PathString = $PathString | ConvertTo-ProperPath
                        if ($RemoveFileName) {
                            $PathString = [Path]::GetDirectoryName($PathString)
                        }
                        if ($VMNameToRemove) {
                            $PathString = $PathString -replace "\\?$( $VMNameToRemove )`$" # lop off any Local path
                        }
                        if ($KnownPaths.Add("$PathString|$( [EPathTypes]::Path )|$( [Guid]::Empty )")) {
                            if ($IsShared) {
                                Write-DatedDebug -Message " - - - - shared scan directory '$PathString'"
                                $Used.SharedScanPaths.Add($PathString)
                            } else {
                                Write-DatedDebug -Message " - - - - local scan directory '$PathString'"
                                if (-not $PathObject -or $RemoveFileName -or $VMNameToRemove) {
                                    $PathString |
                                        ConvertTo-PathInfo -HostName $HostName -Type ([EPathTypes]::Path) -Check $true |
                                        Add-PathInfo -Collection $Used.LocalScanDirectories |
                                        Out-Null
                                } else {
                                    $PathObject |
                                        ConvertTo-PathInfo -HostName $HostName -Type ([EPathTypes]::Path) |
                                        Add-PathInfo -Collection $Used.LocalScanDirectories |
                                        Out-Null
                                }
                            }
                        } else {
                            Write-DatedDebug -Message " - - - - [ALREADY REGISTERED: scan directory '$PathString']"
                        }
                    }
                } end {
                }
            }

            function Add-File {
                <#
                    .DESCRIPTION
                        This function can take System.IO.FileInfo, Microsoft.HyperV.PowerShell.HardDiskDrive, Microsoft.HyperV.PowerShell.VMFloppyDiskDrive,
                        Microsoft.Vhd.PowerShell.VirtualHardDisk, or PathInfo objects or absolute path strings at its Path parameter. For shared metafile
                        paths a PathInfo object is stored, containing the containing directory path and information about metafile type and VM identifier (GUID).
                        For local file paths existance and availablity of the file is checked and a PathInfo object is stored also. In case of a failed check
                        the Problem property of the PathInfo object contains further information about the error.
                #>
                [CmdletBinding()]
                [OutputType([void])]

                param(
                    [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)] [PSObject[]]$Path,
                    [Parameter()] [Switch]$RemoveFileName,
                    [Parameter(Mandatory)] [Boolean]$IsShared,
                    [Parameter(Mandatory)] [EPathTypes]$Type,
                    [Parameter()] [Guid]$VMId = [Guid]::Empty
                )

                begin {
                } process {
                    foreach ($P in $Path) {
                        [FileInfo]$PathObject = $null
                        [String]$PathString = $null
                        [String]$VhdProblem = $null
                        if ($P | Get-Member -Name 'LastAccessTime') {
                            # type FileInfo
                            $PathObject = $P
                            $PathString = $P.FullName
                        } elseif ($P | Get-Member -Name 'Available') {
                            # type PathInfo
                            $PathString = $P.FullName
                            $VhdProblem = $P.Problem
                        } elseif ($P | Get-Member -Name 'Path') {
                            # type HardDiskDrive, VMFloppyDiskDrive, or VirtualHardDisk
                            $PathString = $P.Path
                        } else {
                            # type String
                            $PathString = $P
                        }
                        $PathString = $PathString | ConvertTo-ProperPath
                        if ($RemoveFileName) {
                            $PathString = [Path]::GetDirectoryName($PathString)
                        }
                        if ($KnownPaths.Add("$PathString|$Type|$VMId")) {
                            if ($IsShared) {
                                if ($Type.HasFlag([EPathTypes]::MetaFile)) {
                                    Write-DatedDebug -Message " - - - - shared file directory '$PathString'"
                                    $PathString |
                                        ConvertTo-PathInfo -Type $Type -VMId $VMId -Check $false |
                                        Add-PathInfo -Collection $Used.SharedMetafileDirectories |
                                        Out-Null
                                } else {
                                    Write-DatedDebug -Message " - - - - shared file '$PathString'"
                                    $PathString |
                                        ConvertTo-PathInfo -Type $Type -Check $false |
                                        Add-PathInfo -Collection $Used.SharedDiskFiles |
                                        Out-Null
                                }
                            } else {
                                Write-DatedDebug -Message " - - - - local file '$PathString'"
                                if (-not $PathObject -or $RemoveFileName) {
                                    if ($Type.HasFlag([EPathTypes]::MetaFile)) {
                                        $PathString |
                                            ConvertTo-PathInfo -HostName $HostName -Type $Type -Check $true -Problem $VhdProblem |
                                            Add-PathInfo -Collection $Used.LocalMetaFiles |
                                            Out-Null
                                    } else {
                                        $PathString |
                                            ConvertTo-PathInfo -HostName $HostName -Type $Type -Check $true -Problem $VhdProblem |
                                            Add-PathInfo -Collection $Used.LocalDiskFiles |
                                            Out-Null
                                    }
                                } else {
                                    if ($Type.HasFlag([EPathTypes]::MetaFile)) {
                                        $PathObject |
                                            ConvertTo-PathInfo -HostName $HostName -Type $Type -Problem $VhdProblem |
                                            Add-PathInfo -Collection $Used.LocalMetaFiles |
                                            Out-Null
                                    } else {
                                        $PathObject |
                                            ConvertTo-PathInfo -HostName $HostName -Type $Type -Problem $VhdProblem |
                                            Add-PathInfo -Collection $Used.LocalDiskFiles |
                                            Out-Null
                                    }
                                }
                            }
                        } else {
                            if ($IsShared -and $Type.HasFlag([EHostTypes]::MetaFile)) {
                                Write-DatedDebug -Message " - - - - [ALREADY REGISTERED: file directory '$PathString']"
                            } else {
                                Write-DatedDebug -Message " - - - - [ALREADY REGISTERED: file '$PathString']"
                            }
                        }
                    }
                } end {
                }
            }
            #endregion functions

            #region variables
            [String]$HyperVModuleName = 'Hyper-V'
            [String]$script:HostName = $HostName
            [String]$ScriptLocation = "[InitializeSessionScript on '$( $script:HostName )']"
            [PSCustomObject]$script:Regexes = $Regexes
            [PSCustomObject]$script:ComparerScripts = $ComparerScripts
            [HashSet[String]]$KnownPaths = [HashSet[String]]::new([StringComparer]::OrdinalIgnoreCase)
            #endregion variables

            Write-DatedDebug -Message "$ScriptLocation Started" -PassThru | Write-DatedVerbose
        } process {
            if ($PSVersionTable.PSVersion -lt 5.1) {
                throw [PlatformNotSupportedException]::new("The host '$HostName' runs PowerShell version $( $PSVersionTable.PSVersion ), minimum version is 5.1.")
            }
            Write-DatedDebug -Message " - PowerShell version $( $PSVersionTable.PSVersion )"
            if ($NeedsHyperVModule) {
                if (Get-Module -Name $HyperVModuleName -ListAvailable) {
                    Write-DatedDebug -Message ' - Hyper-V module is available'
                } else {
                    throw [PlatformNotSupportedException]::new("On host '$HostName' $HyperVModuleName is not available.")
                }
            }
            [Version]$PSVersionTable.PSVersion
        } end {
            Write-DatedDebug -Message "$ScriptLocation Finished" -PassThru | Write-DatedVerbose
        }
    }

    [ScriptBlock]$GetUsedScript = {
        <#
			This script searchs the paths and files of the VM host and its VMs. Its search scope depends on the passed parameters.
			In case of locally stored files it returns detailed informations on them and their directories as PathInfo objects.
			In case of a shared location of the files, this is done only for virtual hard disk files (their name is known).
			For metafiles only information about the containing directory, the metafile type, and the identifier of the containing
			VM (GUID) is returned. These informations about shared metafiles are collected from all VM hosts before resolving the
			specific files in the ResolveSharedUsedScript.
		#>
        [OutputType([PSObject])]

        param(
            [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowNull()] [PSObject[]]$UserPaths,
            [Parameter(Mandatory)] [Boolean]$UseDefaultPaths,
            [Parameter(Mandatory)] [Boolean]$UseExistingPaths
        )

        begin {
            #region variables
            [PSObject]$Used = [PSCustomObject]@{
                SharedScanPaths           = [List[String]]::new()
                SharedMetafileDirectories = [List[PathInfo]]::new()
                SharedDiskFiles           = [List[PathInfo]]::new()
                LocalScanDirectories      = [List[PathInfo]]::new()
                LocalMetaFiles            = [List[PathInfo]]::new()
                LocalDiskFiles            = [List[PathInfo]]::new()
            }
            [String]$ScriptLocation = "[GetUsedScript on '$HostName']"
            [Boolean]$IsShared = $false
            #endregion variables

            Write-DatedDebug -Message "$ScriptLocation Started" -PassThru | Write-DatedVerbose
        } process {
            try {
                #region prepare
                $LocalVMHost = Get-VMHost
                # '(Resolve-Path {Path}).Path' may be prefixed by 'Microsoft.PowerShell.Core\FileSystem::'. Convert-Path strips it off.
                [String]$VMHostHVRegistrationPath = ($Env:ProgramData | Join-Path -ChildPath 'Microsoft\Windows\Hyper-V' | Resolve-Path).Path | Convert-Path
                #endregion prepare

                #region add directories and files
                Write-DatedDebug -Message "$ScriptLocation Scanning for files and directories used by VM host and VMs or specified by user" -PassThru |
                    Write-DatedVerbose

                #region user paths
                Write-DatedDebug -Message ' - adding user-specified directories' -PassThru | Write-DatedVerbose
                foreach ($UP in $UserPaths) {
                    if ($UP | Get-Member -Name 'FullName') {
                        $IsShared = $UP.FullName -match $Regexes.SharedPath
                    } elseif ($UP | Get-Member -Name 'Path') {
                        $IsShared = $UP.Path -match $Regexes.SharedPath
                    } else {
                        $IsShared = $UP -match $Regexes.SharedPath
                    }
                    Add-Directory -Path $UP -IsShared $IsShared
                }
                #endregion user paths

                #region host
                Write-DatedDebug -Message ' - adding VM host directories' -PassThru | Write-DatedVerbose
                if ($UseDefaultPaths) {
                    Write-DatedDebug -Message ' - - adding VM host registration directory' -PassThru | Write-DatedVerbose
                    $IsShared = $false
                    Add-Directory -Path $VMHostHVRegistrationPath -IsShared $IsShared
                    Write-DatedDebug -Message ' - - adding VM host default configuration, state, smart paging, and checkpoint directory' -PassThru |
                        Write-DatedVerbose
                    $IsShared = $LocalVMHost.VirtualMachinePath -match $Regexes.SharedPath
                    Add-Directory -Path $LocalVMHost.VirtualMachinePath -IsShared $IsShared
                    Write-DatedDebug -Message ' - - adding VM host default virtual hard drive directory' -PassThru | Write-DatedVerbose
                    $IsShared = $LocalVMHost.VirtualHardDiskPath -match $Regexes.SharedPath
                    Add-Directory -Path $LocalVMHost.VirtualHardDiskPath -IsShared $IsShared
                }
                #endregion host

                #region cluster
                Write-DatedDebug -Message ' - - adding VM host cluster shared volume directories' -PassThru | Write-DatedVerbose
                [String]$ClusterStoragePath = Join-Path -Path $Env:SystemDrive -ChildPath 'ClusterStorage'
                if (Test-Path -Path $ClusterStoragePath) {
                    $IsShared = $false
                    Get-ChildItem -Path $ClusterStoragePath -Force -ErrorAction ([ActionPreference]::Continue) | Add-Directory -IsShared $IsShared
                } else {
                    Write-DatedDebug -Message ' - - - no cluster shared volumes'
                }
                #endregion cluster

                #region VMs
                foreach ($VM in Hyper-V\Get-VM) {
                    try {
                        Write-DatedDebug -Message " - adding directories and files of '$( $VM.Name )'" -PassThru | Write-DatedVerbose

                        #region configuration files from registration location
                        Write-DatedDebug -Message ' - - adding registration configuration files' -PassThru | Write-DatedVerbose
                        [String]$RegistrationPath = Join-Path -Path $VMHostHVRegistrationPath -ChildPath 'Virtual Machines Cache'
                        $IsShared = $false
                        <#
							Advantage of using using 'Get-ChildItem -Filter {file extension}' multiple times: For less deeply nested scan paths this is faster than
							'Get-ChildItem -Include {file extensions}'. The deeper the scan path is nested, the more likely 'Get-ChildItem -Include {file extensions}' is faster.
							Disadvantage of using using 'Get-ChildItem -Filter {file extension}': In Windows PowerShell 5.1, the filter behaves according to a regex
							'\.{file extension}[^.]*'. So both file types, 'vhd' and 'vhdx' are found when filtering for '*.vhd'. In PowerShell Core 7.3, however,
							-Filter behaves according to a regex '\.{file extension}$'. So only 'vhd' file type is found.
							Advantage of using a trailing Where-Object instead of -Include parameter: the former seems to be faster according to
							https://stackoverflow.com/questions/52293871/powershell-performance-get-childitem-include-vs-get-childitem-where-object .
						#>
                        Get-ChildItem -File -Path $RegistrationPath -Force -Recurse |
                            Where-Object -Property 'Name' -Match -Value ($VM.Id.ToString() + $Regexes.ConfigurationFileExtension) |
                            Add-File -IsShared $IsShared -Type ([EPathTypes]::ConfigurationFile)
                        #endregion configuration files from registration location

                        #region configuration and state files from VM.Path and configuration location
                        if ($VM.Path -eq $VM.ConfigurationLocation) {
                            [String[]]$ConfigurationPaths = @($VM.ConfigurationLocation)
                        } else {
                            [String[]]$ConfigurationPaths = @($VM.Path, $VM.ConfigurationLocation)
                        }
                        Write-DatedDebug -Message ' - - adding configuration and state directories and files' -PassThru | Write-DatedVerbose
                        foreach ($ConfigurationPath in $ConfigurationPaths) {
                            $IsShared = $ConfigurationPath -match $Regexes.SharedPath
                            if ($UseExistingPaths) {
                                Add-Directory -Path $ConfigurationPath -IsShared $IsShared -VMNameToRemove $VM.Name
                            }
                            if ($IsShared) {
                                Add-File -Path $ConfigurationPath -IsShared $IsShared -Type ([EPathTypes]::ConfigurationFile) -Id $VM.Id
                                Add-File -Path $ConfigurationPath -IsShared $IsShared -Type ([EPathTypes]::StateFile) -Id $VM.Id
                            } else {
                                Get-ChildItem -File -Path $ConfigurationPath -Force -Recurse |
                                    Where-Object -Property 'Name' -Match -Value ($VM.Id.ToString() + $Regexes.ConfigurationFileExtension) |
                                    Add-File -IsShared $IsShared -Type ([EPathTypes]::ConfigurationFile)
                                Get-ChildItem -File -Path $ConfigurationPath -Force -Recurse |
                                    Where-Object -Property 'Name' -Match -Value ($VM.Id.ToString() + $Regexes.StateFileExtension) |
                                    Add-File -IsShared $IsShared -Type ([EPathTypes]::StateFile)
                            }
                        }
                        #endregion configuration and state files from VM.Path and configuration location

                        #region checkpoints configuration files from registration location
                        Write-DatedDebug -Message ' - - adding checkpoint registration configuration files' -PassThru | Write-DatedVerbose
                        $IsShared = $false
                        foreach ($Checkpoint in (Get-VMSnapshot -VM $VM)) {
                            Write-DatedDebug -Message " - - - checkpoint ID '$( $Checkpoint.Id )'"
                            [String]$CheckpointPath = Join-Path -Path $VMHostHVRegistrationPath -ChildPath 'Snapshots Cache'
                            Get-ChildItem -File -Path $CheckpointPath -Force -Recurse |
                                Where-Object -Property 'Name' -Match -Value ($Checkpoint.Id.ToString() + $Regexes.ConfigurationFileExtension) |
                                Add-File -IsShared $IsShared -Type ([EPathTypes]::ConfigurationFile)
                            # these files have the same name as but are not identical to these in the checkpoint location
                        }
                        #endregion checkpoints configuration files from registration location

                        #region checkpoints configuration and state files from checkpoint location
                        Write-DatedDebug -Message ' - - adding checkpoint configuration and state directories and files' -PassThru | Write-DatedVerbose
                        $IsShared = $VM.SnapshotFileLocation -match $Regexes.SharedPath
                        if ($UseExistingPaths) {
                            Add-Directory -Path $VM.SnapshotFileLocation -IsShared $IsShared -VMNameToRemove $VM.Name
                        }
                        [String]$CheckpointMetafilesPath = Join-Path -Path $VM.SnapshotFileLocation -ChildPath 'Snapshots'
                        if ($IsShared) {
                            Add-File -Path $CheckpointMetafilesPath -IsShared $IsShared -Type ([EPathTypes]::ConfigurationFile) -Id $Checkpoint.Id
                            Add-File -Path $CheckpointMetafilesPath -IsShared $IsShared -Type ([EPathTypes]::StateFile) -Id $Checkpoint.Id
                        } else {
                            foreach ($Checkpoint in (Get-VMSnapshot -VM $VM)) {
                                Write-DatedDebug -Message " - - - checkpoint ID '$( $Checkpoint.Id )'"
                                Get-ChildItem -File -Path $CheckpointMetafilesPath -Force -Recurse |
                                    Where-Object -Property 'Name' -Match -Value ($Checkpoint.Id.ToString() + $Regexes.ConfigurationFileExtension) |
                                    Add-File -IsShared $IsShared -Type ([EPathTypes]::ConfigurationFile)
                                Get-ChildItem -File -Path $CheckpointMetafilesPath -Force -Recurse |
                                    Where-Object -Property 'Name' -Match -Value ($Checkpoint.Id.ToString() + $Regexes.StateFileExtension) |
                                    Add-File -IsShared $IsShared -Type ([EPathTypes]::StateFile)
                            }
                        }
                        #endregion checkpoints configuration and state files from checkpoint location

                        #region smart paging files
                        Write-DatedDebug -Message ' - - adding smart paging directories and files' -PassThru | Write-DatedVerbose
                        $IsShared = $VM.SmartPagingFilePath -match $Regexes.SharedPath
                        if ($UseExistingPaths) {
                            Add-Directory -Path $VM.SmartPagingFilePath -IsShared $IsShared -VMNameToRemove $VM.Name
                        }
                        if ($VM.SmartPagingFileInUse) {
                            if ($IsShared) {
                                Add-File -Path $VM.SmartPagingFilePath -IsShared $IsShared -Type ([EPathTypes]::SmartPagingFile) -Id $VM.Id
                            } else {
                                Get-ChildItem -File -Path $VM.SmartPagingFilePath -Force -Recurse |
                                    Where-Object -Property 'Name' -Match -Value ($VM.Id.ToString() + '.+' + $Regexes.SmartPagingFileExtension) |
                                    Add-File -IsShared $IsShared -Type ([EPathTypes]::SmartPagingFile)
                            }
                        } else {
                            Write-DatedDebug -Message ' - - - smart paging is not active'
                        }
                        #endregion smart paging files

                        #region VM VHD and floppy files
                        Write-DatedDebug -Message ' - - adding virtual hard drive directories and files' -PassThru | Write-DatedVerbose
                        foreach ($VhdObj in (Get-VMHardDiskDrive -VM $VM)) {
                            $IsShared = $VhdObj.Path -match $Regexes.SharedPath
                            if ($IsShared) {
                                # type must not be HardDiskDrive[] due to a potential type version conflict
                                [PSObject[]]$Vhds = @($VhdObj)
                            } else {
                                [PSObject[]]$Vhds = @($VhdObj | Get-VhdChain)
                            }
                            foreach ($Vhd in $Vhds) {
                                if ($UseExistingPaths) {
                                    Add-Directory -Path $Vhd -IsShared $IsShared -RemoveFileName
                                }
                                Add-File -Path $Vhd -IsShared $IsShared -Type ([EPathTypes]::VhdFile)
                            }
                        }
                        if ($VM.Generation -lt 2) {
                            Write-DatedDebug -Message ' - - adding floppy directories and files' -PassThru | Write-DatedVerbose
                            foreach ($FloppyObj in (Get-VMFloppyDiskDrive -VM $VM)) {
                                if ($FloppyObj.Path) {
                                    $IsShared = $FloppyObj.Path -match $Regexes.SharedPath
                                    if ($UseExistingPaths) {
                                        Add-Directory -Path $FloppyObj -IsShared $IsShared -RemoveFileName
                                    }
                                    Add-File -Path $FloppyObj -IsShared $IsShared -Type ([EPathTypes]::FloppyFile)
                                }
                            }
                        }
                        #endregion VM VHD and floppy files

                        #region checkpoints VHD and floppy files
                        <#
							Checkpoint VHD files are stored in the same location as their base VHD, which may normally differ from the location of checkpoint
							configuration file. This is also assumed for checkpoint floppy files.
						#>
                        Write-DatedDebug -Message ' - - adding checkpoints virtual hard drive and floppy directories and files' -PassThru | Write-DatedVerbose
                        foreach ($Checkpoint in (Get-VMSnapshot -VM $VM)) {
                            Write-DatedDebug -Message " - - - checkpoint ID '$( $Checkpoint.Id )'"
                            foreach ($VhdObj in (Get-VMHardDiskDrive -VMSnapshot $Checkpoint)) {
                                $IsShared = $VhdObj.Path -match $Regexes.SharedPath
                                if ($UseExistingPaths) {
                                    Add-Directory -Path $VhdObj -IsShared $IsShared -RemoveFileName
                                }
                                Add-File -Path $VhdObj -IsShared $IsShared -Type ([EPathTypes]::VhdFile)
                            }
                            if ($VM.Generation -lt 2) {
                                foreach ($FloppyObj in (Get-VMFloppyDiskDrive -VMSnapshot $Checkpoint)) {
                                    if ($FloppyObj.Path) {
                                        $IsShared = $FloppyObj.Path -match $Regexes.SharedPath
                                        if ($UseExistingPaths) {
                                            Add-Directory -Path $FloppyObj -IsShared $IsShared -RemoveFileName
                                        }
                                        Add-File -Path $FloppyObj -IsShared $IsShared -Type ([EPathTypes]::FloppyFile)
                                    }
                                }
                            }
                        }
                        #endregion checkpoints VHD and floppy files
                    } catch {
                        Write-DatedWarning -Message "$ScriptLocation Error while retrieving used files and directories of '$( $VM.Name )'"
                    }
                }
                #endregion VMs
                #endregion add directories and files
            } catch {
                Write-DatedWarning -Message "$ScriptLocation Error while retrieving host data of '$( $LocalVMHost.Name )'"
            }
        } end {
            $Used.LocalScanDirectories = [PathInfo[]]@($Used.LocalScanDirectories | Remove-Subpath)
            $Used
            Write-DatedDebug -Message "$ScriptLocation Finished" -PassThru | Write-DatedVerbose
        }
    }

    [ScriptBlock]$GetOrphanedScript = {
        <#
			.DESCRIPTION
				This script retrieves orphaned files in all directories from $ScanDirectories. Some system directories are generally excluded from scan.
				When run on local scan directories, $ExcludedMetafiles and $ExcludedDiskFiles must contain all known ("good") files of the VM host the script is running on.
				In this case, $OtherExcludedMetaFiles and $OtherExcludedDiskFiles must contain all known ('good') SHARED files to exclude files and paths
				referenced both ways, shared and local.
				When running on shared scan directories, $ExcludedMetafiles and $ExcludedDiskFiles must contain all known ('good') shared files of all hosts.
				In this case, $OtherExcludedMetaFiles and $OtherExcludedDiskFiles must contain all known ('good') LOCAL files of ALL hosts, again excluding
				files and paths referenced both ways, shared and local.
		#>
        # The following comment is for functional reasons. It must not be renamed or removed.
        #ScriptUsing
        [OutputType([PSObject])]

        param(
            [Parameter(Mandatory)] [AllowEmptyCollection()] [PSObject[]]$ScanDirectories,
            [Parameter(Mandatory)] [AllowEmptyCollection()] [PSObject[]]$ExcludedMetafiles,
            [Parameter(Mandatory)] [AllowEmptyCollection()] [PSObject[]]$ExcludedDiskFiles,
            [Parameter(Mandatory)] [AllowEmptyCollection()] [PSObject[]]$OtherExcludedMetaFiles,
            [Parameter(Mandatory)] [AllowEmptyCollection()] [PSObject[]]$OtherExcludedDiskFiles,
            [Parameter(Mandatory)] [Boolean]$IgnoreClusterSharedVolumes,
            [Parameter(Mandatory)] [Boolean]$Force,
            [Parameter()] [String]$HostName = $script:HostName,
            [Parameter()] [PSObject]$Preferences,
            [Parameter()] [HashTable]$ScriptFunctions,
            [Parameter()] [PSObject]$Regexes = $script:Regexes,
            [Parameter()] [PSObject]$ComparerScripts = $script:ComparerScripts
        )

        begin {
            #region preferences
            if ($PSBoundParameters.ContainsKey('Preferences')) {
                Set-StrictMode -Version $Preferences.StrictModeVersion
                $ErrorActionPreference = $Preferences.ErrorAction
                $DebugPreference = $Preferences.Debug
                $VerbosePreference = $Preferences.Verbose
            }
            #endregion preferences

            #region types
            # The following comment is for functional reasons. It must not be renamed or removed.
            #ScriptTypes
            #endregion types

            #region script functions
            if ($PSBoundParameters.ContainsKey('ScriptFunctions')) {
                foreach ($ScriptFunction in $ScriptFunctions.GetEnumerator()) {
                    New-Item -Path "Function:$( $ScriptFunction.Key )" -Value $ScriptFunction.Value | Out-Null
                }
            }
            #endregion script functions

            #region variables
            [List[String]]$ExcludedPaths = [List[String]]::new()
            $ExcludedPaths.Add((Join-Path -Path $Env:SystemRoot -ChildPath 'vss')) # VSS writers are also registered as <guid>.xml
            $ExcludedPaths.Add((Join-Path -Path $Env:SystemRoot -ChildPath 'WinSxs')) # many things in WinSxs will trigger a response, also it takes forever to scan
            $ExcludedPaths.Add((Join-Path -Path $Env:ProgramData -ChildPath 'Microsoft\Windows\Hyper-V\Resource Types')) # HV resource types are also registered as <guid>.xml
            if ($IgnoreClusterSharedVolumes) {
                $ExcludedPaths.Add((Join-Path -Path $Env:SystemDrive -ChildPath 'ClusterStorage'))
            }
            [Guid]$DummyGuid = [Guid]::Empty
            [String]$ScriptLocation = "[GetOrphanedScript on '$( $HostName )']"
            [HashSet[PSObject]]$ExcludedMetafileSet = [HashSet[PSObject]]::new($ExcludedMetafiles, [PSEqualityComparer]::new(
                    $ComparerScripts.NameHash,
                    $ComparerScripts.FullNameEquality
                ))
            [HashSet[PSObject]]$ExcludedDiskFileSet = [HashSet[PSObject]]::new($ExcludedDiskFiles, [PSEqualityComparer]::new(
                    $ComparerScripts.NameHash,
                    $ComparerScripts.FullNameEquality
                ))
            [HashSet[PSObject]]$OtherExcludedMetaFileSet = [HashSet[PSObject]]::new($OtherExcludedMetaFiles, [PSEqualityComparer]::new(
                    $ComparerScripts.NameHash,
                    $ComparerScripts.NameCreationTimeEquality
                ))
            [HashSet[PSObject]]$OtherExcludedDiskFileSet = [HashSet[PSObject]]::new($OtherExcludedDiskFiles, [PSEqualityComparer]::new(
                    $ComparerScripts.NameHash,
                    $ComparerScripts.NameCreationTimeEquality
                ))
            #endregion variables

            Write-DatedDebug -Message "$ScriptLocation Started" -PassThru | Write-DatedVerbose
        } process {
            $Verbose = $VerbosePreference
            $VerbosePreference = [ActionPreference]::SilentlyContinue
            foreach ($ScanDirectory in ($ScanDirectories | ConvertTo-PathInfo)) {
                if (($ScanDirectory | Remove-Subpath -Comparand $ExcludedPaths)) {
                    try {
                        # Take note that the script has set ErrorActionPreference to Stop.
                        foreach ($File in (Get-ChildItem -Path $ScanDirectory.FullName -File -Force:$Force -Recurse |
                                    Where-Object -FilterScript {
                                        $_.Extension -match $Regexes.MetafileExtension `
                                            -and -not ($ExcludedMetafileSet.Contains($_) -or $OtherExcludedMetaFileSet.Contains($_))
                                    } |
                                    Remove-Subpath -Comparand $ExcludedPaths)
                        ) {
                            #VM files of this type will all be formatted as a GUID
                            [Match]$Match = [Regex]::Match($File.BaseName, $Regexes.Guid, [RegexOptions]::IgnoreCase -bor [RegexOptions]::ExplicitCapture)
                            if ($Match.Success -and [Guid]::TryParse($Match.Value, [ref]$DummyGuid)) {
                                $File
                            }
                        }
                        foreach ($File in (Get-ChildItem -Path $ScanDirectory.FullName -File -Force:$Force -Recurse |
                                    Where-Object -FilterScript {
                                        $_.Extension -match $Regexes.DiskFileExtension `
                                            -and -not ($ExcludedDiskFileSet.Contains($_) -or $OtherExcludedDiskFileSet.Contains($_))
                                    } |
                                    Remove-Subpath -Comparand $ExcludedPaths)
                        ) {
                            $File
                        }
                    } catch {
                        Write-DatedWarning -Message "$ScriptLocation Error while scanning directory '$( $ScanDirectory.FullName )', scanning this directory has been aborted"
                        $ScanDirectory.SetProblem("$( $Error[0].Exception.Message ) (scanning this directory has been aborted)")
                        $ScanDirectory
                    }
                } else {
                    Write-DatedWarning -Message "$ScriptLocation Error while scanning directory '$( $ScanDirectory.FullName )': directory is excluded from scan by design" -ErrorNr -1
                    $ScanDirectory.SetProblem('Directory is excluded by design')
                    $ScanDirectory
                }
            }
            $VerbosePreference = $Verbose
        } end {
            Write-DatedDebug -Message "$ScriptLocation Finished" -PassThru | Write-DatedVerbose
        }
    }
    #endregion script blocks

    #region functions
    function Test-Host {
        <#
			.DESCRIPTION
				This function checks if $VMHost is available.
				$VMHost may be a String, a Microsoft.HyperV.PowerShell.VMHost object, or any other object with a Name property.
				If $VMHost is member of an Active Directory and $IgnoreClusterSharedVolumes isn't set, it also collects information about any cluster domain.
				In order to scan the shared directories and files, the local host is always included in the list of hosts.
		#>
        [CmdletBinding()]
        [OutputType([HostInfo])]

        param(
            [Parameter( ValueFromPipeline, ValueFromPipelineByPropertyName)] [PSObject[]]$VMHost,
            [ParamArrayAttribute()] [Switch]$AsLocalOnly
        )

        begin {
            #region variables
            [Boolean]$GotLocalHost = $false
            #endregion variables

            if ($AsLocalOnly) {
                Write-DatedDebug -Message "$ScriptLocation Verifying local host" -PassThru | Write-DatedVerbose
            } else {
                Write-DatedDebug -Message "$ScriptLocation Verifying Hyper-V hosts" -PassThru | Write-DatedVerbose
            }
        } process {
            foreach ($Vmh in $VMHost) {
                Write-DatedDebug -Message "$ScriptLocation Verifying '$Vmh'"
                try {
                    if ($Vmh | Get-Member -Name 'Name') {
                        # type Microsoft.HyperV.PowerShell.VMHost
                        [String]$HostName = $Vmh.Name
                    } else {
                        # type String
                        [String]$HostName = $Vmh
                    }
                    [String]$QualifiedHostName = $HostName
                    [Boolean]$IsLocal = $HostName -eq $Env:ComputerName
                    # if error rises on a non-domain client: try command 'Set-Item WSMan:localhost\client\trustedhosts -value *'
                    if ($Credential) {
                        [CimSession]$Session = New-CimSession -ComputerName $HostName -Credential $Credential -Verbose:$false
                    } else {
                        [CimSession]$Session = New-CimSession -ComputerName $HostName -Verbose:$false
                    }
                    [HashTable]$Parameters = @{
                        CimSession  = $Session
                        Namespace   = 'root\CIMV2'
                        Class       = 'Win32_ComputerSystem'
                        Property    = 'Name', 'Domain', 'PartOfDomain'
                        ErrorAction = [ActionPreference]::Stop
                        Verbose     = $false
                    }
                    [CimInstance]$Client = Get-CimInstance @Parameters
                    if ($Client.PartOfDomain) {
                        $QualifiedHostName = $Client.Name + '.' + $Client.Domain
                        if (-not $IgnoreClusterSharedVolumes) {
                            try {
                                [HashTable]$Parameters = @{
                                    CimSession  = $Session
                                    Namespace   = 'root\MSCluster'
                                    Class       = 'MSCluster_Node'
                                    Property    = 'Name'
                                    ErrorAction = [ActionPreference]::Stop
                                    Verbose     = $false
                                }
                                foreach ($Node in (Get-CimInstance @Parameters)) {
                                    $ClusterNames.Add($Node.Name + '.' + $Client.Domain)
                                    Write-DatedDebug -Message " - Adding cluster node '$( $Node.Name )' to scan list"
                                    [HostInfo]::new($Node.Name, $Node.Name + '.' + $Client.Domain, [EHostTypes]::VM)
                                }
                            } catch {
                                Write-DatedDebug -Message " - - '$QualifiedHostName' isn't a cluster node"
                            }
                        }
                    } else {
                        Write-DatedDebug -Message " - - '$QualifiedHostName' isn't registered to any domain"
                    }
                    Write-DatedDebug -Message " - adding host '$QualifiedHostName' to scan list"
                    if ($IsLocal) {
                        $GotLocalHost = $true
                        if ($AsLocalOnly) {
                            [HostInfo]::new($HostName, $QualifiedHostName, [EHostTypes]::Local)
                        } else {
                            [HostInfo]::new($HostName, $QualifiedHostName, [EHostTypes]::Local -bor [EHostTypes]::VM)
                        }
                    } else {
                        [HostInfo]::new($HostName, $QualifiedHostName, [EHostTypes]::VM)
                    }
                } catch {
                    Write-DatedWarning -Message "$ScriptLocation Error while contacting '$QualifiedHostName' by WMI"
                    [HostInfo]::new($HostName, $QualifiedHostName, [EHostTypes]::None, $Error[0].Exception.Message)
                }
            }
        } end {
            if (-not $GotLocalHost) {
                if (-not $AsLocalOnly) {
                    $Env:ComputerName | Test-Host -AsLocalOnly
                } else {
                    throw [PlatformNotSupportedException]::new("Can't identify a host as local host")
                }
            }
        }
    }

    function Initialize-Session {
        <#
			.DESCRIPTION
				This function runs the InitializeSessionScript in parallel on all VM hosts.
				If an error occures its information is stored in the Problem property of $VMHost and this will be excluded from further scans of the cmdlet.
		#>
        [CmdletBinding()]
        [OutputType([HostInfo])]

        param(
            [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)] [HostInfo[]]$VMHost
        )

        begin {
        } process {
            foreach ($Vmh in $VMHost) {
                if ($Vmh.Available -eq [EAvailable]::Yes) {
                    [HashTable]$SessionParameters = @{
                        ComputerName = $Vmh.QualifiedName
                        ErrorAction  = [ActionPreference]::Stop
                    }
                    if ($Credential) {
                        $SessionParameters.Add('Credential', $Credential)
                    }
                    Write-DatedDebug -Message "$ScriptLocation Establishing a remote session on '$Vmh'" -PassThru | Write-DatedVerbose
                    $Vmh.InvokeSession($SessionParameters)
                    Write-DatedDebug -Message "$ScriptLocation Starting initialization of '$Vmh'"
                    [Object[]]$JobParameters = @(
                        $Vmh.QualifiedName,
                        $Vmh.Type.HasFlag([EHostTypes]::VM),
                        $Preferences,
                        $ScriptFunctions,
                        $Regexes,
                        $ComparerScripts
                    )
                    # https://stackoverflow.com/questions/64283089/powershell-join-scriptblocks
                    $Vmh.StartJob([ScriptBlock]::Create(($InitializeSessionScript.ToString() -replace '#ScriptUsing', $ScriptUsing -replace '#ScriptTypes', $ScriptTypes.ToString())), `
                            $JobParameters)
                    try {
                        Write-DatedDebug -Message "$ScriptLocation Retrieving data from initialization of '$Vmh'"
                        $Vmh.PSVersion = [Version]($Vmh.GetJobsResults() | Select-Object -First 1)
                        Write-DatedDebug -Message "$ScriptLocation Retrieved data from initialization of '$Vmh'" -PassThru | Write-DatedVerbose
                    } catch {
                        $Vmh.SetProblem($Error[0].Exception.Message)
                        Write-DatedWarning -Message "$ScriptLocation Error while initializing '$Vmh'"
                    }
                }
                $Vmh
            }
        } end {
        }
    }

    function Get-Used {
        <#
			.DESCRIPTION
				This function runs the GetUsedScript in parallel against all hosts marked with type [EHostTypes]::VM.
				It returns results for all hosts, sorted by the categories shared, remote, file, and directory.
		#>
        [CmdletBinding()]
        [OutputType([ResultCollections])]

        param(
        )

        begin {
            #region variables
            [ResultCollections]$ResultCollector = [ResultCollections]::new()
            #endregion variables
        } process {
            foreach ($DataVMHost in ($VMHosts | Where-Object -FilterScript { $_.Available -eq [EAvailable]::Yes -and $_.Type.HasFlag([EHostTypes]::VM) })) {
                try {
                    [Object[]]$JobParameters = @(
                        $VMPath,
                        $UseDefaultPaths,
                        $UseExistingPaths
                    )
                    Write-DatedDebug -Message "$ScriptLocation Starting scan for used directories and files on '$DataVMHost'" -PassThru | Write-DatedVerbose
                    $DataVMHost.StartJob($GetUsedScript, $JobParameters)
                } catch {
                    Write-DatedWarning -Message "$ScriptLocation Error while connecting with '$DataVMHost'"
                    $DataVMHost.SetProblem($Error[0].Exception.Message)
                }
            }
        } end {
            [HostInfo[]]$JobVMHosts = @($VMHosts | Where-Object -FilterScript { $_.HasJob() })
            if ($JobVMHosts.Count) {
                Write-DatedDebug -Message ' - retrieving used directories and files'
                foreach ($JobVMHost in $JobVMHosts) {
                    try {
                        [PSObject]$JobResult = $JobVMHost.GetJobsResults() | Select-Object -First 1
                    } catch {
                        Write-DatedWarning -Message "$ScriptLocation Error while retrieving used host and VM data from '$JobVMHost'"
                        $JobVMHost.SetProblem($Error[0].Exception.Message)
                        continue
                    }
                    Write-DatedDebug -Message "$ScriptLocation Retrieved used directories and files from '$JobVMHost'"
                    Write-DatedDebug -Message ' - merging shared directories and files'
                    try {
                        $ResultCollector.SharedScanPaths.UnionWith([String[]]$JobResult.SharedScanPaths)
                        [PSObject[]]$JobResult.SharedMetafileDirectories |
                            ConvertTo-PathInfo |
                            Add-PathInfo -Collection $ResultCollector.SharedMetafileDirectories |
                            Out-Null
                        [PSObject[]]$JobResult.SharedDiskFiles |
                            ConvertTo-PathInfo |
                            Add-PathInfo -Collection $ResultCollector.SharedDiskFiles |
                            Out-Null
                        Write-DatedDebug -Message ' - merging remote directories and files'
                        [PSObject[]]$JobResult.LocalScanDirectories |
                            ConvertTo-PathInfo |
                            Add-PathInfo -Collection $ResultCollector.RemoteScanDirectories |
                            Out-Null
                        [PSObject[]]$JobResult.LocalMetaFiles |
                            ConvertTo-PathInfo |
                            Add-PathInfo -Collection $ResultCollector.RemoteMetaFiles |
                            Out-Null
                        [PSObject[]]$JobResult.LocalDiskFiles |
                            ConvertTo-PathInfo |
                            Add-PathInfo -Collection $ResultCollector.RemoteDiskFiles |
                            Out-Null
                    } catch {
                        Write-DatedWarning -Message "$ScriptLocation Error while merging used host and VM data from '$JobVMHost'"
                        $JobVMHost.SetProblem($Error[0].Exception.Message)
                    }
                }
                Write-DatedDebug -Message "$ScriptLocation Retrieved used directories and files from all hosts" -PassThru | Write-DatedVerbose
            } else {
                Write-DatedWarning -Message "$ScriptLocation Unable to run the script for retrieving used directories and files at any host" -ErrorNr -1
            }
            $ResultCollector
        }
    }

    function Resolve-SharedUsed {
        <#
			.DESCRIPTION
				This function runs the ResolveSharedUsedScript. It adds detailed shared directory and file information from all hosts.
		#>
        [CmdletBinding()]
        [OutputType([ResultCollections])]

        param(
            [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)] [ResultCollections]$ResultCollector
        )

        begin {
        } process {
            Write-DatedDebug -Message "$ScriptLocation Start resolving shared directories and files" -PassThru | Write-DatedVerbose
            $ResultCollector.SharedScanPaths |
                ConvertTo-PathInfo -Type ([EPathTypes]::Path) -Check $true |
                Add-PathInfo -Collection $ResultCollector.SharedScanDirectories |
                Out-Null
            Write-DatedDebug -Message ' - - adding shared configuration, state, and smart paging directories and files' -PassThru | Write-DatedVerbose
            foreach ($MetafileDirectory in ($ResultCollector.SharedMetafileDirectories | Where-Object -Property 'Available' -NE -Value ([EAvailable]::No))) {
                try {
                    switch ([EPathTypes]$MetafileDirectory.Type) {
                        [EPathTypes]::ConfigurationFile {
                            foreach ($Metafile in (Get-ChildItem -File -Path $MetafileDirectory.FullName -Force -Recurse |
                                        Where-Object -Property 'Name' -Match -Value ($MetafileDirectory.VMId.ToString() + $Regexes.ConfigurationFileExtension))
                            ) {
                                if ($Metafile | ConvertTo-PathInfo -Type ([EPathTypes]::ConfigurationFile) | Add-PathInfo -Collection $ResultCollector.SharedMetaFiles) {
                                    Write-DatedDebug -Message " - - - - configuration file '$( $Metafile.FullName )'"
                                } else {
                                    Write-DatedDebug -Message " - - - - [ALREADY REGISTERED: configuration file '$( $Metafile.FullName )']"
                                }
                            }
                            continue
                        } [EPathTypes]::StateFile {
                            foreach ($Metafile in (Get-ChildItem -File -Path $MetafileDirectory.FullName -Force -Recurse |
                                        Where-Object -Property 'Name' -Match -Value ($MetafileDirectory.VMId.ToString() + $Regexes.StateFileExtension))
                            ) {
                                if ($Metafile | ConvertTo-PathInfo -Type ([EPathTypes]::StateFile) | Add-PathInfo -Collection $ResultCollector.SharedMetaFiles) {
                                    Write-DatedDebug -Message " - - - - state file '$( $Metafile.FullName )'"
                                } else {
                                    Write-DatedDebug -Message " - - - - [ALREADY REGISTERED: state file '$( $Metafile.FullName )']"
                                }
                            }
                            continue
                        } default {
                            # [EPathTypes]::SmartPagingFile
                            foreach ($Metafile in (Get-ChildItem -File -Path $MetafileDirectory.FullName -Force -Recurse |
                                        Where-Object -Property 'Name' -Match -Value ($MetafileDirectory.VMId.ToString() + '.+' + $Regexes.SmartPagingFileExtension))
                            ) {
                                if ($Metafile | ConvertTo-PathInfo -Type ([EPathTypes]::SmartPagingFile) | Add-PathInfo -Collection $ResultCollector.SharedMetaFiles) {
                                    Write-DatedDebug -Message " - - - - smart paging file '$( $Metafile.FullName )'"
                                } else {
                                    Write-DatedDebug -Message " - - - - [ALREADY REGISTERED: smart paging file '$( $Metafile.FullName )']"
                                }
                            }
                        }
                    }
                    if ($UseExistingPaths) {
                        if ($MetafileDirectory.FullName |
                                ConvertTo-PathInfo -Type ([EPathTypes]::Path) -Check $true |
                                Add-PathInfo -Collection $ResultCollector.SharedScanDirectories
                        ) {
                            Write-DatedDebug -Message " - - - - scan directory '$( $MetafileDirectory.FullName )'"
                        } else {
                            Write-DatedDebug -Message " - - - - [ALREADY REGISTERED: scan directory '$( $MetafileDirectory.FullName )']"
                        }
                    }
                } catch {
                    Write-DatedWarning -Message "$ScriptLocation Error while retrieving '$( $MetafileDirectory.FullName )'"
                    $MetafileDirectory.FullName |
                        ConvertTo-PathInfo -Type ([EPathTypes]::Path) -Check $false -Problem $Error[0].Exception.Message |
                        Add-PathInfo -Collection $ResultCollector.SharedScanDirectories |
                        Out-Null
                }
            }
            Write-DatedDebug -Message ' - - adding shared VHD and floppy directories and files' -PassThru | Write-DatedVerbose
            [PathInfo[]]$SharedDiskFiles = [PathInfo[]]::new($ResultCollector.SharedDiskFiles.Count)
            $ResultCollector.SharedDiskFiles.CopyTo($SharedDiskFiles)
            $ResultCollector.SharedDiskFiles.Clear() # otherwise the value 'Unknown' of the Available property from the already known PathInfo objects won't be updated
            foreach ($DiskFile in ($SharedDiskFiles | Where-Object -Property 'Available' -NE -Value ([EAvailable]::No))) {
                try {
                    foreach ($Vhd in ($DiskFile | Get-VhdChain -CheckShared)) {
                        if ($Vhd | Add-PathInfo -Collection $ResultCollector.SharedDiskFiles) {
                            Write-DatedDebug -Message " - - - - file '$( $Vhd.FullName )'"
                        } else {
                            Write-DatedDebug -Message " - - - - [ALREADY REGISTERED: file '$( $Vhd.FullName )']"
                        }
                        if ($UseExistingPaths) {
                            if ([Path]::GetDirectoryName($Vhd.FullName) |
                                    ConvertTo-PathInfo -Type ([EPathTypes]::Path) -Check $true |
                                    Add-PathInfo -Collection $ResultCollector.SharedScanDirectories
                            ) {
                                Write-DatedDebug -Message " - - - - scan directory '$( $Vhd.FullName )'"
                            } else {
                                Write-DatedDebug -Message " - - - - [ALREADY REGISTERED: scan directory '$( [Path]::GetDirectoryName($Vhd.FullName) )']" |
                                    Out-Null
                            }
                        }
                    }
                } catch {
                    Write-DatedWarning -Message "$ScriptLocation Error while retrieving '$( $DiskFile.FullName )'"
                    [Path]::GetDirectoryName($DiskFile) |
                        ConvertTo-PathInfo -Type ([EPathTypes]::Path) -Check $false -Problem $Error[0].Exception.Message |
                        Add-PathInfo -Collection $ResultCollector.SharedScanDirectories |
                        Out-Null
                }
            }
            Write-DatedDebug -Message "$ScriptLocation Finished resolving shared directories and files" -PassThru | Write-DatedVerbose
        } end {
            $ResultCollector
        }
    }

    function Optimize-Used {
        <#
			.DESCRIPTION
				This function removes multiple found cluster shared volumes from remote file and remote directory lists and
				it removes subpaths from shared scan directory list.
		#>
        [CmdletBinding()]
        [OutputType([ResultCollections])]

        param(
            [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)] [ResultCollections]$ResultCollector
        )

        begin {
        } process {
            Write-DatedDebug -Message "$ScriptLocation Optimizing by removing cluster duplicates or removing cluster shared volumes if switch is set"
            # eliminate scanning the same CSV locations from different hosts by retargeting all CSV scans to the first cluster node
            $ResultCollector.SetRemoteScanDirectories([PathInfo[]]@($ResultCollector.RemoteScanDirectories | Optimize-ClusterSharedVolume))
            $ResultCollector.SetRemoteMetaFiles([PathInfo[]]@($ResultCollector.RemoteMetaFiles | Optimize-ClusterSharedVolume))
            $ResultCollector.SetRemoteDiskFiles([PathInfo[]]@($ResultCollector.RemoteDiskFiles | Optimize-ClusterSharedVolume))

            Write-DatedDebug -Message "$ScriptLocation Optimizing by removing subpaths"
            $ResultCollector.SetSharedScanDirectories([PathInfo[]]@($ResultCollector.SharedScanDirectories | Remove-Subpath))

            if ($DebugPreference -ne [ActionPreference]::SilentlyContinue) {
                [PathInfo[]]$ScanDirectories = @(($ResultCollector.SharedScanDirectories + $ResultCollector.RemoteScanDirectories) |
                        Where-Object -Property 'Available' -NE -Value ([EAvailable]::No)
                )
                Write-DatedDebug -Message "$ScriptLocation Found $( $ScanDirectories.Count ) directory/ies to scan:"
                $ScanDirectories | ForEach-Object -Process { " - $_" } | Write-DatedDebug

                [PathInfo[]]$Metafiles = @(($ResultCollector.SharedMetaFiles + $ResultCollector.RemoteMetaFiles) |
                        Where-Object -FilterScript { $_.Available -eq [EAvailable]::Yes }
                )
                Write-DatedDebug -Message "$ScriptLocation Found $( $Metafiles.Count ) used configuration, state, and smart paging file(s):"
                $Metafiles | ForEach-Object -Process { " - $_" } | Write-DatedDebug

                [PathInfo[]]$DiskFiles = @(($ResultCollector.SharedDiskFiles + $ResultCollector.RemoteDiskFiles) |
                        Where-Object -FilterScript { $_.Available -eq [EAvailable]::Yes -and $_.Type.HasFlag([EPathTypes]::DiskFile) }
                )
                Write-DatedDebug -Message "$ScriptLocation Found $( $DiskFiles.Count ) used virtual hard drive and floppy file(s):"
                $DiskFiles | ForEach-Object -Process { " - $_" } | Write-DatedDebug

                [PathInfo[]]$Problematic = @(($ResultCollector.RemoteScanDirectories + `
                            $ResultCollector.SharedScanDirectories + `
                            $ResultCollector.SharedMetaFiles + `
                            $ResultCollector.SharedDiskFiles + `
                            $ResultCollector.RemoteMetaFiles + `
                            $ResultCollector.RemoteDiskFiles) |
                        Where-Object -Property 'Available' -EQ -Value ([EAvailable]::No)
                )
                Write-DatedDebug -Message "$ScriptLocation Found $( $Problematic.Count ) not available directory/ies and file(s):"
                $Problematic | ForEach-Object -Process { " - $_" } | Write-DatedDebug
            }
        } end {
            $ResultCollector
        }
    }

    function Get-Orphaned {
        <#
			.DESCRIPTION
				This function runs the GetOrphanedScript. First it runs the script against all hosts marked with type [EHostTypes]::VM for local files.
				Afterwards it runs the script against the local host for shared files. It returns the orphaned files of all hosts.
		#>
        [CmdletBinding()]
        [OutputType([ResultCollections])]

        param(
            [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)] [ResultCollections]$ResultCollector
        )

        begin {
        } process {
            [PathInfo[]]$RemoteScanDirectories = @($ResultCollector.RemoteScanDirectories |
                    Where-Object -Property 'Available' -NE -Value ([EAvailable]::No)
            )
            [PathInfo[]]$SharedScanDirectories = @($ResultCollector.SharedScanDirectories |
                    Where-Object -Property 'Available' -NE -Value ([EAvailable]::No)
            )
            if ($RemoteScanDirectories.Count + $SharedScanDirectories.Count) {
                #region get remote orphaned files
                Write-DatedDebug -Message "$ScriptLocation Scan for remote orphanded files" -PassThru | Write-DatedVerbose
                if ($RemoteScanDirectories.Count) {

                    foreach ($DataVMHost in ($VMHosts |
                                Where-Object -FilterScript { $_.Available -eq [EAvailable]::Yes -and $_.Type.HasFlag([EHostTypes]::VM) })
                    ) {
                        Write-DatedDebug -Message " - preparing scan of '$DataVMHost'"
                        if ($IgnoreClusterSharedVolumes) {
                            [Boolean]$HostIgnoreClusterSharedVolumes = $true
                        } else {
                            [Boolean]$HostIsPrimary = $false
                            foreach ($ClusterName in $ClusterNames) {
                                if ($DataVMHost.HasName($ClusterName)) {
                                    $HostIsPrimary = $true
                                    break
                                }
                            }
                            [Boolean]$HostIgnoreClusterSharedVolumes = -not $HostIsPrimary
                        }
                        [PathInfo[]]$HostScanDirectories = @($RemoteScanDirectories | Where-Object -FilterScript { $DataVMHost.HasName($_.HostName) })
                        if ($HostScanDirectories.Count) {
                            [PathInfo[]]$HostMetafiles = @($ResultCollector.RemoteMetaFiles |
                                    Where-Object -FilterScript { $_.Available -eq [EAvailable]::Yes `
                                            -and $DataVMHost.HasName($_.HostName)
                                    })
                            [PathInfo[]]$HostDiskFiles = @($ResultCollector.RemoteDiskFiles |
                                    Where-Object -FilterScript { $_.Available -eq [EAvailable]::Yes `
                                            -and $DataVMHost.HasName($_.HostName)
                                    })
                            if ($DebugPreference -ne [ActionPreference]::SilentlyContinue) {
                                Write-DatedDebug -Message ' - - host-specific directories to scan:'
                                $HostScanDirectories | ForEach-Object -Process { " - - - $( $_.FullName )" } | Write-DatedDebug
                                Write-DatedDebug -Message ' - - host-specific configuration, state, and smart paging file exclusions:'
                                $HostMetafiles | ForEach-Object -Process { " - - - $( $_.FullName )" } | Write-DatedDebug
                                Write-DatedDebug -Message ' - - host-specific virtual hard drive and floppy file exclusions:'
                                $HostDiskFiles | ForEach-Object -Process { " - - - $( $_.FullName )" } | Write-DatedDebug
                            }

                            [Object[]]$Parameters = @(
                                $HostScanDirectories,
                                $HostMetafiles,
                                $HostDiskFiles,
                                $ResultCollector.SharedMetaFiles,
                                $ResultCollector.SharedDiskFiles,
                                $HostIgnoreClusterSharedVolumes,
                                $Force
                            )
                            Write-DatedDebug -Message "$ScriptLocation Starting scan for remote orphaned files of '$DataVMHost' in $( $HostScanDirectories.Count ) directory/ies" -PassThru |
                                Write-DatedVerbose
                            $DataVMHost.StartJob($GetOrphanedScript, $Parameters)
                        } else {
                            Write-DatedWarning -Message "$ScriptLocation '$DataVMHost' has no directories to scan" -ErrorNr -1
                        }
                    }
                } else {
                    Write-DatedDebug -Message ' - no remote directories to scan'
                }
                #endregion get remote orphaned files

                #region get shared orphaned files
                Write-DatedDebug -Message "$ScriptLocation Scan for shared orphanded files" -PassThru | Write-DatedVerbose
                if ($SharedScanDirectories.Count) {
                    [HostInfo]$LocalVMHost = $VMHosts |
                        Where-Object -FilterScript { $_.Available -eq [EAvailable]::Yes -and $_.Type.HasFlag([EHostTypes]::Local) } |
                        Select-Object -First 1
                    if ($LocalVMHost) {
                        Write-DatedDebug -Message ' - preparing shared scan'
                        [PathInfo[]]$SharedMetafiles = @($ResultCollector.SharedMetaFiles |
                                Where-Object -FilterScript { $_.Available -eq [EAvailable]::Yes }
                        )
                        [PathInfo[]]$SharedDiskFiles = @($ResultCollector.SharedDiskFiles |
                                Where-Object -FilterScript { $_.Available -eq [EAvailable]::Yes }
                        )
                        if ($DebugPreference -ne [ActionPreference]::SilentlyContinue) {
                            Write-DatedDebug -Message ' - - shared directories to scan:'
                            $SharedScanDirectories | ForEach-Object -Process { " - - - $( $_.FullName )" } | Write-DatedDebug
                            Write-DatedDebug -Message ' - - shared configuration, state, and smart paging file exclusions:'
                            $SharedMetafiles | ForEach-Object -Process { " - - - $( $_.FullName )" } | Write-DatedDebug
                            Write-DatedDebug -Message ' - - shared virtual hard drive and floppy file exclusions:'
                            $SharedDiskFiles | ForEach-Object -Process { " - - - $( $_.FullName )" } | Write-DatedDebug
                        }
                        [Object[]]$Parameters = @(
                            $SharedScanDirectories,
                            $SharedMetafiles,
                            $SharedDiskFiles,
                            $ResultCollector.RemoteMetaFiles,
                            $ResultCollector.RemoteDiskFiles,
                            $IgnoreClusterSharedVolumes,
                            $Force,
                            $LocalVMHost.QualifiedName,
                            $Preferences,
                            $ScriptFunctions,
                            $Regexes,
                            $ComparerScripts
                        )
                        Write-DatedDebug -Message "$ScriptLocation Starting scan for shared orphands files on '$LocalVMHost' in $( $SharedScanDirectories.Count ) directory/ies" -PassThru |
                            Write-DatedVerbose
                        $LocalVMHost.StartJobNoSession([ScriptBlock]::Create(($GetOrphanedScript.ToString() -replace '#ScriptUsing', $ScriptUsing -replace '#ScriptTypes', $ScriptTypes.ToString())), `
                                $Parameters)
                    }
                } else {
                    Write-DatedDebug -Message ' - no shared directories to scan'
                }
                #endregion get shared orphaned files

                #region retrieve orphaned files and problematic paths
                Write-DatedDebug -Message "$ScriptLocation Retrieving remote and shared orphaned files from all hosts"
                foreach ($JobVMHost in $VMHosts | Where-Object -FilterScript { $_.HasJob() }) {
                    foreach ($Path in $JobVMHost.GetJobsResults()) {
                        if (($Path | Get-Member -Name 'Problem') -and $Path.Problem) {
                            if ($Path.FullName -match $Regexes.SharedPath) {
                                $Path |
                                    ConvertTo-PathInfo |
                                    Add-PathInfo -Collection $ResultCollector.SharedScanDirectories |
                                    Out-Null
                            } else {
                                $Path |
                                    ConvertTo-PathInfo |
                                    Add-PathInfo -Collection $ResultCollector.RemoteScanDirectories |
                                    Out-Null
                            }
                        } else {
                            [void]$ResultCollector.OrphanedFiles.Add($Path)
                        }
                    }
                }
                Write-DatedDebug -Message "$ScriptLocation Retrieved remote and shared orphaned files from all hosts" -PassThru | Write-DatedVerbose
                #endregion retrieve orphaned files and problematic paths
            } else {
                Write-DatedWarning -Message "$ScriptLocation Missing any directory information to scan, specified by user or read from the VM hosts" -ErrorNr -1
            }
        } end {
            $ResultCollector
        }
    }

    function Ensure-SuffixedBackslash {
        <#
			.DESCRIPTION
				This function appends the path transmitted over the pipe with a backslash if it doesn't already end with one.
				The path is then forwarded via the pipe.
		#>
        [CmdletBinding()]
        [OutputType([String])]
        [SuppressMessage('PSUseApprovedVerbs', '', Justification = 'https://github.com/PowerShell/PowerShell/issues/11710')]

        param(
            [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)] [String[]]$Path
        )

        begin {
        } process {
            foreach ($P in $Path) {
                if ($P.EndsWith('\')) {
                    $P
                } else {
                    "$P\"
                }
            }
        } end {
        }
    }

    function ConvertTo-ProperPath {
        <#
			.DESCRIPTION
				This function cleans up path entries for use with later functions and cmdlets:
				 - raw volume identifiers might come in with a '?' but must go out with a '.' (dot)
				 - it removes single and double quotes
				 - it replaces slashs with backslashs
				 - it removes trailing backslashs except from drive only paths as 'C:/'
				 - it corrects drive-specification from e.g. 'C:Windows' to 'C:\Windows' or 'C:' to 'C:\'
		#>
        [CmdletBinding()]
        [OutputType([String])]

        param(
            [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)] [String[]]$Path
        )

        begin {
        } process {
            foreach ($P in $Path) {
                $P -replace $Regexes.Quote `
                    -replace $Regexes.WrongBackslash, $Regexes.BackslashSubstitute `
                    -replace $Regexes.TrailingBackslash `
                    -replace $Regexes.WrongRawVolumeIdentifier, $Regexes.RawVolumeIdentifierSubstitute `
                    -replace $Regexes.WrongDrive, $Regexes.DriveSubstitute
            }
        } end {
        }
    }

    function ConvertTo-PathInfo {
        <#
			.DESCRIPTION
				This function returns PathInfo objects out of System.IO.FileSystemInfo, another PathInfo object, or a path string.
				In the case of path strings the existance and availability of the directory or file can be checked. If this check fails,
				the Problem property of the returned PathInfo object contains information about the error.
				If no check is performed on a path string, its Available property is 'Unknown' and its availability must be checked later on.
		#>
        [CmdletBinding()]
        [OutputType([PathInfo])]

        param(
            [Parameter(ParameterSetName = 'PSObject', Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
            [Parameter(ParameterSetName = 'Path', Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
            [Parameter(ParameterSetName = 'FileSystemInfo', Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
            [PSObject[]]$Path,
            [Parameter(ParameterSetName = 'Path', Mandatory)]
            [Parameter(ParameterSetName = 'FileSystemInfo', Mandatory)]
            [EPathTypes]$Type,
            [Parameter(ParameterSetName = 'Path', Mandatory)]
            [Boolean]$Check,
            [Parameter(ParameterSetName = 'Path')]
            [Parameter(ParameterSetName = 'FileSystemInfo')]
            [String]$HostName = [String]::Empty,
            [Parameter(ParameterSetName = 'Path')]
            [Guid]$VMId = [Guid]::Empty,
            [Parameter(ParameterSetName = 'Path')]
            [Parameter(ParameterSetName = 'FileSystemInfo')]
            [String]$Problem = [String]::Empty
        )

        begin {
        } process {
            foreach ($P in $Path) {
                switch ($PSCmdlet.ParameterSetName) {
                    'PSObject' {
                        [PathInfo]::new($P.HostName, $P.FullName, $P.CreationTimeUtc, $P.Type, $P.VMId, $P.Available, $P.Problem)
                        continue
                    } 'Path' {
                        if ($Check) {
                            try {
                                [FileSystemInfo]$DirectoryOrFile = $P | ConvertTo-ProperPath | Get-Item -Force
                                [PathInfo]::new($HostName, $DirectoryOrFile.FullName, $DirectoryOrFile.CreationTimeUtc, $Type, $VMId, [EAvailable]::Yes, [String]::Empty)
                            } catch {
                                Write-DatedWarning -Message "$script:ScriptLocation Error while retrieving '$P'"
                                [PathInfo]::new($HostName, $P, [DateTime]::MinValue, $Type, $VMId, [EAvailable]::No, $Error[0].Exception.Message)
                            }
                        } else {
                            [PathInfo]::new($HostName, $P, [DateTime]::MinValue, $Type, $VMId, [EAvailable]::Unknown, $Problem)
                        }
                        continue
                    } default {
                        # 'FileSystemInfo'
                        [PathInfo]::new($HostName, $P.FullName, $P.CreationTimeUtc, $Type, [Guid]::Empty, [EAvailable]::Yes, $Problem)
                    }
                }
            }
        } end {
        }
    }

    function Add-PathInfo {
        <#
			.DESCRIPTION
				This function adds a PathInfo object to $Collection if not already contained, based of the properties of the equality comparer of $Collection.
				If $Path contains error information in its Problem property, an object that may be recognized as equal in $Collection is exchanged for the former.
		#>
        [CmdletBinding()]
        [OutputType([Boolean])]

        param(
            [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)] [PathInfo[]]$Path,
            [Parameter(Mandatory)] [AllowEmptyCollection()] [ICollection[Pathinfo]]$Collection
        )

        begin {
        } process {
            foreach ($P in $Path) {
                if ($P.Available -eq [EAvailable]::No) {
                    [Boolean]$Removed = $Collection.Remove($P)
                    if ($Collection -is [HashSet[PathInfo]]) {
                        $Collection.Add($P) -and -not $Removed
                    } else {
                        $Collection.Add($P)
                        $true -and -not $Removed
                    }
                } else {
                    if ($Collection -is [HashSet[PathInfo]]) {
                        $Collection.Add($P)
                    } else {
                        $Collection.Add($P)
                        $true
                    }
                }
            }
        } end {
        }
    }

    function Optimize-ClusterSharedVolume {
        <#
			.DESCRIPTION
				This function resets all items that target '*\clusterstorage\*' so that the same location isn't scanned from multiple nodes or false
				positives returned. Also, if the IgnoreClusterSharedVolumes flag is set, these items are simply removed so that they won't be scanned at all.
		#>
        [CmdletBinding()]
        [OutputType([PathInfo])]

        param(
            [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)] [PathInfo[]]$Path
        )

        begin {
        } process {
            foreach ($P in $Path) {
                if ($P.FullName -match $Regexes.ClusterStoragePath) {
                    if (-not $IgnoreClusterSharedVolumes) {
                        foreach ($ClusterName in $ClusterNames) {
                            if ($ClusterName -ne $P.HostName) {
                                $P.HostName = $ClusterName
                                $P
                            } else {
                                $P
                            }
                        }
                    }
                } else {
                    $P
                }
            }
        } end {
        }
    }

    function Remove-Subpath {
        <#
			.DESCRIPTION
				This function only forwards the path transmitted over the pipe if it is not a subpath of one of the paths in $Comparand.
				The piped path and these in $Comparand can be of type String, System.IO.FileSystemInfo, or PathInfo.
				In the case of a PathInfo object, the HostName property is involved in deciding whether there is a subpath.

            .PARAMETER Comparand
				If this parameter is omitted, $Path list is compared to itself. In this case, duplicates in $Path are filtered out.

            .PARAMETER AllowSame
				This switch is for internal use only and must not be set from outside the function.
		#>
        [CmdletBinding()]
        [OutputType([String], [PathInfo], [FileSystemInfo])]
        [SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = "Doesn't apply")]

        param(
            [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)] [AllowEmptyCollection()] [PSObject[]]$Path,
            [Parameter()] [PSObject[]]$Comparand = $null,
            [Parameter()] [Switch]$AllowSame
        )

        begin {
            if ($null -eq $Comparand) {
                [List[PSObject]]$Paths = [List[PSObject]]::new()
                [HashSet[String]]$KnownPaths = [HashSet[String]]::new([StringComparer]::OrdinalIgnoreCase)
            }
            if ($AllowSame) {
                [String]$ComparandSuffix = '?*'
            } else {
                [String]$ComparandSuffix = '*'
            }
        } process {
            foreach ($P in $Path) {
                [String]$ExaminedHostName = $null
                if ($P | Get-Member -Name 'FullName') {
                    # type FileSystemInfo or PathInfo
                    [String]$ExaminedPath = $P.FullName | Ensure-SuffixedBackslash
                    if (($P | Get-Member -Name 'HostName') -and $P.HostName) {
                        $ExaminedHostName = $P.HostName
                    }
                } else {
                    # type String
                    [String]$ExaminedPath = $P | Ensure-SuffixedBackslash
                }
                if ($null -ne $Comparand) {
                    [Boolean]$IsSubpath = $false
                    foreach ($C in $Comparand) {
                        [String]$ComparedHostName = $null
                        if ($C | Get-Member -Name 'FullName') {
                            # type FileSystemInfo or PathInfo
                            [String]$ComparedPath = $C.FullName
                            if (($C | Get-Member -Name 'HostName') -and $C.HostName) {
                                $ComparedHostName = $C.HostName
                            }
                        } else {
                            # type String
                            [String]$ComparedPath = $C
                        }
                        if ($ExaminedHostName -eq $ComparedHostName `
                                -and $ExaminedPath -like ($ComparedPath | Ensure-SuffixedBackslash) + $ComparandSuffix) {
                            $IsSubpath = $true
                            break
                        }
                    }
                    if (-not $IsSubpath) {
                        $P
                    }
                } else {
                    if ($KnownPaths.Add("$ExaminedHostName|$ExaminedPath")) {
                        $Paths.Add($P)
                    }
                }
            }
        } end {
            if ($null -eq $Comparand) {
                $Paths | Remove-Subpath -Comparand $Paths -AllowSame
            }
        }
    }

    function Get-SharedVhd {
        <#
            .DESCRIPTION
                This function evaluates a shared virtual hard disk drive file where (Get-Vhd ...).ParentPath doesn't work.
                It returns a VhdInfo object which is a simple variant of Microsoft.Vhd.PowerShell.VirtualHardDisk object containing only the most
                important properties of the virtual hard disk drive (e.g. ParentPath).
            .NOTES
                Technical information was taken from:
                 - Virtual Hard Disk Image Format Specification - October 11, 2006 - Version 1.0
                 - [MS-VHDX]: Virtual Hard Disk v2 (VHDX) File Format - Release: October 3, 2022
            .LINK
                https://www.microsoft.com/en-us/download/details.aspx?id=23850
            .LINK
                https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx
        #>
        [CmdletBinding()]
        [OutputType([VhdInfo])]

        param(
            [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)] [String[]]$Path
        )

        begin {
        } process {
            foreach ($P in $Path) {
                [VhdxFile]$VhdxFile = [VhdxFile]::new($P)
                try {
                    if ($VhdxFile.Validate()) {
                        $VhdxFile.Info
                        return
                    }
                } finally {
                    $VhdxFile.Dispose()
                }
                [VhdFile]$VhdFile = [VhdFile]::new($P)
                try {
                    if ($VhdFile.Validate()) {
                        $VhdFile.Info
                        return
                    }
                } finally {
                    $VhdFile.Dispose()
                }
                throw [InvalidDataException]::new("$P is neither a VHD nor a VHDX file")
            }
        } end {
        }
    }

    function Get-VhdChain {
        <#
            .DESCRIPTION
                This function takes path strings or Microsoft.HyperV.PowerShell.HardDiskDrive, System.IO.FileInfo, or PathInfo objects
                representing a virtual hard disk drive. First of all it return a PathInfo object representing the initial virtual hard
                disk drive file. After this it returns the chain of parents drives, if exist, also as PathInfo objects.
                Locally stored virtual hard disk drive files are checked for accessablility, shared one only with switch $CheckShared.
                If the search for a parent drive fails, the returned PathInfo object contains error information in its Problem property.
        #>
        [CmdletBinding()]
        [OutputType([PathInfo])]

        param(
            [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)] [Alias('Path')] [PSObject[]]$Vhd,
            [Parameter()] [Switch]$CheckShared
        )

        begin {
        } process {
            foreach ($V in $Vhd) {
                [FileInfo]$PathObject = $null
                [String]$PathString = $null
                if ($V | Get-Member -Name 'Path') {
                    # type HardDiskDrive
                    $PathString = $V.Path
                } elseif ($V | Get-Member -Name 'LastAccessTime') {
                    # type FileInfo
                    $PathObject = $V
                    $PathString = $V.FullName
                } elseif ($V | Get-Member -Name 'FullName') {
                    # type PathInfo
                    $PathString = $V.FullName
                } else {
                    # type String
                    $PathString = $V
                }
                $PathString = $PathString | ConvertTo-ProperPath
                try {
                    do {
                        Write-DatedDebug -Message " - - - checking for parent virtual hard drive of '$( $PathString )'"
                        if ($local:PathObject) {
                            $PathObject | ConvertTo-PathInfo -Type ([EPathTypes]::VhdFile)
                            $PathObject = $null
                        } else {
                            $PathString |
                                ConvertTo-PathInfo -Type ([EPathTypes]::VhdFile) -Check ($PathString -notmatch $Regexes.SharedPath -or $CheckShared)
                        }
                        if ($PathString -match $Regexes.SharedPath) {
                            [VhdInfo]$VhdObject = $PathString | Get-SharedVhd
                        } else {
                            # Get-Vhd can only operate on raw volume identifiers with a period
                            try {
                                [VhdInfo]$VhdObject = [VhdInfo]::new(($PathString | Get-VHD | Select-Object -First 1))
                            } catch [VirtualisationException] {
                                throw [ItemNotFoundException]::new("The directory '$PathString' doesn't exist or access is denied.")
                            }
                        }
                        $PathString = $VhdObject.ParentPath
                        if ($PathString) {
                            Write-DatedDebug -Message " - - - parent '$( $VhdObject.ParentPath )' found for '$VhdObject', traversing chain"
                        } else {
                            Write-DatedDebug -Message " - - - no parent found for '$VhdObject'"
                        }
                    } while ($PathString)
                } catch {
                    Write-DatedWarning -Message "$ScriptLocation Error while retrieving '$PathString'"
                    $PathString | ConvertTo-PathInfo -Type ([EPathTypes]::VhdFile) -Check $false -Problem $Error[0].Exception.Message
                }
            }
        } end {
        }
    }

    function Test-VhdxChecksum {
        <#
            .DESCRIPTION
                This function verifies VHDX CRC32C checksums. The size of the stored checksum has to be 4 bytes (UInt32).
        #>
        [CmdletBinding()]
        [OutputType([Boolean])]

        param(
            [Parameter(Mandatory)] [Byte[]]$BinaryData,
            [Parameter(Mandatory)] [UInt64]$Position,
            [Parameter(Mandatory)] [UInt64]$Size,
            [Parameter(Mandatory)] [UInt64]$ChecksumOffset
        )

        begin {
        } process {
            [Byte[]]$TestData = [Byte[]]::new($Size)
            [Buffer]::BlockCopy($BinaryData, `
                    $Position, `
                    $TestData, `
                    0, `
                    $Size)
            [Buffer]::BlockCopy([Byte[]]::new($script:ChecksumSize), `
                    0, `
                    $TestData, `
                    $ChecksumOffset, `
                    $script:ChecksumSize)
            [UInt32]$StoredChecksum = [BitConverter]::ToUInt32($BinaryData, $Position + $ChecksumOffset)
            [UInt32]$CalculatedChecksum = $TestData | Get-Crc32C
        } end {
            $CalculatedChecksum -eq $StoredChecksum
        }
    }

    function Get-Crc32C {
        <#
            .DESCRIPTION
                This function calculates the CRC of the input data using the CRC32C algorithm.
                This is original CRC32-IEEE algorithm revised by Castagnioli (changed polynomial).
                This algorithm is using the reversed polynomial due to run at little endian systems.
            .NOTES
                C to PowerShell conversion based on code in https://www.w3.org/TR/PNG/#D-CRCAppendix
                Author: Øyvind Kallstad
                Date: 06.02.2017
                Version: 1.0
            .LINK
                https://www.w3.org/TR/PNG/#D-CRCAppendix
            .LINK
                https://communary.net/2017/02/12/calculate-crc32-in-powershell/
        #>
        [CmdletBinding()]
        [OutputType([UInt32])]

        param (
            [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)][Byte[]]$InputObject
        )

        begin {
            #region variables
            if (-not (Test-Path -Path 'Variable:\Crc32CLookup')) {
                $script:Crc32CLookup = Get-Crc32CLookup
            }
            [UInt32]$Initial = 0xFFFFFFFFL
            [UInt32]$Complement = 0xFFFFFFFFL
            [UInt32]$Crc = $Initial
            [UInt32]$ByteMask = 0xFF
            #endregion variables
        } process {
            foreach ($Byte in $InputObject) {
                $Crc = $Crc32CLookup[($Crc -bxor $Byte) -band $ByteMask] -bxor ($Crc -shr 8)
            }
        } end {
            $Crc -bxor $Complement
        }
    }

    function Get-Crc32CLookup {
        <#
            .DESCRIPTION
                This function calculates the CRC lookup table.
        #>
        [CmdletBinding()]
        [OutputType([UInt32[]])]

        param (
        )

        begin {
            [Int32]$EntriesCt = 256
            [Int32]$BitsCt = 8
            [UInt32[]]$Lookup = [UInt32[]]::new($EntriesCt)
            [UInt32]$Polynomial = 0x82F63B78L # 0x82F63B78L = reversed polynomial by Castagnoli, 0xEDB88320L = reversed polynomial from original IEEE algorithm
        } process {
            for ($EntryCtr = 0; $EntryCtr -lt $EntriesCt; $EntryCtr++) {
                [UInt32]$Entry = $EntryCtr
                for ($BitCtr = 0; $BitCtr -lt $BitsCt; $BitCtr++) {
                    if ($Entry -band 1) {
                        $Entry = $Polynomial -bxor ($Entry -shr 1)
                    } else {
                        $Entry = $Entry -shr 1
                    }
                }
                $Lookup[$EntryCtr] = $Entry
            }
        } end {
            $Lookup
        }
    }

    function Test-VhdChecksum {
        <#
            .DESCRIPTION
                This function verifies VHD checksums. The size of the stored checksum has to be 4 bytes (UInt32).
        #>
        [CmdletBinding()]
        [OutputType([Boolean])]

        param(
            [Parameter(Mandatory)] [Byte[]]$BinaryData,
            [Parameter(Mandatory)] [UInt64]$Position,
            [Parameter(Mandatory)] [UInt64]$Size,
            [Parameter(Mandatory)] [UInt64]$ChecksumOffset
        )

        begin {
        } process {
            [Byte[]]$TestData = [Byte[]]::new($Size)
            [Buffer]::BlockCopy($BinaryData, `
                    $Position, `
                    $TestData, `
                    0, `
                    $Size)
            [Buffer]::BlockCopy([Byte[]]::new($script:ChecksumSize), `
                    0, `
                    $TestData, `
                    $ChecksumOffset, `
                    $script:ChecksumSize)
            [UInt32]$StoredChecksum = [BigEndianBitConverter]::ToUInt32($BinaryData, $Position + $ChecksumOffset)
            [UInt32]$CalculatedChecksum = $TestData | Get-Checksum
        } end {
            $CalculatedChecksum -eq $StoredChecksum
        }
    }

    function Get-Checksum {
        <#
            .DESCRIPTION
                This function calculates just a one’s complement of the sum of all the bytes in $InputObject.
                from: Virtual Hard Disk Image Format Specification - October 11, 2006 - Version 1.0
        #>
        [CmdletBinding()]
        [OutputType([UInt32])]

        param (
            [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)][Byte[]]$InputObject
        )

        begin {
            #region variables
            [UInt32]$UInt32Mask = 0xFFFFFFFFL
            [UInt32]$Complement = 0xFFFFFFFFL
            [UInt64]$Checksum = 0
            #endregion variables
        } process {
            foreach ($Byte in $InputObject) {
                $Checksum = ($Checksum + $Byte) -band $UInt32Mask
            }
        } end {
            $Checksum -bxor $Complement
        }
    }

    function Assert-ReadByte {
        <#
            .DESCRIPTION
                This function throws an EndOfStreamException if the piped amount does not match $Comparand.
                Otherwise, the piped amount is passed through.
        #>
        [CmdletBinding()]
        [OutputType([UInt64], [void])]

        param (
            [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)] [UInt64]$Count,
            [Parameter(Mandatory)] [UInt64]$Comparand,
            [Parameter(Mandatory)] [String]$Location,
            [Parameter()] [Switch]$PassThru
        )

        begin {
        } process {
            if ($Count -ne $Comparand) {
                throw [EndOfStreamException]::new("Read $Count instead of $Comparand bytes for '$Location'.")
            } elseif ($PassThru) {
                $Count
            }
        } end {
        }
    }

    function Write-DatedVerbose {
        <#
			.DESCRIPTION
				This function write verbose information to the PS host, prefixed with current date and time.
		#>
        [CmdletBinding()]
        [OutputType([String], [void])]

        param(
            [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)] [String[]]$Message,
            [Parameter()] [Switch]$PassThru
        )

        begin {
        } process {
            foreach ($M in $Message) {
                if ($VerbosePreference -ne [ActionPreference]::SilentlyContinue) {
                    Write-Verbose -Message ((Get-Date -Format 'dd.MM.yyyy HH:mm:ss.fff') + ' ' + $M)
                }
                if ($PassThru) {
                    $M
                }
            }
        } end {
        }
    }

    function Write-DatedDebug {
        <#
			.DESCRIPTION
				This function writes debug information to the PS host, preceded by the current date and time.
		#>
        [CmdletBinding()]
        [OutputType([String], [void])]

        param(
            [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)] [String[]]$Message,
            [Parameter()] [Switch]$PassThru
        )

        begin {
        } process {
            foreach ($M in $Message) {
                if ($DebugPreference -ne [ActionPreference]::SilentlyContinue) {
                    Write-Debug -Message "  $( Get-Date -Format 'dd.MM.yyyy HH:mm:ss.fff' ) $M"
                }
                if ($PassThru) {
                    $M
                }
            }
        } end {
        }
    }

    function Write-DatedWarning {
        <#
			.DESCRIPTION
				This function writes warning information to the PS host, preceded by the current date and time and appended with the exception message,
				category information, and a stack trace. If $ErrorNr is set to -1, the additional error information is omitted.
		#>
        [CmdletBinding()]
        [OutputType([String], [void])]

        param(
            [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)] [String[]]$Message,
            [Parameter()] [Int32]$ErrorNr = 0,
            [Parameter()] [Switch]$PassThru
        )

        begin {
        } process {
            foreach ($M in $Message) {
                if ($ErrorNr -ge 0) {
                    Write-Warning -Message @"
$( Get-Date -Format 'dd.MM.yyyy HH:mm:ss.fff' ) $M
	Exception message: $( $Error[$ErrorNr].Exception.Message )
	Category info: $( $Error[$ErrorNr].CategoryInfo )
	Stack trace:
$( $Error[$ErrorNr].ScriptStackTrace )
"@
                } else {
                    Write-Warning -Message ((Get-Date -Format 'dd.MM.yyyy HH:mm:ss.fff') + ' ' + $M)
                }
                if ($PassThru) {
                    $M
                }
            }
        } end {
        }
    }
    #endregion functions

    #region script functions
    [HashTable]$ScriptFunctions = @{
        <#
			.NOTES
				As Env in ${Env:ComputerName} denotes a provider of environment variables, 'Function' denotes the provider of functions.
			.LINK
				https://community.spiceworks.com/topic/2358479-powershell-function-not-being-recognized-when-script-is-run
			.LINK
				http://powershellcookbook.com/recipe/Ipun/access-environment-variables
			.LINK
				https://stefanstranger.github.io/2020/07/11/PowerShellVariablesLevel400/
		#>
        ${Function:ConvertTo-ProperPath}.Ast.Name     = ${Function:ConvertTo-ProperPath}.ToString()
        ${Function:Write-DatedVerbose}.Ast.Name       = ${Function:Write-DatedVerbose}.ToString()
        ${Function:Write-DatedDebug}.Ast.Name         = ${Function:Write-DatedDebug}.ToString()
        ${Function:Write-DatedWarning}.Ast.Name       = ${Function:Write-DatedWarning}.ToString()
        ${Function:Ensure-SuffixedBackslash}.Ast.Name = ${Function:Ensure-SuffixedBackslash}.ToString()
        ${Function:Remove-Subpath}.Ast.Name           = ${Function:Remove-Subpath}.ToString()
        ${Function:ConvertTo-PathInfo}.Ast.Name       = ${Function:ConvertTo-PathInfo}.ToString()
        ${Function:Add-PathInfo}.Ast.Name             = ${Function:Add-PathInfo}.ToString()
        ${Function:Get-VhdChain}.Ast.Name             = ${Function:Get-VhdChain}.ToString()
    }
    #endregion script functions

    Write-DatedDebug -Message "$ScriptLocation Started" -PassThru | Write-DatedVerbose
} process {
    #region validate input parameters
    if (($VMPath -and ($ExcludeDefaultPaths -or $ExcludeExistingPaths)) `
            -or (-not $VMPath -and ($IncludeDefaultPaths -or $IncludeExistingPaths)) `
            -or ($ExcludeDefaultPaths -and $ExcludeExistingPaths)
    ) {
        throw [ArgumentException]::new('The combination of parameters is not allowed')
    }
    if ($VMPath) {
        [Boolean]$UseDefaultPaths = $IncludeDefaultPaths
        [Boolean]$UseExistingPaths = $IncludeExistingPaths
    } else {
        [Boolean]$UseDefaultPaths = -not $ExcludeDefaultPaths
        [Boolean]$UseExistingPaths = -not $ExcludeExistingPaths
    }
    [String[]]@(
        " - VM host: {$VMHost}",
        " - VM path: {$VMPath}",
        " - include default paths: $UseDefaultPaths",
        " - include existing paths: $UseExistingPaths",
        " - ignore cluster shared volumes: $IgnoreClusterSharedVolumes"
    ) | Write-DatedDebug
    #endregion validate input parameters

    #region main
    [HostInfo[]]$VMHosts = @($VMHost | Test-Host | Initialize-Session)
    try {
        if ($VMHosts | Where-Object -FilterScript { $_.Available -eq [EAvailable]::Yes -and $_.Type.HasFlag([EHostTypes]::VM) }) {
            #region get used directories and files and orphaned files
            [ResultCollections]$ResultCollector = Get-Used | Resolve-SharedUsed | Optimize-Used | Get-Orphaned
            #endregion get used directories and files and orphaned files

            #region correct file output format
            if ($ResultCollector.OrphanedFiles.Count) {
                [HostInfo[]]$OldDirectoryAndFileFormatVMHosts = @($VMHosts |
                        Where-Object -FilterScript { $_.Available -eq [EAvailable]::Yes `
                                -and $_.Type.HasFlag([EHostTypes]::VM) `
                                -and $_.NeedsOldDirectoryAndFileFormat([Version]$PSVersionTable.PSVersion)
                        })
                if ($OldDirectoryAndFileFormatVMHosts.Count) {
                    <#
						To prevent output issues when Windows PowerShell is remotely invoked by PowerShell Core:
						https://github.com/PowerShell/PowerShell/issues/11400 and
						https://github.com/PowerShell/PowerShell/issues/10759
					#>
                    try {
                        Update-FormatData -PrependPath (Join-Path -Path $Env:windir -ChildPath 'System32\WindowsPowerShell\v1.0\FileSystem.format.ps1xml')
                    } catch {
                        Write-DatedWarning -Message ('{0} Error while compensating output incompatibilities between PS versions {{{1}}} running at {{{2}}} and {3} running on this computer' `
                                -f $ScriptLocation, `
                                [String]::Join(', ', ($OldDirectoryAndFileFormatVMHosts | ForEach-Object -Process { $_.PSVersion.ToString() })), `
                                [String]::Join(', ', ($OldDirectoryAndFileFormatVMHosts | ForEach-Object -Process { $_.Name })), `
                                $PSVersionTable.PSVersion)
                    }
                }
            }
            #endregion correct file output format

            #region final output
            Write-Host -Object "`r`n`tOrphaned Hyper-V files:" -ForegroundColor ([ConsoleColor]::DarkCyan)
            if ($ResultCollector.OrphanedFiles.Count) {
                $ResultCollector.OrphanedFiles
                Write-Host -Object "`r`n"
            } else {
                Write-Host -Object "none`r`n"
            }
            $ProblematicPaths.AddRange([PathInfo[]]@((($ResultCollector.RemoteScanDirectories + `
                                $ResultCollector.SharedScanDirectories + `
                                $ResultCollector.SharedMetaFiles + `
                                $ResultCollector.SharedDiskFiles + `
                                $ResultCollector.RemoteMetaFiles + `
                                $ResultCollector.RemoteDiskFiles) |
                            Where-Object -Property 'Available' -EQ -Value ([EAvailable]::No))
                ))
            #endregion final output
        } else {
            Write-DatedWarning -Message "$ScriptLocation Missing any VM host to scan" -ErrorNr -1
        }
        foreach ($ProblematicVMHost in ($VMHosts | Where-Object -Property 'Available' -EQ -Value ([EAvailable]::No))) {
            $ProblematicVMHosts.Add($ProblematicVMHost.Clone())
        }
    } finally {
        foreach ($Vmh in $VMHosts) {
            $Vmh.Dispose()
        }
    }
    #endregion main
} end {
    Write-Host -Object "`tProblematic directories and files:" -ForegroundColor ([ConsoleColor]::DarkCyan)
    if ($ProblematicPaths.Count) {
        $ProblematicPaths | Format-Table -Property HostName, FullName, Problem -AutoSize -Wrap
        Write-Host -Object "`r`n"
    } else {
        Write-Host -Object "none`r`n"
    }
    Write-Host -Object "`tProblematic hosts:" -ForegroundColor ([ConsoleColor]::DarkCyan)
    if ($ProblematicVMHosts.Count) {
        $ProblematicVMHosts | Format-Table -Property QualifiedName, Problem -AutoSize -Wrap
        Write-Host -Object "`r`n"
    } else {
        Write-Host -Object "none`r`n"
    }
    Write-DatedDebug -Message "$ScriptLocation Finished" -PassThru | Write-DatedVerbose
}
