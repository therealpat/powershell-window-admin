Install-module -name NTFSsecurity
Import-module ntfssecurity
#Need to find a nicer way to do this, set the powershell windows size width to say 900 to ensure that long folder paths/files can be saved without being truncated. If you don't with -autosize option whole column will not be output.
#If dir structure has lots of folders/file to go through it will take a while and use quite a bit of memory.
$target = 'C:\'
$output = 'C:\temp\ntfspermissions.csv'

get-childitem $target -recurse | Get-NTFSAccess | select * | Format-Table -AutoSize | out-file $output -Append