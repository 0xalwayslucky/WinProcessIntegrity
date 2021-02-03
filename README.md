# Windows Process Integrity Command Line Tool
- Smol program to determine the mandatory integrity level of a running process from command line.
- (Tested on Windows 10 x64)

## Usage 
`wpi.exe <Process-Id>`

### Notes
In order to be able to display the integrity level of a process, the process accessing this integrity level has to be AT LEAST the same integrity level of the process you want to check.

## Example
- wpi.exe runs with integrity level LOW
- cmd.exe (PID 1337) runs with integrity level MEDIUM

`wpi.exe 1337`
⋅⋅⋅ - fails because it can not access the cmd.exe
