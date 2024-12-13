> Based on https://github.com/commial/experiments/tree/master/windows-defender/VDM

# DefenderInsights
 
Check what's behind the Threatnames that Windows Defender's static detection gives you.
 
## Usage:

Copy over vdm files to ./vdms/
 
You can find them in C:\ProgramData\Microsoft\Windows Defender\Definition Updates\\<GUID\>\
 
Run: **python3 DefenderInsights.py \<ThreatName\>**
 
Example: python3 DefenderInsights.py SuspGolang.AG


### Note:

If this there aren't any extracted strings, but some hex, try to decipher it with tools like cyberchef - from hex

