# Ghidra_AntiDebugSeeker  

![](pictures/Ghidra_AntiDebugSeeker_icon.png)  

## Introduction

This tool is the Ghidra version of [AntiDebugSeeker](https://github.com/LAC-Japan/IDA_Plugin_AntiDebugSeeker).  
It can be used in two ways: as a Ghidra Script and as a module.  

Through this tool, users can automatically extract potential anti-debugging methods used by malware, making it easier for analysts to take appropriate action.  

The main functionalities of this plugin are as follows:

- Extraction of Windows API that are potentially being used for anti-debugging by the malware  
  (All subsequent API represent the Windows API)  
- In addition to API, extraction of anti-debugging techniques based on key phrases that serve as triggers, as some anti-debugging methods cannot be comprehensively identified by API calls alone.

Additionally, the file that defines the detection rules is designed to easily add keywords you want to detect.  
This allows analysts to easily add new detection rules or make changes.  
  
For packed malware, running this plugin after unpacking and fixing the Import Address Table is more effective.

## Files Required to RUN the Program  

 1. AntiDebugSeeker.java (For Ghidra : Ghidra Script Version)
     Zip Folder containing the compiled files including AntiDebugSeekerPlugin.java (For Ghidra : Ghidra Module Extension)
 2. anti_debug_Ghidra.config (Converted for Ghidra : A file containing rules for detecting anti-debugging techniques)
 3. anti_debug_techniques_descriptions_Ghidra.json (Converted for Ghidra : A file containing descriptions of the detected rules)
