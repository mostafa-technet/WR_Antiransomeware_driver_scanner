<!---
    name: Scanner File System Minifilter Driver
    platform: WDM
    language: cpp
    category: FileSystem
    description: A file data scanner example. Typically, anti-virus filters are of this type.
    samplefwlink: http://go.microsoft.com/fwlink/p/?LinkId=617655
--->


This driver works to prevent antiransomwares work on Windows OS. It checks signature of applications, if they are unsigned CAN'T modify files based on formats. The user can change the setting, by default they can modify 2 files in their own directory only. No unsigned exe can make a new exe. All exe files can create new files. 

