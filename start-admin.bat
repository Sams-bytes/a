@echo off
rem Launch Aegis AS ADMINISTRATOR. This is only needed for the network map's
rem "Deep scan" (operating-system detection needs raw network access = admin).
rem Windows will show one "Do you want to allow this?" (UAC) prompt - click Yes.
powershell -Command "Start-Process -FilePath '%~dp0start.bat' -Verb RunAs"
