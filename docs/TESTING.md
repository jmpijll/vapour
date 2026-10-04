# Windows nightly testing

Download `Vapour-windows-x64.zip` from the newest **Windows nightly** on the repository's Releases page. Extract the ZIP, then run `Vapour.exe` on Windows x64 with WebView2. Build tools are only needed to build from source. This is an unsigned prerelease; Windows may show a publisher warning.

Start without administrator access. Test opening/hiding the tray window, keyboard navigation, appearance preferences, restart persistence, interface traffic, connection details, copying endpoints and explicit speedtest start/cancel. Speedtests transfer data and the selected server sees your source IP.

Packet capture is disabled pending isolated driver acceptance. Starting the app as administrator does not enable it. DNS interception and the separate privileged helper are not included in this release baseline. Administrator app measurements and manual firewall actions remain experimental; use an isolated Windows VM for those checks. A passing CI run does not prove native measurement accuracy or explain earlier machine shutdowns.

Report bugs through the repository's bug-report issue form. Include the commit from `release.json`, Windows version, steps, expected behaviour and observed behaviour. Redact process paths, addresses, hostnames and private screenshots. Each release contains its matching source, license notices and checksums. Keep the previous working nightly if a new build regresses.
