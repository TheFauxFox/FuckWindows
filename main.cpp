#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <array>
#include <string>

void print(std::string msg, char end = '\n')
{
    std::cout << msg << end;
}

std::string input(std::string prompt)
{
    print(prompt, *"");
    std::string resp;
    std::getline(std::cin, resp);
    return resp;
}

bool yn(std::string prompt, bool defaultVal = true)
{
    print(prompt);
    std::string defaultStr = "[(y/n) Default: n]";
    if (defaultVal)
    {
        defaultStr = "[(y/n) Default: y]";
    }
    std::string resp = input(defaultStr + " > ");
    if (resp == "")
    {
        return defaultVal;
    }
    else if (strcasecmp(resp.c_str(), "n") == 0)
    {
        print("Okay fine, skipping it");
        return false;
    }
    else if (strcasecmp(resp.c_str(), "y") == 0)
    {
        return true;
    }
    else
    {
        print("I don't know what the fuck you entered, it wasn't y or n, so I'm calling it an n.");
        return false;
    }
}

void countdown(std::string label, int seconds)
{
    for (int i = 0; i < seconds; i++)
    {
        std::string hasS = "s";
        if (i == seconds - 1)
        {
            hasS = "";
        }
        print(label + std::to_string(seconds - i) + " second" + hasS, '\r');
        Sleep(1000);
    }
}

int run(std::string cmd, bool silent = false)
{
    std::string end = "";
    if (silent)
    {
        end = " >NUL 2>&1";
    }
    return system((cmd + end).c_str());
}

int silent(std::string cmd)
{
    return run(cmd, true);
}

void initReboot()
{
    countdown("Rebooting in: ", 5);
    silent("shutdown /r /t 0");
}

bool GotAdmin()
{
    bool fIsElevated = false;
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation;
    DWORD dwSize;

    try
    {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
        GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize);
        fIsElevated = elevation.TokenIsElevated;
    }
    catch (...)
    {
    }

    if (hToken)
    {
        CloseHandle(hToken);
        hToken = NULL;
    }
    return fIsElevated;
}

void GetAdmin()
{
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, ARRAYSIZE(szPath)))
    {
        SHELLEXECUTEINFOW sei = {sizeof(sei)};
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;
        if (!ShellExecuteExW(&sei))
        {
            print("BBBBBBBBBBBBBBBBB                                           hhhhhhh");
            print("B::::::::::::::::B                                          h:::::h");
            print("B::::::BBBBBB:::::B                                         h:::::h");
            print("BB:::::B     B:::::B                                        h:::::h");
            print("  B::::B     B:::::B rrrrr   rrrrrrrrr    uuuuuu    uuuuuu   h::::h hhhhh");
            print("  B::::B     B:::::B r::::rrr:::::::::r   u::::u    u::::u   h::::hh:::::hhh");
            print("  B::::BBBBBB:::::B  r:::::::::::::::::r  u::::u    u::::u   h::::::::::::::hh");
            print("  B:::::::::::::BB   rr::::::rrrrr::::::r u::::u    u::::u   h:::::::hhh::::::h");
            print("  B::::BBBBBB:::::B   r:::::r     r:::::r u::::u    u::::u   h::::::h   h::::::h");
            print("  B::::B     B:::::B  r:::::r     rrrrrrr u::::u    u::::u   h:::::h     h:::::h");
            print("  B::::B     B:::::B  r:::::r             u::::u    u::::u   h:::::h     h:::::h");
            print("  B::::B     B:::::B  r:::::r             u:::::uuuu:::::u   h:::::h     h:::::h");
            print("BB:::::BBBBBB::::::B  r:::::r             u:::::::::::::::uu h:::::h     h:::::h");
            print("B:::::::::::::::::B   r:::::r              u:::::::::::::::u h:::::h     h:::::h");
            print("B::::::::::::::::B    r:::::r               uu::::::::uu:::u h:::::h     h:::::h");
            print("BBBBBBBBBBBBBBBBB     rrrrrrr                 uuuuuuuu  uuuu hhhhhhh     hhhhhhh");
            if (!yn("Do you want to exit?"))
            {
                if (yn("Do you need to bypass the admin prompt? (AKA: Do you not have permission to run as admin?)"))
                {
                    print("Maybe at some point I'll include a special surprise..");
                }
                else
                {
                    if (yn("Want me to ask for admin again?"))
                    {
                        GetAdmin();
                    }
                    else
                    {
                        print("Christ you're confusing. I'm leaving.");
                    }
                }
            }
        }
    }
}

void WinActivate()
{
    std::array<std::string, 10> keys{
        "TX9XD-98N7V-6WMQ6-BX7FG-H8Q99",
        "3KHY7-WNT83-DGQKR-F7HPR-844BM",
        "7HNRX-D7KGG-3K4RQ-4WPJ4-YTDFH",
        "PVMJN-6DFY6-9CCP6-7BKTT-D3WVR",
        "W269N-WFGWX-YVC9B-4J6C9-T83GX",
        "MH37W-N47XK-V7XM9-C7227-GCQG9",
        "NW6C2-QMPVW-D7KKK-3GKT6-VCFB2",
        "2WH4N-8QGBV-H22JP-CT43Q-MDWWJ",
        "NPPR9-FWDCX-D2C8J-H872K-2YT43",
        "DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4"};
    print("Brute forcing keys..");
    for (std::string key : keys)
    {
        print(key, '\r');
        if (!silent("cscript //nologo C:\\Windows\\System32\\slmgr.vbs /ipk " + key))
        {
            print("");
            break;
        }
    }
    print("Using public KMS server because why not..");
    if (silent("cscript //nologo C:\\Windows\\System32\\slmgr.vbs /skms kms8.msguides.com"))
    {
        print("Did the host go down? We failed to register with kms8.msguides.com.");
        return;
    }
    print("Forcing Windows to activate..");
    if (silent("cscript //nologo C:\\Windows\\System32\\slmgr.vbs /ato"))
    {
        print("Okay, I don't know how that happened. We failed to activate.");
        return;
    }
    print("A'ight, fuck paying for Windows. We got this bag.");
}

bool getGuide(std::string msg, bool show)
{
    if (!show)
    {
        return true;
    }
    return yn("Wanna " + msg + "?");
}

void sp(std::string label, std::string cmd)
{
    print(label);
    silent(cmd);
}

void disableService(std::string name)
{
    sp("[Service] Stopping " + name, "sc stop " + name);
    sp("[Service] Disabling " + name, "sc config " + name + "start= disabled");
}

void setRegKey(std::string key, std::string value, std::string data)
{
    sp("[Registry] Setting " + key + "\\" + value + " to: " + data, "reg add \"" + key + "\" /v \"" + value + "\" /t REG_DWORD /d " + data + "/f");
}

void removePackage(std::string name)
{
    sp("[Bloatware] Removing package " + name, "PowerShell -Command \"Get-AppxPackage *" + name + "* | Remove-AppxPackage\"");
}

void disableTask(std::string name)
{
    sp("[Task] Disabling task " + name, "schtasks /Change /TN \"" + name + "\" /Disable");
}

void disableTelemetry(bool guide)
{
    bool g = guide;
    if (getGuide("disable diagnostics tracking", guide))
    {
        disableService("DiagTrack");
        disableService("diagnosticshub.standardcollector.service");
    }
    if (getGuide("disable mobile push service", guide))
    {
        disableService("dmwapppushservice");
    }
    if (getGuide("disable remote registry edits", guide))
    {
        disableService("RemoteRegistry");
    }
    if (getGuide("disable link tracking service", guide))
    {
        disableService("TrkWks");
    }
    if (getGuide("disable Windows Media Player network tracking", guide))
    {
        disableService("WMPNetworkSvc");
    }
    if (getGuide("disable Windows SuperFetch (background app pre-loading)", guide))
    {
        disableService("SysMain");
    }
    if (getGuide("remove the useless retail demo task", guide))
    {
        sp("[Service] Stopping RetailDemo", "sc stop RetailDemo");
        sp("[Service] Removing RetailDemo", "sc delete RetailDemo");
    }
    if (getGuide("automatically disable all telemetry (data collection) scheduled tasks (saying no will require you step through each one)", guide))
    {
        guide = false;
    }
    if (getGuide("disable smart screen telemetry", guide))
    {
        disableTask("Microsoft\\Windows\\AppID\\SmartScreenSpecific");
    }
    if (getGuide("disable application experience telemetry", guide))
    {
        disableTask("Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser");
        disableTask("Microsoft\\Windows\\Application Experience\\ProgramDataUpdater");
        disableTask("Microsoft\\Windows\\Application Experience\\StartupAppTask");
        disableTask("Microsoft\\Windows\\Application Experience\\AitAgent");
    }
    if (getGuide("disable customer experience improvement telemetry", guide))
    {
        disableTask("Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator");
        disableTask("Microsoft\\Windows\\Customer Experience Improvement Program\\KernelCeipTask");
        disableTask("Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip");
        disableTask("Microsoft\\Windows\\Customer Experience Improvement Program\\Uploader");
        disableTask("Microsoft\\Windows\\PI\\Sqm-Tasks");
    }
    if (getGuide("disable family safety upload (what the fuck)", guide))
    {
        disableTask("Microsoft\\Windows\\Shell\\FamilySafetyUpload");
    }
    if (getGuide("disable Office telemetry", guide))
    {
        disableTask("Microsoft\\Office\\OfficeTelemetryAgentLogOn");
        disableTask("Microsoft\\Office\\OfficeTelemetryAgentFallBack");
        disableTask("Microsoft\\Office\\Office 15 Subscription Heartbeat");
    }
    if (getGuide("disable disc diagnostic data telemetry", guide))
    {
        disableTask("Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector");
    }
    if (getGuide("disable power efficiency telemetry", guide))
    {
        disableTask("Microsoft\\Windows\\Power Efficiency Diagnostics\\AnalyzeSystem");
    }
    if (getGuide("disable Windows error reporting telemetry", guide))
    {
        disableTask("Windows Error Reporting\\QueueReporting");
    }
    if (getGuide("disable Windows application performance telemetry", guide))
    {
        disableTask("Microsoft\\Windows\\maintenance\\winsat");
    }
    if (getGuide("disable Windows Media Player collecting info and not just playing media", guide))
    {
        disableTask("Microsoft\\Windows\\media center\\activateWindowssearch");
        disableTask("Microsoft\\Windows\\media center\\configureinternettimeservice");
        disableTask("Microsoft\\Windows\\media center\\dispatchrecoverytasks");
        disableTask("Microsoft\\Windows\\media center\\ehdrminit");
        disableTask("Microsoft\\Windows\\media center\\installplayready");
        disableTask("Microsoft\\Windows\\media center\\mcupdate");
        disableTask("Microsoft\\Windows\\media center\\mediacenterrecoverytask");
        disableTask("Microsoft\\Windows\\media center\\objectstorerecoverytask");
        disableTask("Microsoft\\Windows\\media center\\ocuractivate");
        disableTask("Microsoft\\Windows\\media center\\ocurdiscovery");
        disableTask("Microsoft\\Windows\\media center\\pbdadiscovery");
        disableTask("Microsoft\\Windows\\media center\\pbdadiscoveryw1");
        disableTask("Microsoft\\Windows\\media center\\pbdadiscoveryw2");
        disableTask("Microsoft\\Windows\\media center\\pvrrecoverytask");
        disableTask("Microsoft\\Windows\\media center\\pvrscheduletask");
        disableTask("Microsoft\\Windows\\media center\\registersearch");
        disableTask("Microsoft\\Windows\\media center\\reindexsearchroot");
        disableTask("Microsoft\\Windows\\media center\\sqlliterecoverytask");
        disableTask("Microsoft\\Windows\\media center\\updaterecordpath");
    }
    guide = g;
    if (getGuide("disable Windows telemetry registry keys", guide))
    {
        setRegKey("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Device Metadata", "PreventDeviceMetadataFromNetwork", "1");
        setRegKey("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection", "AllowTelemetry", "0");
        setRegKey("HKLM\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows\\DataCollection", "AllowTelemetry", "0");
        setRegKey("HKLM\\SOFTWARE\\Policies\\Microsoft\\MRT", "DontOfferThroughWUAU", "1");
        setRegKey("HKLM\\SOFTWARE\\Policies\\Microsoft\\SQMClient\\Windows", "CEIPEnable", "0");
        setRegKey("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat", "AITEnable", "0");
        setRegKey("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat", "DisableUAR", "1");
        setRegKey("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", "AllowTelemetry", "0");
        setRegKey("HKLM\\SYSTEM\\CurrentControlSet\\Control\\WMI\\AutoLogger\\AutoLogger-Diagtrack-Listener", "Start", "0");
        setRegKey("HKLM\\SYSTEM\\CurrentControlSet\\Control\\WMI\\AutoLogger\\SQMLogger", "Start", "0");
    }
    if (getGuide("disable your advertising id", guide))
    {
        setRegKey("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", "Enabled", "0");
    }
    if (getGuide("stop websites from knowing what languages you have installed", guide))
    {
        setRegKey("HKCU\\Control Panel\\International\\User Profile", "HttpAcceptLanguageOptOut", "1");
    }
    if (getGuide("disable Windows hotspot (desktops usually can't use this anyways)", guide))
    {
        setRegKey("HKLM\\Software\\Microsoft\\PolicyManager\\default\\WiFi\\AllowWiFiHotSpotReporting", "value", "0");
        setRegKey("HKLM\\Software\\Microsoft\\PolicyManager\\default\\WiFi\\AllowAutoConnectToWiFiSenseHotspots", "value", "0");
    }
    if (getGuide("disable Windows wifi password sharing (please don't share my wifi creds with Facebook friends..)", guide))
    {
        setRegKey("HKLM\\software\\microsoft\\wcmsvc\\wifinetworkmanager", "wifisensecredshared", "0");
        setRegKey("HKLM\\software\\microsoft\\wcmsvc\\wifinetworkmanager", "wifisenseopen", "0");
    }
    if (getGuide("disable Windows update from downloading from other Windows user (outside your own local network, kinda weird mate)", guide))
    {
        setRegKey("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config", "DoDownloadMode", "0");
    }
    if (getGuide("stop Windows from showing your most recently used apps in the start menu", guide))
    {
        setRegKey("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "Start_TrackDocs", "0");
    }
    if (getGuide("disable Windows Defender (codenamed spynet in the registry..) from sending files to Microsoft", guide))
    {
        setRegKey("HKLM\\software\\microsoft\\windows defender\\spynet", "spynetreporting", "0");
        setRegKey("HKLM\\software\\microsoft\\windows defender\\spynet", "submitsamplesconsent", "0");
    }
    if (getGuide("disable Windows Search (task bar search) from using Cortana and Bing (Also disables Cortana search when Windows is locked)", guide))
    {
        setRegKey("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search", "AllowCortana", "0");
        setRegKey("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search", "AllowCortanaAboveLock", "0");
        setRegKey("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search", "AllowSearchToUseLocation", "0");
        setRegKey("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search", "BingSearchEnabled", "0");
        setRegKey("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search", "BingSearchEnabled", "0");
    }
}

void removeBloat(bool guide)
{
    if (getGuide("remove Windows alarms app", guide))
    {
        removePackage("WindowsAlarms");
    }
    if (getGuide("remove Office Hub app", guide))
    {
        removePackage("MicrosoftOfficeHub");
    }
    if (getGuide("remove OneNote app", guide))
    {
        removePackage("OneNote");
    }
    if (getGuide("remove Windows Phone app", guide))
    {
        removePackage("WindowsPhone");
        removePackage("CommsPhone");
    }
    if (getGuide("remove Skype app (please)", guide))
    {
        removePackage("SkypeApp");
    }
    if (getGuide("remove Windows sound recorder app", guide))
    {
        removePackage("WindowsSoundRecorder");
    }
    if (getGuide("remove Windows Maps app (why would you use maps on a desktop..)", guide))
    {
        removePackage("WindowsMaps");
    }
    if (getGuide("remove OneDrive integration", guide))
    {
        sp("Uninstalling OneDrive", "start /wait \"\" \"%%SYSTEMROOT%%\\SYSWOW64\\ONEDRIVESETUP.EXE\" /UNINSTALL");
        sp("Removing OneDrive temp folder", "rd C:\\OneDriveTemp /Q /S");
        sp("Removing OneDrive system folders", "rd \"%%USERPROFILE%%\\OneDrive\" /Q /S");
        silent("rd \"%%LOCALAPPDATA%%\\Microsoft\\OneDrive\" /Q /S");
        silent("rd \"%%PROGRAMDATA%%\\Microsoft OneDrive\" /Q /S");
        sp("Remove OneDrive context menu items", "reg add \"HKEY_CLASSES_ROOT\\CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\\ShellFolder\" /f /v Attributes /t REG_DWORD /d 0");
        silent("reg add \"HKEY_CLASSES_ROOT\\Wow6432Node\\CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\\ShellFolder\" /f /v Attributes /t REG_DWORD /d 0");
    }
}

void settingsTweak(bool guide)
{
    if (getGuide("disable windows update", guide))
    {
        setRegKey("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", "NoAutoUpdate", "1");
    }
    if (getGuide("hide taskbar search box (You can still search by tapping the Windows key)", guide))
    {
        setRegKey("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search", "SearchboxTaskbarMode", "0");
    }
    if (getGuide("set the file explorer to start in \"This PC\" instead of \"Quick Access\"", guide))
    {
        setRegKey("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "LaunchTo", "1");
    }
    if (getGuide("show hidden files in the file explorer", guide))
    {
        setRegKey("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "Hidden", "1");
    }
    if (getGuide("show hidden system files in the file explorer", guide))
    {
        setRegKey("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "ShowSuperHidden", "1");
    }
    if (getGuide("show file extensions in the file explorer", guide))
    {
        setRegKey("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "HideFileExt", "0");
    }
    if (getGuide("disable SmartScreen for Windows Store apps (doesn't change if you disable SmartScreen entirely)", guide))
    {
        setRegKey("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost", "EnableWebContentEvaluation", "0");
    }
    if (getGuide("add a context menu option to take full ownership of any file or directory (misuse may cause issues)", guide))
    {
        setRegKey("HKCR\\*\\shell\\runas", "@", "Take Ownership");
        setRegKey("HKCR\\*\\shell\\runas", "NoWorkingDirectory", "");
        setRegKey("HKCR\\*\\shell\\runas\\command", "@", "cmd.exe /c takeown /f \\\"%1\\\" && icacls \\\"%1\\\" /grant administrators:F");
        setRegKey("HKCR\\*\\shell\\runas\\command", "IsolatedCommand", "cmd.exe /c takeown /f \\\"%1\\\" && icacls \\\"%1\\\" /grant administrators:F");
        setRegKey("HKCR\\Directory\\shell\\runas", "@", "Take Ownership");
        setRegKey("HKCR\\Directory\\shell\\runas", "NoWorkingDirectory", "");
        setRegKey("HKCR\\Directory\\shell\\runas\\command", "@", "cmd.exe /c takeown /f \\\"%1\\\" /r /d y && icacls \\\"%1\\\" /grant administrators:F /t");
        setRegKey("HKCR\\Directory\\shell\\runas\\command", "IsolatedCommand", "cmd.exe /c takeown /f \\\"%1\\\" /r /d y && icacls \\\"%1\\\" /grant administrators:F /t");
    }
    if (getGuide("set Windows to use the dark theme", guide))
    {
        setRegKey("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", "AppsUseLightTheme", "0");
    }
    if (getGuide("enable Windows \"verbose\" mode (more info on login and shutdown)", guide))
    {
        setRegKey("HKLM\\SOFTWARE\\WOW6432Node\\Microsoft", "VerboseStatus", "32");
    }
    if (getGuide("(theoretically) boost network transfer speeds", guide))
    {
        setRegKey("HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "IRPStackSize", "32");
    }
    if (getGuide("disable the useless function called \"Shake to Minimize\" (Try shaking this window side to side rapidly)", guide))
    {
        setRegKey("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "DisallowShaking", "1");
    }
    if (getGuide("set clicking on an app in the taskbar with multiple windows open to automatically open the last active window", guide))
    {
        setRegKey("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "LastActiveClick", "1");
    }
}

bool disableDefender()
{
    if (yn("Last chance, still want to continue?"))
    {
        setRegKey("HKLM\\Software\\Policies\\Microsoft\\Windows Defender", "DisableAntiSpyware", "1");
        setRegKey("HKLM\\SOFTWARE\\Policies\\Microsoft\\Real-Time Protection", "DisableBehaviorMonitoring", "1");
        setRegKey("HKLM\\SOFTWARE\\Policies\\Microsoft\\Real-Time Protection", "DisableOnAccessProtection", "1");
        setRegKey("HKLM\\SOFTWARE\\Policies\\Microsoft\\Real-Time Protection", "DisableScanOnRealtimeEnable", "1");
        return true;
    }
    return false;
}

bool disableSmartScreen()
{
    if (yn("Last chance, still want to continue?"))
    {
        setRegKey("HKLM\\Software\\Policies\\Microsoft\\Windows\\System", "EnableSmartScreen", "0");
        return true;
    }
    return false;
}

void MainScreen()
{
    print("    ______           __      _       ___           __                  ");
    print("   / ____/_  _______/ /__   | |     / (_)___  ____/ /___ _      _______");
    print("  / /_  / / / / ___/ //_/   | | /| / / / __ \\/ __  / __ \\ | /| / / ___/");
    print(" / __/ / /_/ / /__/ ,<      | |/ |/ / / / / / /_/ / /_/ / |/ |/ (__  ) ");
    print("/_/    \\__,_/\\___/_/|_|     |__/|__/_/_/ /_/\\__,_/\\____/|__/|__/____/");
    print("\n  Made with hatred by Faux");
    print("\n---------------------------------------DISCLAIMER---------------------------------------");
    print("  1) This tool is simply a proof of concept that and for myself to learn C++.");
    print("     I do not condone stealing software, especially from billion-dollar corporations");
    print("     that definitely need your $200. Please throw money at the Windows overlords before");
    print("     using this. (Any language within the software implying otherwise is satire)");
    print("  2) I am also not responsible for any instability or viruses caused by the use of this");
    print("     tool. If you choose to disable Defender/SmartScreen/Windows Updates,");
    print("     you may make your machine vulnerable to a plethora of attack methods if you're");
    print("     dumb enough to trust every \"Free Nature Background\" application in existence.");
    print("  3) If you have any questions, please check out the tutorial video linked here:");
    print("     https://www.youtube.com/watch?v=dQw4w9WgXcQ");
    print("----------------------------------------------------------------------------------------\n");
    print("    [0] - Exit");
    print("    [1] - Activate Windows");
    print("    [2] - Disable Telemetry");
    print("    [3] - Remove Bloatware");
    print("    [4] - Settings Tweaks");
    print("    [5] - Disable Windows Defender");
    print("    [6] - Disable Windows SmartScreen");
    print("    [7] - Fuck Windows");
    int resp = std::stoi(input("\n>> "));
    switch (resp)
    {
    case 1:
        WinActivate();
        if (yn("Windows needs to reboot for the changes to take effect. Reboot now?"))
        {
            initReboot();
        }
        break;
    case 2:
        disableTelemetry(yn("Wanna pick your options?", false));
        if (yn("Windows needs to reboot for the changes to take effect. Reboot now?"))
        {
            initReboot();
        }
        break;
    case 3:
        removeBloat(yn("Wanna pick your options?", false));
        if (yn("Windows needs to reboot for the changes to take effect. Reboot now?"))
        {
            initReboot();
        }
        break;
    case 4:
        settingsTweak(yn("Wanna pick your options?", false));
        if (yn("Windows needs to reboot for the changes to take effect. Reboot now?"))
        {
            initReboot();
        }
        break;
    case 5:
        print("**WARNING**");
        print("This will remove your last resort anti-virus. This is potentially dangerous, if you're tech dumb.");
        if (yn("Still wanna continue?", false))
        {
            if (disableDefender() && yn("Windows needs to reboot for the changes to take effect. Reboot now?"))
            {
                initReboot();
            }
        }
        break;
    case 6:
        print("**WARNING**");
        print("This will remove the annoying popup for executables that Windows doesn't trust. This could lead to dumb mistakes if you're tech dumb.");
        if (yn("Still wanna continue?", false))
        {
            if (disableSmartScreen() && yn("Windows needs to reboot for the changes to take effect. Reboot now?"))
            {
                initReboot();
            }
        }
        break;
    case 7:
        WinActivate();
        disableTelemetry(false);
        removeBloat(false);
        settingsTweak(false);
        disableDefender();
        disableSmartScreen();
        print("Windows has successfully been fucked.");
        initReboot();
        break;
    case 0:
    default:
        print("Exiting");
        Sleep(1500);
    }
}

int main()
{
    if (!GotAdmin())
    {
        GetAdmin();
    }
    else
    {
        MainScreen();
    }
}
