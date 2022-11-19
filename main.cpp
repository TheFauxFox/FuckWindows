#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <array>
#include <sstream>

void print(std::string msg, const char end = '\n')
{
    std::cout << msg << end;
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
    if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath)))
    {
        SHELLEXECUTEINFO sei = {sizeof(sei)};
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;
        if (!ShellExecuteEx(&sei))
        {
            print("BBBBBBBBBBBBBBBBB                                        hhhhhhh             ");
            print("B::::::::::::::::B                                       h:::::h             ");
            print("B::::::BBBBBB:::::B                                      h:::::h             ");
            print("BB:::::B     B:::::B                                     h:::::h             ");
            print("  B::::B     B:::::Brrrrr   rrrrrrrrr   uuuuuu    uuuuuu  h::::h hhhhh       ");
            print("  B::::B     B:::::Br::::rrr:::::::::r  u::::u    u::::u  h::::hh:::::hhh    ");
            print("  B::::BBBBBB:::::B r:::::::::::::::::r u::::u    u::::u  h::::::::::::::hh  ");
            print("  B:::::::::::::BB  rr::::::rrrrr::::::ru::::u    u::::u  h:::::::hhh::::::h ");
            print("  B::::BBBBBB:::::B  r:::::r     r:::::ru::::u    u::::u  h::::::h   h::::::h");
            print("  B::::B     B:::::B r:::::r     rrrrrrru::::u    u::::u  h:::::h     h:::::h");
            print("  B::::B     B:::::B r:::::r            u::::u    u::::u  h:::::h     h:::::h");
            print("  B::::B     B:::::B r:::::r            u:::::uuuu:::::u  h:::::h     h:::::h");
            print("BB:::::BBBBBB::::::B r:::::r            u:::::::::::::::uuh:::::h     h:::::h");
            print("B:::::::::::::::::B  r:::::r             u:::::::::::::::uh:::::h     h:::::h");
            print("B::::::::::::::::B   r:::::r              uu::::::::uu:::uh:::::h     h:::::h");
            print("BBBBBBBBBBBBBBBBB    rrrrrrr                uuuuuuuu  uuuuhhhhhhh     hhhhhhh");
            print("\nI needed that to do this shit, why would you say no");
            silent("pause");
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
    print("Wanna " + msg + "? (Default: Yes)");
    print("(y/n) >", *" ");
    std::string resp;
    std::getline(std::cin, resp);
    if (strcasecmp(resp.c_str(), "n") == 0)
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

void DoEverything(bool guide)
{
    if (getGuide("disable diagnostics tracking", guide))
    {
        disableService("DiagTrack");
        disableService("diagnosticshub.standardcollector.service");
    }
    if (getGuide("disable mobile push service", guide))
    {
        disableService("dmwapppushservice");
    }
}

void MainScreen()
{
    print("    ______           __      _       ___           __                  ");
    print("   / ____/_  _______/ /__   | |     / (_)___  ____/ /___ _      _______");
    print("  / /_  / / / / ___/ //_/   | | /| / / / __ \\/ __  / __ \\ | /| / / ___/");
    print(" / __/ / /_/ / /__/ ,<      | |/ |/ / / / / / /_/ / /_/ / |/ |/ (__  ) ");
    print("/_/    \\__,_/\\___/_/|_|     |__/|__/_/_/ /_/\\__,_/\\____/|__/|__/____/");
    print("\n  Made with hatred by Faux\n\n");
    print("------------------------------------------");
    print("    [0] - Exit");
    print("    [1] - Auto-Run");
    print("    [2] - Guided Run");
    print("    [3] - Activate Windows");
    print("\n");
    print(">>", *" ");
    int resp;
    std::cin >> resp;
    switch (resp)
    {
    case 1:
        DoEverything(false);
        break;
    case 2:
        DoEverything(true);
    case 3:
        WinActivate();
        break;
    case 0:
    default:
        break;
    }
    print("\n[Press enter to continue]");
    silent("pause");
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
