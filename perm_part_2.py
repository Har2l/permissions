import sys
import win32security
import win32process
import win32api
import win32con

def print_privileges(token):
    privs = win32security.GetTokenInformation(token, win32security.TokenPrivileges)
    for luid, attributes in privs:
        name = win32security.LookupPrivilegeName(None, luid)
        if attributes & win32security.SE_PRIVILEGE_ENABLED:
            state = "Enabled"
        else:
            state = "Disabled"
        print(f"{name:<40}{state}")

pid = int(sys.argv[1])

try:
    process = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
    token = win32security.OpenProcessToken(process, win32security.TOKEN_QUERY|win32security.TOKEN_ADJUST_PRIVILEGES)
    print_privileges(token)
except win32api.error as e:
    print(f"Couldn't open PID {pid}: {e.strerror} — try running as administrator.")
    