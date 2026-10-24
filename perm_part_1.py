import win32security
import win32process

# GetCurrentProcess() = "me, this running program"
# OpenProcessToken(...) = "open the ID card of that program so I can read it"
# TOKEN_QUERY = "I only want to read it, not change it"
token = win32security.OpenProcessToken(
    win32process.GetCurrentProcess(),
    win32security.TOKEN_QUERY,
)

print("Got the token:", token)
privs = win32security.GetTokenInformation(token, win32security.TokenPrivileges)
print(privs)
for luid, attributes in privs:
    name = win32security.LookupPrivilegeName(None, luid)

    if attributes & win32security.SE_PRIVILEGE_ENABLED:
        state = "Enabled"
    else:
        state = "Disabled"

    print(f"{name:<40}{state}")