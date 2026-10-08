using System;
using System.IO;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class PCIntegrityCatalogRead
{
    [DllImport("wintrust.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
    static extern bool CryptCATAdminAcquireContext2(out IntPtr context, IntPtr subsystem, string algorithm, IntPtr policy, uint flags);
    [DllImport("wintrust.dll", ExactSpelling=true, SetLastError=true)]
    static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr context, IntPtr file, ref uint size, byte[] hash, uint flags);
    [DllImport("wintrust.dll", ExactSpelling=true)]
    static extern bool CryptCATAdminReleaseContext(IntPtr context, uint flags);
    [DllImport("wintrust.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
    static extern IntPtr CryptCATOpen(string path, uint flags, IntPtr provider, uint version, uint encoding);
    [DllImport("wintrust.dll", ExactSpelling=true)]
    static extern IntPtr CryptCATEnumerateMember(IntPtr catalog, IntPtr previous);
    [DllImport("wintrust.dll", ExactSpelling=true)]
    static extern bool CryptCATClose(IntPtr catalog);
    [StructLayout(LayoutKind.Sequential)]
    struct MemberHead { public uint Size; public IntPtr ReferenceTag; public IntPtr FileName; }

    public static string Hash(string path)
    {
        IntPtr context;
        if (!CryptCATAdminAcquireContext2(out context, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) {
                uint size = 0;
                CryptCATAdminCalcHashFromFileHandle2(context, stream.SafeFileHandle.DangerousGetHandle(), ref size, null, 0);
                if (size == 0 || size > 128) throw new InvalidOperationException("Invalid catalog hash size");
                byte[] hash = new byte[size];
                stream.Position = 0;
                if (!CryptCATAdminCalcHashFromFileHandle2(context, stream.SafeFileHandle.DangerousGetHandle(), ref size, hash, 0))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return BitConverter.ToString(hash).Replace("-", "");
            }
        } finally { CryptCATAdminReleaseContext(context, 0); }
    }

    public static string[] Matches(string path, string[] hashes)
    {
        HashSet<string> wanted = new HashSet<string>(hashes, StringComparer.OrdinalIgnoreCase);
        List<string> found = new List<string>();
        IntPtr catalog = CryptCATOpen(path, 0, IntPtr.Zero, 0x200, 0);
        if (catalog == new IntPtr(-1) || catalog == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            IntPtr member = IntPtr.Zero;
            while ((member = CryptCATEnumerateMember(catalog, member)) != IntPtr.Zero) {
                MemberHead head = (MemberHead)Marshal.PtrToStructure(member, typeof(MemberHead));
                string tag = Marshal.PtrToStringUni(head.ReferenceTag);
                if (tag != null && wanted.Contains(tag)) found.Add(tag);
            }
        } finally { CryptCATClose(catalog); }
        return found.ToArray();
    }
}
