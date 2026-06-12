using System.Security.Cryptography;
using System.Text;
using Tinifan.Level5.Binary;
using Viola.Core.EncryptDecrypt.Logic.Utils;

namespace Viola.Core.Utils.CpkList.Logic;

public sealed class CpkListEntry
{
    public string FullPath { get; init; } = string.Empty;
    public string CpkPath { get; init; } = string.Empty;
    public int Size { get; init; }
}

public static class CCpkListUtils
{
    private const uint LegacyKey = 0x1717E18E;
    private const uint ModernKeyScrambleKey = 0x8A90ABA9;
    private const uint ModernIvScrambleKey = 0x4C801618;
    private const uint T2bFooterMagic = 0x62327401;

    private static readonly byte[] ModernEncryptedKey =
    [
        0x21, 0xCB, 0xC9, 0x72, 0xF9, 0xF2, 0x8B, 0x17,
        0x9D, 0xE2, 0x50, 0x64, 0xD1, 0x8C, 0xA9, 0x4D,
        0x53, 0x8D, 0x90, 0x1E, 0x96, 0xF6, 0x0D, 0x75,
        0x7A, 0xA8, 0xD9, 0x43, 0x42, 0xE2, 0x4F, 0x58
    ];

    private static readonly byte[] ModernEncryptedIv =
    [
        0x6D, 0x4B, 0x8E, 0x3F, 0x2F, 0x49, 0xC9, 0xF0,
        0x9D, 0xE6, 0x44, 0x38, 0xE3, 0x1E, 0xCB, 0xB0
    ];

    public static IEnumerable<byte[]> GetReadableCandidates(byte[] bytes)
    {
        if (TryDecryptModern(bytes, out var modernBytes))
        {
            yield return modernBytes;
        }

        yield return bytes;

        var legacyBytes = (byte[])bytes.Clone();
        CCriwareCrypt.DecryptBlock(legacyBytes, 0, LegacyKey);
        yield return legacyBytes;
    }

    public static bool TryReadEntries(byte[] bytes, out List<CpkListEntry> entries)
    {
        entries = new List<CpkListEntry>();
        foreach (var candidate in GetReadableCandidates(bytes))
        {
            if (TryReadT2bEntries(candidate, out entries) || TryReadCfgBinEntries(candidate, out entries))
            {
                return true;
            }
        }

        return false;
    }

    public static bool TryGetCfgBinPayload(byte[] bytes, out byte[] payload, out bool wasLegacyEncrypted)
    {
        wasLegacyEncrypted = false;

        foreach (var candidate in GetReadableCandidates(bytes))
        {
            if (TryOpenCfgBin(candidate))
            {
                payload = candidate;
                wasLegacyEncrypted = !ReferenceEquals(candidate, bytes);
                return true;
            }
        }

        payload = Array.Empty<byte>();
        return false;
    }

    public static bool IsModernCpkList(byte[] bytes)
    {
        return TryDecryptModern(bytes, out var decrypted) && IsT2b(decrypted);
    }

    private static bool TryDecryptModern(byte[] bytes, out byte[] decrypted)
    {
        decrypted = Array.Empty<byte>();
        if (bytes.Length == 0 || bytes.Length % 16 != 0)
        {
            return false;
        }

        try
        {
            var key = (byte[])ModernEncryptedKey.Clone();
            var iv = (byte[])ModernEncryptedIv.Clone();
            CCriwareCrypt.DecryptBlock(key, 0, ModernKeyScrambleKey);
            CCriwareCrypt.DecryptBlock(iv, 0, ModernIvScrambleKey);

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var decryptor = aes.CreateDecryptor();
            decrypted = decryptor.TransformFinalBlock(bytes, 0, bytes.Length);
            return decrypted.Length > 0;
        }
        catch (CryptographicException)
        {
            decrypted = Array.Empty<byte>();
            return false;
        }
    }

    private static bool TryReadCfgBinEntries(byte[] bytes, out List<CpkListEntry> entries)
    {
        entries = new List<CpkListEntry>();

        try
        {
            CfgBin cpkList = new CfgBin();
            cpkList.Open(bytes);
            if (cpkList.Entries.Count == 0 || cpkList.Entries[0].Children == null)
            {
                return false;
            }

            foreach (var item in cpkList.Entries[0].Children)
            {
                string dir = Convert.ToString(item.Variables[0].Value) ?? string.Empty;
                string name = Convert.ToString(item.Variables[1].Value) ?? string.Empty;
                string cpkDir = Convert.ToString(item.Variables[2].Value) ?? string.Empty;
                string cpkName = Convert.ToString(item.Variables[3].Value) ?? string.Empty;
                int size = Convert.ToInt32(item.Variables[4].Value);

                entries.Add(new CpkListEntry
                {
                    FullPath = dir + name,
                    CpkPath = BuildCpkPath(cpkDir, cpkName),
                    Size = size
                });
            }

            return entries.Count > 0;
        }
        catch
        {
            entries.Clear();
            return false;
        }
    }

    private static bool TryOpenCfgBin(byte[] bytes)
    {
        try
        {
            CfgBin cpkList = new CfgBin();
            cpkList.Open(bytes);
            return cpkList.Entries.Count > 0;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryReadT2bEntries(byte[] bytes, out List<CpkListEntry> entries)
    {
        entries = new List<CpkListEntry>();
        if (!IsT2b(bytes))
        {
            return false;
        }

        try
        {
            using var stream = new MemoryStream(bytes, writable: false);
            using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);

            uint entryCount = reader.ReadUInt32();
            uint stringOffset = reader.ReadUInt32();
            uint stringSize = reader.ReadUInt32();
            reader.ReadUInt32();

            if (stringOffset > bytes.Length || stringSize > bytes.Length - stringOffset)
            {
                return false;
            }

            var stringData = bytes[(int)stringOffset..(int)(stringOffset + stringSize)];
            for (uint index = 0; index < entryCount && stream.Position < stringOffset; index++)
            {
                reader.ReadUInt32();
                int valueCount = reader.ReadByte();
                var types = ReadT2bTypes(reader, valueCount);
                var values = new int[valueCount];
                for (int i = 0; i < values.Length; i++)
                {
                    values[i] = reader.ReadInt32();
                }

                if (valueCount < 5 || types[0] != 0 || types[1] != 0 || types[2] != 0 || types[3] != 0 || types[4] != 1)
                {
                    continue;
                }

                string dir = ReadT2bString(stringData, values[0]);
                string name = ReadT2bString(stringData, values[1]);
                string cpkDir = ReadT2bString(stringData, values[2]);
                string cpkName = ReadT2bString(stringData, values[3]);
                if (string.IsNullOrEmpty(dir) || string.IsNullOrEmpty(name))
                {
                    continue;
                }

                entries.Add(new CpkListEntry
                {
                    FullPath = dir + name,
                    CpkPath = BuildCpkPath(cpkDir, cpkName),
                    Size = values[4]
                });
            }

            return entries.Count > 0;
        }
        catch
        {
            entries.Clear();
            return false;
        }
    }

    private static bool IsT2b(byte[] bytes)
    {
        return bytes.Length >= 0x10 && BitConverter.ToUInt32(bytes, bytes.Length - 0x10) == T2bFooterMagic;
    }

    private static byte[] ReadT2bTypes(BinaryReader reader, int count)
    {
        var types = new byte[count];
        for (int index = 0; index < count; index += 4)
        {
            byte chunk = reader.ReadByte();
            for (int nibble = 0; nibble < 4 && index + nibble < count; nibble++)
            {
                types[index + nibble] = (byte)((chunk >> (nibble * 2)) & 0x3);
            }
        }

        Align(reader.BaseStream, 4);
        return types;
    }

    private static string ReadT2bString(byte[] stringData, int offset)
    {
        if (offset < 0 || offset >= stringData.Length)
        {
            return string.Empty;
        }

        int endOffset = offset;
        while (endOffset < stringData.Length && stringData[endOffset] != 0)
        {
            endOffset++;
        }

        return Encoding.UTF8.GetString(stringData[offset..endOffset]);
    }

    private static void Align(Stream stream, int alignment)
    {
        stream.Position = (stream.Position + alignment - 1) & ~(alignment - 1);
    }

    private static string BuildCpkPath(string cpkDir, string cpkName)
    {
        if (string.IsNullOrEmpty(cpkName))
        {
            return string.Empty;
        }

        string cpkPath = Path.Combine(cpkDir, cpkName).Replace("\\", "/");
        return cpkPath.StartsWith("/") ? cpkPath[1..] : cpkPath;
    }
}
