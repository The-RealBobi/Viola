using System.Buffers.Binary;
using System.Text;

namespace Viola.Core.Utils.Cpk.Logic;

internal sealed record CpkFilePayload(string RelativePath, string SourcePath);

internal static class CSimpleCpkWriter
{
    private const int Alignment = 0x800;
    private const ulong NoOffset = 0xFFFFFFFFFFFFFFFF;

    public static void Write(string outputPath, IReadOnlyList<CpkFilePayload> files)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);

        var orderedFiles = files
            .OrderBy(file => file.RelativePath, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var tocPacketSize = EstimateTocPacketSize(orderedFiles);
        var tocOffset = (long)Alignment;
        var contentOffset = Align(tocOffset + tocPacketSize, Alignment);
        var offsets = new List<long>(orderedFiles.Count);
        var cursor = contentOffset;

        foreach (var file in orderedFiles)
        {
            cursor = Align(cursor, Alignment);
            offsets.Add(cursor);
            cursor += new FileInfo(file.SourcePath).Length;
        }

        var cpkTable = UtfTable.Create("CpkHeader")
            .AddPerRow("UpdateDateTime", UtfType.UInt64)
            .AddPerRow("FileSize", UtfType.UInt64)
            .AddPerRow("ContentOffset", UtfType.UInt64)
            .AddPerRow("TocOffset", UtfType.UInt64)
            .AddPerRow("EtocOffset", UtfType.UInt64)
            .AddPerRow("ItocOffset", UtfType.UInt64)
            .AddPerRow("GtocOffset", UtfType.UInt64)
            .AddPerRow("Files", UtfType.UInt32)
            .AddPerRow("Groups", UtfType.UInt32)
            .AddPerRow("Attrs", UtfType.UInt32)
            .AddPerRow("TotalFiles", UtfType.UInt32)
            .AddPerRow("Directories", UtfType.UInt32)
            .AddPerRow("Updates", UtfType.UInt32)
            .AddPerRow("Version", UtfType.UInt32)
            .AddPerRow("Revision", UtfType.UInt32)
            .AddPerRow("Align", UtfType.UInt16)
            .AddPerRow("Sorted", UtfType.UInt16)
            .AddPerRow("EID", UtfType.UInt16)
            .AddPerRow("CpkMode", UtfType.UInt16)
            .AddPerRow("Tvers", UtfType.String);

        cpkTable.AddRow(
            0UL,
            (ulong)cursor,
            (ulong)contentOffset,
            (ulong)tocOffset,
            NoOffset,
            NoOffset,
            NoOffset,
            (uint)orderedFiles.Count,
            0U,
            0U,
            (uint)orderedFiles.Count,
            (uint)orderedFiles.Select(file => Path.GetDirectoryName(file.RelativePath)?.Replace("\\", "/") ?? string.Empty).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            0U,
            7U,
            0U,
            (ushort)Alignment,
            (ushort)1,
            (ushort)0,
            (ushort)0,
            "Viola");

        var tocTable = UtfTable.Create("CpkTocInfo")
            .AddPerRow("DirName", UtfType.String)
            .AddPerRow("FileName", UtfType.String)
            .AddPerRow("FileSize", UtfType.UInt64)
            .AddPerRow("ExtractSize", UtfType.UInt64)
            .AddPerRow("FileOffset", UtfType.UInt64)
            .AddPerRow("ID", UtfType.UInt32)
            .AddPerRow("UserString", UtfType.String);

        for (var i = 0; i < orderedFiles.Count; i++)
        {
            var file = orderedFiles[i];
            var relative = file.RelativePath.Replace("\\", "/");
            var dirName = Path.GetDirectoryName(relative)?.Replace("\\", "/") ?? string.Empty;
            var fileName = Path.GetFileName(relative);
            var size = (ulong)new FileInfo(file.SourcePath).Length;

            tocTable.AddRow(dirName, fileName, size, size, (ulong)(offsets[i] - tocOffset), (uint)i, string.Empty);
        }

        var cpkPacket = WritePacket("CPK ", cpkTable.Build());
        var tocPacket = WritePacket("TOC ", tocTable.Build());

        using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None);
        output.Write(cpkPacket);
        PadTo(output, Alignment);
        output.Position = tocOffset;
        output.Write(tocPacket);
        PadTo(output, Alignment);
        output.Position = contentOffset;

        for (var i = 0; i < orderedFiles.Count; i++)
        {
            output.Position = offsets[i];
            using var input = File.OpenRead(orderedFiles[i].SourcePath);
            input.CopyTo(output);
        }
    }

    private static int EstimateTocPacketSize(IReadOnlyList<CpkFilePayload> files)
    {
        var strings = files.Sum(file => file.RelativePath.Length + 2);
        return Align(0x100 + files.Count * 0x40 + strings, 0x10) + 0x10;
    }

    private static byte[] WritePacket(string magic, byte[] utf)
    {
        var packet = new byte[0x10 + utf.Length];
        Encoding.ASCII.GetBytes(magic, packet);
        BinaryPrimitives.WriteUInt64LittleEndian(packet.AsSpan(8), (ulong)utf.Length);
        utf.CopyTo(packet.AsSpan(0x10));
        return packet;
    }

    private static long Align(long value, int alignment)
    {
        return (value + alignment - 1) / alignment * alignment;
    }

    private static int Align(int value, int alignment)
    {
        return (value + alignment - 1) / alignment * alignment;
    }

    private static void PadTo(Stream stream, int alignment)
    {
        var aligned = Align(stream.Position, alignment);
        while (stream.Position < aligned)
        {
            stream.WriteByte(0);
        }
    }

    private enum UtfStorage : byte
    {
        Const = 0x30,
        PerRow = 0x50
    }

    private enum UtfType : byte
    {
        UInt16 = 0x03,
        UInt32 = 0x05,
        UInt64 = 0x07,
        String = 0x0A
    }

    private sealed class UtfColumn
    {
        public string Name { get; init; } = string.Empty;
        public UtfStorage Storage { get; init; }
        public UtfType Type { get; init; }
        public object? ConstValue { get; init; }
    }

    private sealed class UtfTable
    {
        private readonly string _name;
        private readonly List<UtfColumn> _columns = new();
        private readonly List<object?[]> _rows = new();

        private UtfTable(string name)
        {
            _name = name;
        }

        public static UtfTable Create(string name) => new(name);

        public UtfTable AddConst(string name, UtfType type, object value)
        {
            _columns.Add(new UtfColumn { Name = name, Type = type, Storage = UtfStorage.Const, ConstValue = value });
            return this;
        }

        public UtfTable AddPerRow(string name, UtfType type)
        {
            _columns.Add(new UtfColumn { Name = name, Type = type, Storage = UtfStorage.PerRow });
            return this;
        }

        public void AddRow(params object?[] values)
        {
            _rows.Add(values);
        }

        public byte[] Build()
        {
            var rowLength = _columns.Where(column => column.Storage == UtfStorage.PerRow).Sum(column => TypeSize(column.Type));
            var columnBytes = new MemoryStream();
            var rowBytes = new MemoryStream();
            var strings = new StringTable();
            strings.Add(_name);

            foreach (var column in _columns)
            {
                columnBytes.WriteByte((byte)((byte)column.Storage | (byte)column.Type));
                WriteUInt32(columnBytes, strings.Add(column.Name));
                if (column.Storage == UtfStorage.Const)
                {
                    WriteValue(columnBytes, column.Type, column.ConstValue, strings);
                }
            }

            foreach (var row in _rows.DefaultIfEmpty(Array.Empty<object?>()))
            {
                var rowIndex = 0;
                foreach (var column in _columns)
                {
                    if (column.Storage != UtfStorage.PerRow)
                    {
                        continue;
                    }

                    WriteValue(rowBytes, column.Type, row[rowIndex++], strings);
                }
            }

            var rowsOffset = 0x20 + columnBytes.Length;
            var stringsOffset = rowsOffset + rowBytes.Length;
            var stringBytes = strings.Build();
            var tableSize = stringsOffset + stringBytes.Length - 8;
            var output = new MemoryStream();

            output.Write(Encoding.ASCII.GetBytes("@UTF"));
            WriteUInt32(output, (uint)tableSize);
            WriteUInt32(output, (uint)(rowsOffset - 8));
            WriteUInt32(output, (uint)(stringsOffset - 8));
            WriteUInt32(output, (uint)(stringsOffset + stringBytes.Length - 8));
            WriteUInt32(output, strings.OffsetOf(_name));
            WriteUInt16(output, (ushort)_columns.Count);
            WriteUInt16(output, (ushort)rowLength);
            WriteUInt32(output, (uint)Math.Max(1, _rows.Count));
            columnBytes.WriteTo(output);
            rowBytes.WriteTo(output);
            output.Write(stringBytes);

            return output.ToArray();
        }

        private static int TypeSize(UtfType type)
        {
            return type switch
            {
                UtfType.UInt16 => 2,
                UtfType.UInt32 => 4,
                UtfType.UInt64 => 8,
                UtfType.String => 4,
                _ => throw new NotSupportedException($"Unsupported UTF type {type}")
            };
        }

        private static void WriteValue(Stream stream, UtfType type, object? value, StringTable strings)
        {
            switch (type)
            {
                case UtfType.UInt16:
                    WriteUInt16(stream, Convert.ToUInt16(value));
                    break;
                case UtfType.UInt32:
                    WriteUInt32(stream, Convert.ToUInt32(value));
                    break;
                case UtfType.UInt64:
                    WriteUInt64(stream, Convert.ToUInt64(value));
                    break;
                case UtfType.String:
                    WriteUInt32(stream, strings.Add(Convert.ToString(value) ?? string.Empty));
                    break;
                default:
                    throw new NotSupportedException($"Unsupported UTF type {type}");
            }
        }

        private static void WriteUInt16(Stream stream, ushort value)
        {
            Span<byte> buffer = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(buffer, value);
            stream.Write(buffer);
        }

        private static void WriteUInt32(Stream stream, uint value)
        {
            Span<byte> buffer = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
            stream.Write(buffer);
        }

        private static void WriteUInt64(Stream stream, ulong value)
        {
            Span<byte> buffer = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(buffer, value);
            stream.Write(buffer);
        }
    }

    private sealed class StringTable
    {
        private readonly MemoryStream _stream = new();
        private readonly Dictionary<string, uint> _offsets = new(StringComparer.Ordinal);

        public uint Add(string value)
        {
            if (_offsets.TryGetValue(value, out var offset))
            {
                return offset;
            }

            offset = (uint)_stream.Length;
            var bytes = Encoding.UTF8.GetBytes(value);
            _stream.Write(bytes);
            _stream.WriteByte(0);
            _offsets.Add(value, offset);
            return offset;
        }

        public uint OffsetOf(string value) => _offsets[value];

        public byte[] Build() => _stream.ToArray();
    }
}
