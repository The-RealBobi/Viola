using CriFsV2Lib;
using CriFsV2Lib.Definitions.Structs;

namespace Viola.Core.Utils.Cpk.Logic;

internal static class CAudioCpkRebuilder
{
    public static void Write(
        string sourceCpkPath,
        string outputPath,
        IReadOnlyDictionary<string, string> replacements,
        string tempRoot)
    {
        var extractRoot = Path.Combine(tempRoot, Path.GetFileNameWithoutExtension(outputPath));
        if (Directory.Exists(extractRoot))
        {
            Directory.Delete(extractRoot, true);
        }

        Directory.CreateDirectory(extractRoot);

        try
        {
            var payloads = new List<CpkFilePayload>();
            using var source = File.OpenRead(sourceCpkPath);
            using var reader = new CriFsLib().CreateCpkReader(source, true);

            foreach (var entry in reader.GetFiles().OrderBy(GetRelativePath, StringComparer.OrdinalIgnoreCase))
            {
                var relativePath = GetRelativePath(entry);
                if (TryGetReplacement(replacements, relativePath, entry.FileName, out var replacementPath))
                {
                    payloads.Add(new CpkFilePayload(relativePath, replacementPath));
                    continue;
                }

                var tempPath = Path.Combine(extractRoot, relativePath.Replace('/', Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(tempPath)!);

                var localEntry = entry;
                using var extracted = reader.ExtractFileNoDecompression(in localEntry, out _);
                using var output = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, 64 * 1024);
                output.Write(extracted.Span);
                payloads.Add(new CpkFilePayload(relativePath, tempPath));
            }

            CCriCpkWriter.Write(outputPath, payloads);
        }
        finally
        {
            if (Directory.Exists(extractRoot))
            {
                Directory.Delete(extractRoot, true);
            }
        }
    }

    private static string GetRelativePath(CpkFile file)
    {
        return string.IsNullOrWhiteSpace(file.Directory)
            ? file.FileName.Replace('\\', '/')
            : $"{file.Directory.Replace('\\', '/')}/{file.FileName.Replace('\\', '/')}";
    }

    private static bool TryGetReplacement(
        IReadOnlyDictionary<string, string> replacements,
        string relativePath,
        string fileName,
        out string replacementPath)
    {
        if (replacements.TryGetValue(relativePath, out replacementPath!))
        {
            return true;
        }

        var matches = replacements
            .Where(item => Path.GetFileName(item.Key).Equals(fileName, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (matches.Count == 1)
        {
            replacementPath = matches[0].Value;
            return true;
        }

        replacementPath = string.Empty;
        return false;
    }
}
