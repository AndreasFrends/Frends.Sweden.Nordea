using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

#pragma warning disable 1591

namespace Frends.Sweden.Nordea
{
    public static class GenerateNordeaHmacFile
    {
        // Nordea 7-bit Swedish table (HMAC spec section 4): char -> byte written to the output file.
        private static readonly Dictionary<char, byte> CharMap = new()
        {
            [' '] = 0x20,
            ['!'] = 0x21,
            ['"'] = 0x22,
            ['#'] = 0x23,
            ['$'] = 0x24,
            ['%'] = 0x25,
            ['&'] = 0x26,
            ['\''] = 0x27,
            ['('] = 0x28,
            [')'] = 0x29,
            ['*'] = 0x2A,
            ['+'] = 0x2B,
            [','] = 0x2C,
            ['-'] = 0x2D,
            ['.'] = 0x2E,
            ['/'] = 0x2F,
            ['0'] = 0x30,
            ['1'] = 0x31,
            ['2'] = 0x32,
            ['3'] = 0x33,
            ['4'] = 0x34,
            ['5'] = 0x35,
            ['6'] = 0x36,
            ['7'] = 0x37,
            ['8'] = 0x38,
            ['9'] = 0x39,
            [':'] = 0x3A,
            [';'] = 0x3B,
            ['<'] = 0x3C,
            ['='] = 0x3D,
            ['>'] = 0x3E,
            ['?'] = 0x3F,
            ['@'] = 0x40,
            ['É'] = 0x40,
            ['A'] = 0x41,
            ['B'] = 0x42,
            ['C'] = 0x43,
            ['D'] = 0x44,
            ['E'] = 0x45,
            ['F'] = 0x46,
            ['G'] = 0x47,
            ['H'] = 0x48,
            ['I'] = 0x49,
            ['J'] = 0x4A,
            ['K'] = 0x4B,
            ['L'] = 0x4C,
            ['M'] = 0x4D,
            ['N'] = 0x4E,
            ['O'] = 0x4F,
            ['P'] = 0x50,
            ['Q'] = 0x51,
            ['R'] = 0x52,
            ['S'] = 0x53,
            ['T'] = 0x54,
            ['U'] = 0x55,
            ['V'] = 0x56,
            ['W'] = 0x57,
            ['X'] = 0x58,
            ['Y'] = 0x59,
            ['Z'] = 0x5A,
            ['['] = 0x5B,
            ['Ä'] = 0x5B,
            ['\\'] = 0x5C,
            ['Ö'] = 0x5C,
            [']'] = 0x5D,
            ['Å'] = 0x5D,
            ['^'] = 0x5E,
            ['Ü'] = 0x5E,
            ['_'] = 0x5F,
            ['`'] = 0x60,
            ['é'] = 0x60,
            ['a'] = 0x61,
            ['b'] = 0x62,
            ['c'] = 0x63,
            ['d'] = 0x64,
            ['e'] = 0x65,
            ['f'] = 0x66,
            ['g'] = 0x67,
            ['h'] = 0x68,
            ['i'] = 0x69,
            ['j'] = 0x6A,
            ['k'] = 0x6B,
            ['l'] = 0x6C,
            ['m'] = 0x6D,
            ['n'] = 0x6E,
            ['o'] = 0x6F,
            ['p'] = 0x70,
            ['q'] = 0x71,
            ['r'] = 0x72,
            ['s'] = 0x73,
            ['t'] = 0x74,
            ['u'] = 0x75,
            ['v'] = 0x76,
            ['w'] = 0x77,
            ['x'] = 0x78,
            ['y'] = 0x79,
            ['z'] = 0x7A,
            ['{'] = 0x7B,
            ['ä'] = 0x7B,
            ['|'] = 0x7C,
            ['ö'] = 0x7C,
            ['}'] = 0x7D,
            ['å'] = 0x7D,
            ['~'] = 0x7E,
            ['ü'] = 0x7E
        };

        // Strict ASCII for the %-records: throws on a non-ASCII character instead of silently writing '?'.
        private static readonly Encoding StrictAscii =
            Encoding.GetEncoding("us-ascii", EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);

        static GenerateNordeaHmacFile()
        {
            // Windows-1252 is not built in on .NET Core / .NET 8 until this provider is registered.
            // Safe to call repeatedly, so it does not matter whether the Agent has already done it.
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        }

        /// <summary>
        /// Signs a bank file according to Nordea's HMAC-SHA256-128 specification. The source file is decoded once
        /// (encoding detected: strict UTF-8 first, strict Windows-1252 if that fails) and converted to Nordea's 7-bit Swedish table, so the output
        /// file is pure 7-bit ASCII. The HMAC is computed over exactly the bytes written to the output file, after
        /// the spec's normalisation (CR/LF ignored, bytes outside 0x20-0x7E replaced by 0xC3).
        /// A new file is generated with transmission header %001, file header %020, the converted content,
        /// file trailer %022 (KVV and HMAC) and transmission trailer %002.
        /// Characters with no mapping in the Nordea table are written as '?' and counted in ReplacedCharacterCount.
        /// See Nordea specification https://www.nordea.se/Images/39-16211/technical-specification-HMAC.pdf for more info.
        /// </summary>
        /// <returns>{Object}</returns>
        public static object FileProtectionHmac(
            [PropertyTab] NordeaHmacInputGeneral General,
            [PropertyTab] NordeaHmacInputTransmissionHeader TransmissionHeader,
            [PropertyTab] NordeaHmacInputFileHeader FileHeader,
            [PropertyTab] NordeaHmacInputFileTrailer FileTrailer,
            CancellationToken cancellationToken)
        {
            if (File.Exists(General.TargetFilePath))
                throw new Exception($"Target file {General.TargetFilePath} already exists!");

            byte[] key = Convert.FromHexString(General.SecretKey);
            string kvvHmac = GetSealMac(key, StrictAscii.GetBytes("00000000"));

            // Decode once, convert once. These bytes are what gets written AND what gets hashed.
            byte[] content = ConvertToNordeaBytes(General.SourceFilePath, out int replacedCount, out string detectedEncoding);

            cancellationToken.ThrowIfCancellationRequested();
            string fileContentHmac = GetSealMac(key, NormalizeForMac(content));

            var transmissionHeader = CreateTransmissionHeader(TransmissionHeader);
            var fileHeader = CreateFileHeader(FileHeader);
            var fileTrailer = CreateFileTrailer(FileTrailer, kvvHmac, fileContentHmac);
            var transmissionTrailer = CreateTransmissionTrailer();

            var diagnostics = WriteOutFile(
                General.TargetFilePath,
                content,
                transmissionHeader.TransmissionHeaderLine,
                fileHeader.FileHeaderLine,
                fileTrailer.FileTrailerLine,
                transmissionTrailer.TransmissionTrailerLine);

            return new Result
            {
                SourceFilePath = General.SourceFilePath,
                TargetFilePath = General.TargetFilePath,
                ReplacedCharacterCount = replacedCount,
                DetectedSourceEncoding = detectedEncoding,

                OutputEncoding = diagnostics.OutputEncoding,
                ContainsUtf8Bom = diagnostics.ContainsUtf8Bom,
                ContainsNonAsciiBytes = diagnostics.ContainsNonAsciiBytes,
                OutputByteCount = diagnostics.OutputByteCount,

                TransmissionHeader = transmissionHeader,
                FileHeader = fileHeader,
                FileTrailer = fileTrailer,
            };
        }

        /// <summary>
        /// The source encoding is unknown, so it is detected: strict UTF-8 first (a BOM is skipped), then strict
        /// Windows-1252. Text with å/ä/ö that is not valid UTF-8 is, for practical purposes, never misread this way,
        /// and a file with no bytes above 0x7F is the same in both. Neither fits: throws with a clear message.
        /// </summary>
        private static string DecodeSource(string sourceFilePath, out string detectedEncoding)
        {
            byte[] raw = File.ReadAllBytes(sourceFilePath);

            if (Array.TrueForAll(raw, b => b < 0x80))
            {
                detectedEncoding = "ASCII";
                return Encoding.ASCII.GetString(raw);
            }

            try
            {
                int offset = raw.Length >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF ? 3 : 0;
                string text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(raw, offset, raw.Length - offset);
                detectedEncoding = "UTF-8";
                return text;
            }
            catch (DecoderFallbackException)
            {
                // Not valid UTF-8, fall through to Windows-1252.
            }

            try
            {
                string text = Encoding.GetEncoding(1252, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback).GetString(raw);
                detectedEncoding = "Windows-1252";
                return text;
            }
            catch (DecoderFallbackException ex)
            {
                throw new Exception($"Source file {sourceFilePath} is neither valid UTF-8 nor valid Windows-1252: {ex.Message}");
            }
        }

        /// <summary>
        /// Decodes the source file strictly, then maps every character through the Nordea table.
        /// CR/LF are kept as-is (they are ignored by the MAC). Unmapped characters become '?'.
        /// Trailing line breaks are trimmed so exactly one line break precedes the %022 record.
        /// </summary>
        private static byte[] ConvertToNordeaBytes(string sourceFilePath, out int replacedCount, out string detectedEncoding)
        {
            // DecodeSource skips a UTF-8 BOM, so U+FEFF never reaches the char map.
            string text = DecodeSource(sourceFilePath, out detectedEncoding).TrimEnd('\r', '\n');

            var bytes = new List<byte>(text.Length);
            replacedCount = 0;

            foreach (char c in text)
            {
                if (c == '\r' || c == '\n')
                    bytes.Add((byte)c);
                else if (CharMap.TryGetValue(c, out byte mapped))
                    bytes.Add(mapped);
                else
                {
                    bytes.Add((byte)'?');
                    replacedCount++;
                }
            }

            return bytes.ToArray();
        }

        /// <summary>
        /// Nordea spec 2.3.2: CR/LF ignored entirely, 0x20-0x7E used unchanged, anything else replaced by 0xC3.
        /// Applied to the bytes that are actually written, so sender and receiver hash the same data.
        /// </summary>
        private static byte[] NormalizeForMac(byte[] content)
        {
            var normalized = new List<byte>(content.Length);

            foreach (byte b in content)
            {
                if (b == 0x0D || b == 0x0A)
                    continue;

                normalized.Add(b is >= 0x20 and <= 0x7E ? b : (byte)0xC3);
            }

            return normalized.ToArray();
        }

        private static string GetSealMac(byte[] key, byte[] message)
        {
            using var hmac = new HMACSHA256(key);
            byte[] hash = hmac.ComputeHash(message);
            return Convert.ToHexString(hash, 0, 16); // first 128 bits, uppercase hex
        }

        private static TransmissionHeader CreateTransmissionHeader(NordeaHmacInputTransmissionHeader input)
        {
            string externalReference = DateTime.Now.ToString("yyMMdd");

            var th = new TransmissionHeader
            {
                _001Pos1To4 = "%001",
                NodeIdPos5To14 = Pad(input.NodeId_Pos_5_To_14, "Node id pos 5 to 14", 10),
                PasswordPos15To20 = Pad(null, "Password pos 15 to 20", 6),
                DeliveryPos21 = "0",
                FileTypePos22To24 = Pad(input.FileType_Pos_22_To_24, "File type pos 22 to 24", 3),
                ExternalReferencePos25To30 = Pad(externalReference, "External reference pos 25 to 30", 6),
                FreeFieldPos31 = Pad(null, "Free field pos 31", 1),
                ZeroPos32 = "0",
                ReservePos33To80 = Pad(null, "Reserve pos 33 to 80", 48)
            };

            th.TransmissionHeaderLine = th._001Pos1To4 + th.NodeIdPos5To14 + th.PasswordPos15To20 + th.DeliveryPos21
                + th.FileTypePos22To24 + th.ExternalReferencePos25To30 + th.FreeFieldPos31 + th.ZeroPos32 + th.ReservePos33To80;

            return th;
        }

        private static FileHeader CreateFileHeader(NordeaHmacInputFileHeader input)
        {
            string externalReference1 = DateTime.Now.ToString("yyMMdd");

            var fh = new FileHeader
            {
                _020Pos1To4 = "%020",
                DestinationNodePos5To14 = Pad(input.DestinationNode_Pos_5_To_14, "Destination node pos 5 to 14", 10),
                SourceNodePos15To24 = Pad(input.SourceNode_Pos_15_To_24, "Source node pos 15 to 24", 10),
                ExternalReference1Pos25To31 = Pad(externalReference1, "External reference 1 pos 25 to 31", 7),
                NumberOfItemsPos32To38 = Pad(input.NumberOfItems_Pos_32_To_38, "Number of items pos 32 to 38", 7),
                ExternalReference2Pos39To48 = Pad(null, "External reference 2 pos 39 to 48", 10),
                ReservePos49To80 = Pad(null, "Reserve pos 49 to 80", 32)
            };

            fh.FileHeaderLine = fh._020Pos1To4 + fh.DestinationNodePos5To14 + fh.SourceNodePos15To24
                + fh.ExternalReference1Pos25To31 + fh.NumberOfItemsPos32To38 + fh.ExternalReference2Pos39To48 + fh.ReservePos49To80;

            return fh;
        }

        private static FileTrailer CreateFileTrailer(NordeaHmacInputFileTrailer input, string kvvHmac, string fileContentHmac)
        {
            var ft = new FileTrailer
            {
                _002Pos1To4 = "%022",
                NumberOfRecords_Pos_5_To_11 = Pad(input.NumberOfRecords_Pos_5_To_11, "Number of Records pos 5 to 11", 7, zeroPad: true),
                KeyVerificationValueHmac_Pos_12_43 = kvvHmac,
                FileContentHmac_Pos_44_75 = fileContentHmac,
                ReservePos76To80 = Pad(null, "Reserve pos 76 to 80", 5)
            };

            ft.FileTrailerLine = ft._002Pos1To4 + ft.NumberOfRecords_Pos_5_To_11 + ft.KeyVerificationValueHmac_Pos_12_43
                + ft.FileContentHmac_Pos_44_75 + ft.ReservePos76To80;

            return ft;
        }

        private static TransmissionTrailer CreateTransmissionTrailer()
        {
            var tt = new TransmissionTrailer
            {
                _002Pos1To4 = "%002",
                ReservePos5To80 = Pad(null, "Reserve pos 5 to 80", 76)
            };

            tt.TransmissionTrailerLine = tt._002Pos1To4 + tt.ReservePos5To80;

            return tt;
        }

        /// <summary>
        /// Assembles the whole file in memory and writes it in one call, so a failure never leaves a half-written target.
        /// The %-records go through StrictAscii, so a non-ASCII character in a header input throws.
        /// </summary>
        private static OutputDiagnostics WriteOutFile(
            string outFilePath, byte[] content,
            string transmissionHeaderLine, string fileHeaderLine,
            string fileTrailerLine, string transmissionTrailerLine)
        {
            using var output = new MemoryStream();

            void Write(byte[] bytes) => output.Write(bytes, 0, bytes.Length);

            Write(StrictAscii.GetBytes(transmissionHeaderLine + "\r\n"));
            Write(StrictAscii.GetBytes(fileHeaderLine + "\r\n"));
            Write(content);
            Write(StrictAscii.GetBytes("\r\n" + fileTrailerLine + "\r\n" + transmissionTrailerLine));

            byte[] finalBytes = output.ToArray();

            bool hasBom = finalBytes.Length >= 3 &&
                          finalBytes[0] == 0xEF &&
                          finalBytes[1] == 0xBB &&
                          finalBytes[2] == 0xBF;

            bool hasNonAscii = Array.Exists(finalBytes, b => b > 0x7F);

            if (hasNonAscii)
                throw new Exception("Output contains non-ASCII bytes!");

            File.WriteAllBytes(outFilePath, finalBytes);

            return new OutputDiagnostics
            {
                OutputEncoding = "7-bit ASCII",
                ContainsUtf8Bom = hasBom,
                ContainsNonAsciiBytes = hasNonAscii,
                OutputByteCount = finalBytes.Length
            };
        }

        private class OutputDiagnostics
        {
            public string OutputEncoding { get; set; }
            public bool ContainsUtf8Bom { get; set; }
            public bool ContainsNonAsciiBytes { get; set; }
            public int OutputByteCount { get; set; }
        }

        private static string Pad(string? value, string fieldName, int maxChars, bool zeroPad = false)
        {
            value ??= string.Empty;

            if (value.Length > maxChars)
                throw new Exception($"Maximum characters allowed for '{fieldName}' are {maxChars}, found {value.Length}!");

            return zeroPad ? value.PadLeft(maxChars, '0') : value.PadRight(maxChars, ' ');
        }
    }
}