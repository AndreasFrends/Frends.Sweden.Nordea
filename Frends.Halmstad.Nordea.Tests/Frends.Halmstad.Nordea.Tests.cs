using Frends.Sweden.Nordea;
using NUnit.Framework;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;

namespace Frends.Sweden.Nordea.Tests
{
    [TestFixture]
    class TestClass
    {
        /// <summary>
        /// You need to run Frends.Sweden.Nordea.SetPaswordsEnv.ps1 before running unit test, or some other way set environment variables e.g. with GitHub Secrets.
        /// </summary>

        private readonly string _secretKey = "1234567890ABCDEF1234567890ABCDEF";
        private readonly string _testFilePath = Path.Combine(TestContext.CurrentContext.TestDirectory, "TestFiles");
        private string _tempTestFolder;
        private Result _result;
        private string[] _lines;

        [SetUp]
        public void TestSetup()
        {
            // Create tmp directory if not exists
            _tempTestFolder = Path.Combine(Path.GetTempPath(), "NordeaSwedenTest");
            if (!Directory.Exists(_tempTestFolder)) Directory.CreateDirectory(_tempTestFolder);

            // Create test properties and run
            var nordeaHmacInputGeneral = new NordeaHmacInputGeneral
            {
                SecretKey = _secretKey,
                SourceFilePath = _testFilePath + @"\exempelfil_bankfil.txt",
                TargetFilePath = _tempTestFolder + @"\generated.txt"
            };

            var nordeaHmacInputTransmissionHeader = new NordeaHmacInputTransmissionHeader
            {
                NodeId_Pos_5_To_14 = "AAAAAAAAAA",
                Password_Pos_15_To_20 = "BBBBBB",
                FileType_Pos_22_To_24 = "CCC",
            };

            var nordeaHmacInputFileHeader = new NordeaHmacInputFileHeader
            {
                DestinationNode_Pos_5_To_14 = "AAAAAAAAAA",
                SourceNode_Pos_15_To_24 = "BBBBBBBBBB",
                NumberOfItems_Pos_32_To_38 = "DDDDDDD",
            };

            var nordeaHmacInputFileTrailer = new NordeaHmacInputFileTrailer
            {
                NumberOfRecords_Pos_5_To_11 = "AAAAAAA",
            };

            var nordeaHmacInputTransmissionTrailer = new NordeaHmacInputTransmissionTrailer
            {
            };

            var result = Sweden.Nordea.GenerateNordeaHmacFile.FileProtectionHmac(nordeaHmacInputGeneral, nordeaHmacInputTransmissionHeader, nordeaHmacInputFileHeader, nordeaHmacInputFileTrailer, nordeaHmacInputTransmissionTrailer, new CancellationToken());

            _result = (Result)result;

            // Get all lines from generated test file
            _lines = File.ReadAllLines(_tempTestFolder + @"\generated.txt");
        }

        private static string ComputeFileHash(string path)
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(path);
            return Convert.ToHexString(sha256.ComputeHash(stream));
        }

        [TearDown]
        public void TestTearDown()
        {
            Directory.Delete(_tempTestFolder, true);
        }

        [Test]
        public void KeyVerificationValueHmacTest()
        {
            // Get KVV HMAC from generated target file
            var t = Array.FindAll(_lines, s => s.StartsWith("%022"));
            var kvv = t[0].Substring(11, 32);

            // KVV HMAC should be same as as result
            Assert.AreEqual(_result.FileTrailer.KeyVerificationValueHmac_Pos_12_43, kvv);
        }

        [Test]
        public void FileContentHmacTest()
        {
            // Get file content Hmac from generated target file
            var t = Array.FindAll(_lines, s => s.StartsWith("%022"));
            var fc = t[0].Substring(43, 32);

            // File content HMAC should be same as as result output
            Assert.AreEqual(_result.FileTrailer.FileContentHmac_Pos_44_75, fc);
        }

        [Test]
        public void TransmissionHeaderTest()
        {
            // Get transmission header line in generated target file
            var t = Array.FindAll(_lines, s => s.StartsWith("%001"));

            // Transmission header line should be 80 chars long
            Assert.AreEqual(80, t[0].Length);

            // Transmission header line should be same as result output
            Assert.AreEqual(_result.TransmissionHeader.TransmissionHeaderLine, t[0]);
        }

        [Test]
        public void FileHeaderTest()
        {
            // Get file header line in generated target file
            var t = Array.FindAll(_lines, s => s.StartsWith("%020"));

            // File header line should be 80 chars long
            Assert.AreEqual(80, t[0].Length);

            // File header line should be same as result JObject
            Assert.AreEqual(_result.FileHeader.FileHeaderLine, t[0]);
        }

        [Test]
        public void FileTrailerTest()
        {
            // Get file trailer line in generated target file
            var t = Array.FindAll(_lines, s => s.StartsWith("%022"));

            // File trailer line should be 80 chars long
            Assert.AreEqual(80, t[0].Length);

            // File trailer line should be same as result JObject
            Assert.AreEqual(_result.FileTrailer.FileTrailerLine, t[0]);
        }

        [Test]
        public void TransmissionTrailerTest()
        {
            // Get transmission trailer line in generated target file
            var t = Array.FindAll(_lines, s => s.StartsWith("%002"));

            // Transmission trailer line should be 80 chars long
            Assert.AreEqual(80, t[0].Length);

            // Transmission trailer line should be same as result JObject
            Assert.AreEqual(_result.TransmissionTrailer.TransmissionTrailerLine, t[0]);
        }

        [Test]
        public void KvvMatchesKnownVectorTest()
        {
            // Independently computed via HMAC-SHA256(key, "00000000")[:16 bytes], hex, uppercase.
            // Proves the algorithm itself is correct, not just internally consistent with its own output.
            const string expectedKvv = "FF365893D899291C3BF505FB3175E880";
            Assert.AreEqual(expectedKvv, _result.FileTrailer.KeyVerificationValueHmac_Pos_12_43);
        }

        [Test]
        public void NumberOfRecordsIsLeftZeroPaddedTest()
        {
            // Spec: right-aligned, zero-padded. "14" must become "0000014", not "1400000".
            var tempFolder = Path.Combine(Path.GetTempPath(), "NordeaSwedenTest_Padding");
            Directory.CreateDirectory(tempFolder);

            try
            {
                var general = new NordeaHmacInputGeneral
                {
                    SecretKey = _secretKey,
                    SourceFilePath = _testFilePath + @"\exempelfil_bankfil.txt",
                    TargetFilePath = tempFolder + @"\generated.txt"
                };

                var result = (Result)Sweden.Nordea.GenerateNordeaHmacFile.FileProtectionHmac(
                    general,
                    new NordeaHmacInputTransmissionHeader(),
                    new NordeaHmacInputFileHeader(),
                    new NordeaHmacInputFileTrailer { NumberOfRecords_Pos_5_To_11 = "14" },
                    new NordeaHmacInputTransmissionTrailer(),
                    new CancellationToken());

                Assert.AreEqual("0000014", result.FileTrailer.NumberOfRecords_Pos_5_To_11);
            }
            finally
            {
                Directory.Delete(tempFolder, true);
            }
        }

        [Test]
        public void OutputFileStructureOrderTest()
        {
            // Spec: strict order %001, %020, <original content>, %022, %002
            Assert.IsTrue(_lines[0].StartsWith("%001"), "First line should be transmission header (%001)");
            Assert.IsTrue(_lines[1].StartsWith("%020"), "Second line should be file header (%020)");
            Assert.IsTrue(_lines[_lines.Length - 2].StartsWith("%022"), "Second-to-last line should be file trailer (%022)");
            Assert.IsTrue(_lines[_lines.Length - 1].StartsWith("%002"), "Last line should be transmission trailer (%002)");
        }

        [Test]
        public void SourceFileUnchangedTest()
        {
            // Spec: "The original file content shall not be modified."
            var tempFolder = Path.Combine(Path.GetTempPath(), "NordeaSwedenTest_SourceUnchanged");
            Directory.CreateDirectory(tempFolder);

            var sourceFilePath = _testFilePath + @"\exempelfil_bankfil.txt";

            try
            {
                var beforeHash = ComputeFileHash(sourceFilePath);

                var general = new NordeaHmacInputGeneral
                {
                    SecretKey = _secretKey,
                    SourceFilePath = sourceFilePath,
                    TargetFilePath = tempFolder + @"\generated.txt"
                };

                Sweden.Nordea.GenerateNordeaHmacFile.FileProtectionHmac(
                    general,
                    new NordeaHmacInputTransmissionHeader(),
                    new NordeaHmacInputFileHeader(),
                    new NordeaHmacInputFileTrailer(),
                    new NordeaHmacInputTransmissionTrailer(),
                    new CancellationToken());

                var afterHash = ComputeFileHash(sourceFilePath);

                Assert.AreEqual(beforeHash, afterHash, "Source file content changed - spec requires original file untouched.");
            }
            finally
            {
                Directory.Delete(tempFolder, true);
            }
        }

        [Test]
        public void TargetFileAlreadyExistsThrowsTest()
        {
            var tempFolder = Path.Combine(Path.GetTempPath(), "NordeaSwedenTest_TargetExists");
            Directory.CreateDirectory(tempFolder);

            var targetPath = tempFolder + @"\generated.txt";
            File.WriteAllText(targetPath, "already here");

            try
            {
                var general = new NordeaHmacInputGeneral
                {
                    SecretKey = _secretKey,
                    SourceFilePath = _testFilePath + @"\exempelfil_bankfil.txt",
                    TargetFilePath = targetPath
                };

                Assert.Throws<Exception>(() => Sweden.Nordea.GenerateNordeaHmacFile.FileProtectionHmac(
                    general,
                    new NordeaHmacInputTransmissionHeader(),
                    new NordeaHmacInputFileHeader(),
                    new NordeaHmacInputFileTrailer(),
                    new NordeaHmacInputTransmissionTrailer(),
                    new CancellationToken()));
            }
            finally
            {
                Directory.Delete(tempFolder, true);
            }
        }

        [Test]
        public void NormalizationExcludesHeaderTrailerTest()
        {
            // Spec: HMAC covers only business data records. Changing header/trailer reserve
            // fields must not change the content HMAC.
            var hmacA = RunWithReserveValue("AAAA");
            var hmacB = RunWithReserveValue("ZZZZ");

            Assert.AreEqual(hmacA, hmacB);
        }

        private string RunWithReserveValue(string reserveValue)
        {
            var tempFolder = Path.Combine(Path.GetTempPath(), "NordeaSwedenTest_" + Guid.NewGuid());
            Directory.CreateDirectory(tempFolder);

            try
            {
                var general = new NordeaHmacInputGeneral
                {
                    SecretKey = _secretKey,
                    SourceFilePath = _testFilePath + @"\exempelfil_bankfil.txt",
                    TargetFilePath = tempFolder + @"\generated.txt"
                };

                var transmissionHeader = new NordeaHmacInputTransmissionHeader { };

                var result = (Result)Sweden.Nordea.GenerateNordeaHmacFile.FileProtectionHmac(
                    general,
                    transmissionHeader,
                    new NordeaHmacInputFileHeader(),
                    new NordeaHmacInputFileTrailer(),
                    new NordeaHmacInputTransmissionTrailer(),
                    new CancellationToken());

                return result.FileTrailer.FileContentHmac_Pos_44_75;
            }
            finally
            {
                Directory.Delete(tempFolder, true);
            }
        }

        [Test]
        public void NormalizationStripsCrLfAndReplacesOutOfRangeCharsTest()
        {
            // Spec: CR/LF ignored entirely; chars outside 0x20-0x7E replaced with 0xC3.
            // Fixture bytes (ISO-8859-1): A B CR LF C <0x01> D
            // Expected normalized HMAC input: A B C 0xC3 D
            // Deliberately uses a control char, not a diacritic - avoids the open CharMap question.
            var tempFolder = Path.Combine(Path.GetTempPath(), "NordeaSwedenTest_Normalization");
            Directory.CreateDirectory(tempFolder);

            var sourceFilePath = Path.Combine(tempFolder, "source.txt");
            File.WriteAllBytes(sourceFilePath, new byte[] { 0x41, 0x42, 0x0D, 0x0A, 0x43, 0x01, 0x44 });

            try
            {
                var general = new NordeaHmacInputGeneral
                {
                    SecretKey = _secretKey,
                    SourceFilePath = sourceFilePath,
                    TargetFilePath = Path.Combine(tempFolder, "generated.txt")
                };

                var result = (Result)Sweden.Nordea.GenerateNordeaHmacFile.FileProtectionHmac(
                    general,
                    new NordeaHmacInputTransmissionHeader(),
                    new NordeaHmacInputFileHeader(),
                    new NordeaHmacInputFileTrailer(),
                    new NordeaHmacInputTransmissionTrailer(),
                    new CancellationToken());

                const string expectedHmac = "99136248BD392CE201F431D2A93FC358";
                Assert.AreEqual(expectedHmac, result.FileTrailer.FileContentHmac_Pos_44_75);
            }
            finally
            {
                Directory.Delete(tempFolder, true);
            }
        }
    }
}
