
import unittest
from analysis.detect_powershell import analyse_script


class TestPowerShellDetector(unittest.TestCase):

    def test_benign_script(self):
        result = analyse_script("Start-Sleep -Seconds 2")
        self.assertEqual(result["indicator_count"], 0)
        self.assertEqual(
            result["verdict"], "NO_MATCHING_INDICATORS"
        )

    def test_download_method(self):
        result = analyse_script(
            '$client.DownloadString("https://example.invalid/test")'
        )
        self.assertIn("download_method", result["findings"])

    def test_encoded_command(self):
        result = analyse_script(
            "powershell.exe -EncodedCommand ABC123"
        )
        self.assertIn("encoded_command", result["findings"])

    def test_hidden_window(self):
        result = analyse_script(
            "powershell.exe -WindowStyle Hidden"
        )
        self.assertIn("hidden_window", result["findings"])

    def test_suspicious_destination(self):
        result = analyse_script(
            'Copy-Item file.bin "C:\\Users\\Public\\file.bin"'
        )
        self.assertIn(
            "suspicious_destination", result["findings"]
        )

    def test_example_domain_is_excluded(self):
        result = analyse_script(
            'Write-Output "https://example.invalid/payload"'
        )
        self.assertNotIn("external_url", result["findings"])


if __name__ == "__main__":
    unittest.main()
