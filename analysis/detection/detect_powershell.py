
import re
import json
from pathlib import Path

CASE_ID = "PS-001"

INDICATORS = {
    "download_method": re.compile(
        r"\bDownloadString\b|\bDownloadFile\b",
        re.IGNORECASE,
    ),
    "download_related_keyword": re.compile(
        r"\bdownload\b|\bpayload\b|\bstage2\b",
        re.IGNORECASE,
    ),
    "encoded_command": re.compile(
        r"-(?:EncodedCommand|enc)\b",
        re.IGNORECASE,
    ),
    "hidden_window": re.compile(
        r"-WindowStyle\s+Hidden",
        re.IGNORECASE,
    ),
    "suspicious_destination": re.compile(
        r"\\(?:AppData|Temp|Public)\\",
        re.IGNORECASE,
    ),
    "external_url": re.compile(
        r"https?://(?!example\.invalid\b)[^\s\"']+",
        re.IGNORECASE,
    ),
    "example_url": re.compile(
        r"https?://example\.invalid\b",
        re.IGNORECASE,
    ),
}


def analyse_script(script_text):
    findings = []

    for name, pattern in INDICATORS.items():
        if pattern.search(script_text):
            findings.append(name)

    return {
        "case_id": CASE_ID,
        "indicator_count": len(findings),
        "findings": findings,
        "verdict": (
            "REVIEW_REQUIRED" if findings else "NO_MATCHING_INDICATORS"
        ),
        "limitation": (
            "Static keyword and pattern matching only. Findings do not prove "
            "execution, a successful download, or malicious intent."
        ),
    }


if __name__ == "__main__":
    sample_path = Path("evidence/suspicious-script-sample.txt")
    script = sample_path.read_text(encoding="utf-8")
    result = analyse_script(script)

    print(json.dumps(result, indent=2))
