from __future__ import annotations

import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

from packaging.version import Version

BUILD_GRADLE = Path(__file__).resolve().parents[2] / "build.gradle"
MAVEN_METADATA_URL = "https://repo1.maven.org/maven2/ai/reveng/sdk/maven-metadata.xml"

SDK_PIN_RE = re.compile(r"ai\.reveng:sdk:([\d.]+)")
STABLE_RE = re.compile(r"^\d+\.\d+\.\d+$")


def fetch_latest_maven_version() -> str:
    with urllib.request.urlopen(MAVEN_METADATA_URL, timeout=30) as resp:
        root = ET.parse(resp).getroot()
    versions = [
        (el.text or "").strip()
        for el in root.findall("./versioning/versions/version")
        if el.text and STABLE_RE.match(el.text.strip())
    ]
    if not versions:
        raise RuntimeError("no stable ai.reveng:sdk versions found on Maven Central")
    return max(versions, key=Version)


def emit(key: str, value: str) -> None:
    print(f"{key}={value}")


def main() -> int:
    text = BUILD_GRADLE.read_text()

    sdk_match = SDK_PIN_RE.search(text)
    if not sdk_match:
        print("error: could not find ai.reveng:sdk pin in build.gradle", file=sys.stderr)
        return 1
    current_sdk = sdk_match.group(1)

    latest_sdk = fetch_latest_maven_version()

    emit("current_sdk", current_sdk)
    emit("new_sdk", latest_sdk)

    if Version(latest_sdk) <= Version(current_sdk):
        emit("changed", "false")
        return 0

    new_text = text.replace(
        f"ai.reveng:sdk:{current_sdk}",
        f"ai.reveng:sdk:{latest_sdk}",
    )
    BUILD_GRADLE.write_text(new_text)

    emit("changed", "true")
    return 0


if __name__ == "__main__":
    sys.exit(main())
