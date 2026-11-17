
import copy
import html
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from zipfile import ZipFile


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

if len(sys.argv) != 5:
    print(
        "Usage: publish-repo.py <delete-json> <commit-sha> <repo-dir> <full-rebuild>",
        file=sys.stderr,
    )
    sys.exit(1)

to_delete: list[str] = json.loads(sys.argv[1])
current_sha = sys.argv[2]
repo_dir = Path(sys.argv[3]).resolve()
full_rebuild = sys.argv[4].lower() == "true"

artifacts_dir = Path.home() / "apk-artifacts"

if not full_rebuild and not artifacts_dir.is_dir():
    raise FileNotFoundError(
        f"Artifacts directory does not exist: {artifacts_dir}"
    )


# ---------------------------------------------------------------------------
# Repository configuration
# ---------------------------------------------------------------------------

REPO_BASE_URL = (
    "https://raw.githubusercontent.com/"
    "Clouddark75/extensions-source/repo3"
)

REPO_NAME = "Clouddark75 Extensions"
REPO_WEBSITE = (
    "https://github.com/Clouddark75/extensions-source"
)


# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------

repo_apk_dir = repo_dir / "apk"
repo_jar_dir = repo_dir / "jar"
repo_icon_dir = repo_dir / "icon"

repo_apk_dir.mkdir(parents=True, exist_ok=True)
repo_jar_dir.mkdir(parents=True, exist_ok=True)
repo_icon_dir.mkdir(parents=True, exist_ok=True)


def clear_directory(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)

    for item in directory.iterdir():
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()


# A full rebuild makes the build output the source of truth.
if full_rebuild:
    print("Full rebuild: clearing previous APKs, JARs and icons")

    clear_directory(repo_apk_dir)
    clear_directory(repo_jar_dir)
    clear_directory(repo_icon_dir)


# ---------------------------------------------------------------------------
# Android build tools / aapt / apksigner
# ---------------------------------------------------------------------------

android_home = os.environ.get("ANDROID_HOME")

if not android_home:
    android_home = os.environ.get("ANDROID_SDK_ROOT")

if not android_home:
    raise EnvironmentError(
        "ANDROID_HOME and ANDROID_SDK_ROOT are not set"
    )

build_tools_dir = Path(android_home) / "build-tools"

if not build_tools_dir.is_dir():
    raise FileNotFoundError(
        f"Android build-tools directory does not exist: {build_tools_dir}"
    )

build_tools = sorted(
    (
        path
        for path in build_tools_dir.iterdir()
        if path.is_dir()
    ),
    key=lambda path: path.name,
)

if not build_tools:
    raise FileNotFoundError(
        f"No Android build-tools found in {build_tools_dir}"
    )

aapt = build_tools[-1] / "aapt"
apksigner = build_tools[-1] / "apksigner"

if not aapt.exists():
    raise FileNotFoundError(f"aapt not found: {aapt}")

if not apksigner.exists():
    raise FileNotFoundError(f"apksigner not found: {apksigner}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PACKAGE_NAME_REGEX = re.compile(r"package: name='([^']+)'")
VERSION_CODE_REGEX = re.compile(r"versionCode='([^']+)'")
VERSION_NAME_REGEX = re.compile(r"versionName='([^']+)'")

IS_NSFW_REGEX = re.compile(
    r"'tachiyomi.extension.nsfw' value='([^']+)'"
)

APPLICATION_LABEL_REGEX = re.compile(
    r"^application-label:'([^']+)'",
    re.MULTILINE,
)

APPLICATION_ICON_REGEX = re.compile(
    r"^application-icon-\d+:'([^']+)'",
    re.MULTILINE,
)

LANGUAGE_REGEX = re.compile(
    r"tachiyomi-([^.]+)"
)


def get_apk_badging(apk: Path) -> str:
    return subprocess.check_output(
        [
            str(aapt),
            "dump",
            "--include-meta-data",
            "badging",
            str(apk),
        ],
        text=True,
    )


def get_match(
    pattern: re.Pattern[str],
    text: str,
    description: str,
    file: Path,
) -> str:
    match = pattern.search(text)

    if match is None:
        raise ValueError(
            f"Could not find {description} in {file.name}"
        )

    return match.group(1)


def get_icon_path(badging: str) -> str | None:
    match = APPLICATION_ICON_REGEX.search(badging)

    return match.group(1) if match else None


def extract_icon(
    apk: Path,
    package_name: str,
    badging: str,
) -> None:
    icon_path = get_icon_path(badging)

    if not icon_path:
        print(
            f"Warning: no application icon found in {apk.name}"
        )
        return

    output_icon = repo_icon_dir / f"{package_name}.png"

    try:
        with ZipFile(apk) as archive:
            if icon_path not in archive.namelist():
                print(
                    f"Warning: icon {icon_path} not found in {apk.name}"
                )
                return

            with archive.open(icon_path) as source:
                with output_icon.open("wb") as destination:
                    shutil.copyfileobj(source, destination)

        print(f"Icon: {output_icon.name}")

    except Exception as error:
        print(
            f"Warning: could not extract icon from "
            f"{apk.name}: {error}"
        )


def get_language(
    apk_name: str,
    sources: list[dict],
) -> str:
    match = LANGUAGE_REGEX.search(apk_name)
    language = match.group(1) if match else "all"

    if len(sources) == 1:
        source_language = sources[0].get("lang", language)

        if (
            source_language != language
            and source_language not in {"all", "other"}
            and language not in {"all", "other"}
        ):
            language = source_language

    return language


def get_nsfw(
    info: dict,
    badging: str,
) -> int:
    content_warning = info.get("contentWarning")

    if isinstance(content_warning, bool):
        return int(content_warning)

    if isinstance(content_warning, int):
        return content_warning

    if isinstance(content_warning, str):
        normalized = content_warning.lower()

        if normalized in {"true", "1", "yes", "nsfw"}:
            return 1

        if normalized in {"false", "0", "no", "", "safe"}:
            return 0

    match = IS_NSFW_REGEX.search(badging)

    if match:
        return int(match.group(1))

    return 0


def get_content_warning(
    info: dict,
    nsfw: int,
) -> str:
    content_warning = info.get("contentWarning")

    if isinstance(content_warning, str):
        normalized = content_warning.upper()

        if normalized in {"SAFE", "MIXED", "NSFW"}:
            return normalized

    return "MIXED" if nsfw else "SAFE"


def normalize_apk_name(apk: Path) -> str:
    return apk.name.replace("-release.apk", ".apk")


def normalize_jar_name(jar: Path) -> str:
    return jar.name.replace("-release.jar", ".jar")


def get_signing_fingerprint(apk: Path) -> str:
    output = subprocess.check_output(
        [
            str(apksigner),
            "verify",
            "--print-certs",
            str(apk),
        ],
        text=True,
    )

    match = re.search(
        r"Signer #1 certificate SHA-256 digest:\s*([a-fA-F0-9]+)",
        output,
    )

    if match is None:
        raise ValueError(
            f"Could not extract signing fingerprint from {apk.name}"
        )

    return match.group(1).lower()


def remove_module_files(module: str) -> None:
    apk_pattern = f"tachiyomi-{module}-v*.apk"
    jar_pattern = f"tachiyomi-{module}-v*.jar"

    icon_pattern = (
        f"eu.kanade.tachiyomi.extension.{module}.png"
    )

    for file in repo_apk_dir.glob(apk_pattern):
        print(f"  Removing APK: {file.name}")
        file.unlink(missing_ok=True)

    for file in repo_jar_dir.glob(jar_pattern):
        print(f"  Removing JAR: {file.name}")
        file.unlink(missing_ok=True)

    for file in repo_icon_dir.glob(icon_pattern):
        print(f"  Removing icon: {file.name}")
        file.unlink(missing_ok=True)


def read_json(path: Path, default):
    if not path.exists():
        return default

    with path.open(encoding="utf-8") as file:
        return json.load(file)


def write_json(
    path: Path,
    data,
    indent: int = 2,
) -> None:
    with path.open("w", encoding="utf-8") as file:
        json.dump(
            data,
            file,
            ensure_ascii=False,
            indent=indent,
        )
        file.write("\n")


# ---------------------------------------------------------------------------
# Read existing index and content hashes
# ---------------------------------------------------------------------------

index_path = repo_dir / "index.json"
hashes_path = repo_dir / "content-hashes.json"
repo_metadata_path = repo_dir / "repo.json"

if full_rebuild:
    remote_index = []
    content_hashes = {}
else:
    remote_index = read_json(index_path, [])
    content_hashes = read_json(hashes_path, {})

    if not isinstance(remote_index, list):
        raise ValueError(
            f"{index_path} does not contain a JSON array"
        )

    if not isinstance(content_hashes, dict):
        raise ValueError(
            f"{hashes_path} does not contain a JSON object"
        )


# ---------------------------------------------------------------------------
# Remove deleted modules
# ---------------------------------------------------------------------------

if not full_rebuild:
    for module in to_delete:
        print(f"Removing deleted or rebuilt module: {module}")
        remove_module_files(module)

    content_hashes = {
        package_name: content_hash
        for package_name, content_hash in content_hashes.items()
        if not any(
            package_name.endswith(f".{module}")
            for module in to_delete
        )
    }


# ---------------------------------------------------------------------------
# Collect source-info files and APKs / JARs
# ---------------------------------------------------------------------------

info_files = (
    sorted(artifacts_dir.glob("**/keiyoushi-source-info.json"))
    if artifacts_dir.is_dir()
    else []
)

print(f"Found {len(info_files)} source-info files")

new_entries: list[dict] = []
rebuilt_packages: set[str] = set()

signing_fingerprint: str | None = None

for info_file in info_files:
    with info_file.open(encoding="utf-8") as file:
        info = json.load(file)

    package_name = info["packageName"]
    module = info["module"]

    if not full_rebuild:
        print(f"Processing: {package_name}")

    # -----------------------------------------------------------------------
    # Locate APK
    # -----------------------------------------------------------------------

    apk_dir = info_file.parent / "outputs" / "apk" / "release"
    apk_files = sorted(apk_dir.glob("*.apk"))

    if not apk_files:
        raise FileNotFoundError(
            f"{package_name}: no release APK found under {apk_dir}"
        )

    apk = apk_files[0]

    # -----------------------------------------------------------------------
    # Locate JAR
    # -----------------------------------------------------------------------

    jar_dir = info_file.parent / "outputs" / "jar" / "release"
    jar_files = sorted(jar_dir.glob("*.jar"))

    if not jar_files:
        raise FileNotFoundError(
            f"{package_name}: no release JAR found under {jar_dir}"
        )

    jar = jar_files[0]

    badging = get_apk_badging(apk)

    package_info = next(
        (
            line
            for line in badging.splitlines()
            if line.startswith("package: ")
        ),
        None,
    )

    if package_info is None:
        raise ValueError(
            f"Could not find package information in {apk.name}"
        )

    badging_package_name = get_match(
        PACKAGE_NAME_REGEX,
        package_info,
        "package name",
        apk,
    )

    if badging_package_name != package_name:
        raise ValueError(
            f"Package mismatch for {apk.name}: "
            f"source-info says {package_name}, "
            f"APK says {badging_package_name}"
        )

    # -----------------------------------------------------------------------
    # Version information
    # -----------------------------------------------------------------------

    version_code_value = info.get("versionCode")

    if version_code_value is None:
        version_code_value = get_match(
            VERSION_CODE_REGEX,
            package_info,
            "version code",
            apk,
        )

    version_code = int(version_code_value)

    version_name = info.get("versionName")

    if version_name is None:
        version_name = get_match(
            VERSION_NAME_REGEX,
            package_info,
            "version name",
            apk,
        )

    name = info.get("name")

    if not name:
        name = get_match(
            APPLICATION_LABEL_REGEX,
            badging,
            "application label",
            apk,
        )

    sources = info.get("sources", [])

    language = get_language(
        normalize_apk_name(apk),
        sources,
    )

    nsfw = get_nsfw(info, badging)
    content_warning = get_content_warning(info, nsfw)

    # -----------------------------------------------------------------------
    # Content hash
    # -----------------------------------------------------------------------

    content_hash = info.get("contentHash")

    if not content_hash:
        raise ValueError(
            f"{package_name}: contentHash is missing from "
            f"{info_file}"
        )

    previous_hash = content_hashes.get(package_name)

    previous_entry = next(
        (
            item
            for item in remote_index
            if item.get("pkg") == package_name
        ),
        None,
    )

    previous_code = (
        previous_entry.get("code")
        if previous_entry is not None
        else None
    )

    changed = (
        previous_entry is None
        or previous_code != version_code
        or previous_hash != content_hash
    )

    if changed:
        print(
            f"Changed: {package_name} "
            f"(versionCode={version_code})"
        )
    else:
        print(f"Unchanged content: {package_name}")

    content_hashes[package_name] = content_hash

    # -----------------------------------------------------------------------
    # Copy APK
    # -----------------------------------------------------------------------

    final_apk_name = normalize_apk_name(apk)
    destination_apk = repo_apk_dir / final_apk_name

    shutil.copy2(apk, destination_apk)

    print(f"APK: {final_apk_name}")

    # -----------------------------------------------------------------------
    # Copy JAR
    # -----------------------------------------------------------------------

    final_jar_name = normalize_jar_name(jar)
    destination_jar = repo_jar_dir / final_jar_name

    shutil.copy2(jar, destination_jar)

    print(f"JAR: {final_jar_name}")

    # -----------------------------------------------------------------------
    # Signing fingerprint
    # -----------------------------------------------------------------------

    current_fingerprint = get_signing_fingerprint(apk)

    if signing_fingerprint is None:
        signing_fingerprint = current_fingerprint
    elif signing_fingerprint != current_fingerprint:
        raise ValueError(
            "Different APK signing certificates detected. "
            f"Expected {signing_fingerprint}, "
            f"found {current_fingerprint} in {apk.name}"
        )

    # -----------------------------------------------------------------------
    # Extract icon
    # -----------------------------------------------------------------------

    extract_icon(
        apk,
        package_name,
        badging,
    )

    # -----------------------------------------------------------------------
    # Build repository index entry
    # -----------------------------------------------------------------------

    source_entries = []

    for source in sources:
        source_entry = {
            "name": source["name"],
            "lang": source["lang"],
            "id": source["id"],
            "baseUrl": source["baseUrl"],
        }

        if "versionId" in source:
            source_entry["versionId"] = source["versionId"]

        source_entries.append(source_entry)

    entry = {
        "name": name,
        "pkg": package_name,
        "apk": final_apk_name,
        "jar": final_jar_name,
        "apkUrl": f"{REPO_BASE_URL}/apk/{final_apk_name}",
        "jarUrl": f"{REPO_BASE_URL}/jar/{final_jar_name}",
        "icon": f"{package_name}.png",
        "lang": language,
        "code": version_code,
        "version": version_name,
        "nsfw": nsfw,
        "contentWarning": content_warning,
        "sources": source_entries,
    }

    new_entries.append(entry)
    rebuilt_packages.add(package_name)


# ---------------------------------------------------------------------------
# Merge index
# ---------------------------------------------------------------------------

if full_rebuild:
    final_index = list(new_entries)
else:
    final_index = [
        item
        for item in remote_index
        if item.get("pkg") not in rebuilt_packages
        and not any(
            item.get("pkg", "").endswith(f".{module}")
            for module in to_delete
        )
    ]

    final_index.extend(new_entries)

final_index.sort(key=lambda item: item["pkg"])


# ---------------------------------------------------------------------------
# Write index.json
# ---------------------------------------------------------------------------

write_json(
    index_path,
    final_index,
)


# ---------------------------------------------------------------------------
# Write index.min.json
# ---------------------------------------------------------------------------

minified_index = copy.deepcopy(final_index)

for entry in minified_index:
    for source in entry.get("sources", []):
        source.pop("versionId", None)

index_min_path = repo_dir / "index.min.json"

with index_min_path.open("w", encoding="utf-8") as index_min_file:
    json.dump(
        minified_index,
        index_min_file,
        ensure_ascii=False,
        separators=(",", ":"),
    )


# ---------------------------------------------------------------------------
# Write content-hashes.json
# ---------------------------------------------------------------------------

write_json(
    hashes_path,
    content_hashes,
)


# ---------------------------------------------------------------------------
# Write repo.json for Suwayomi
# ---------------------------------------------------------------------------

if signing_fingerprint is None:
    previous_repo = read_json(repo_metadata_path, {})

    signing_fingerprint = (
        previous_repo.get("meta", {}).get(
            "signingKeyFingerprint"
        )
    )

if signing_fingerprint:
    repo_metadata = {
        "meta": {
            "name": REPO_NAME,
            "website": REPO_WEBSITE,
            "signingKeyFingerprint": signing_fingerprint,
        }
    }

    write_json(
        repo_metadata_path,
        repo_metadata,
    )
else:
    print(
        "Warning: signing fingerprint unavailable; "
        "repo.json was not updated."
    )


# ---------------------------------------------------------------------------
# Write index.html
# ---------------------------------------------------------------------------

index_html_path = repo_dir / "index.html"

with index_html_path.open("w", encoding="utf-8") as index_html_file:
    index_html_file.write(
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        '<meta charset="UTF-8">\n'
        "<title>Clouddark75 Extensions</title>\n"
        "</head>\n"
        "<body>\n"
        "<pre>\n"
    )

    for entry in final_index:
        apk_escaped = html.escape(
            f"apk/{entry['apk']}",
            quote=True,
        )

        name_escaped = html.escape(entry["name"])

        index_html_file.write(
            f'<a href="{apk_escaped}">'
            f"{name_escaped} (APK)"
            "</a>\n"
        )

        jar_name = entry.get("jar")

        if jar_name:
            jar_escaped = html.escape(
                f"jar/{jar_name}",
                quote=True,
            )

            index_html_file.write(
                f'<a href="{jar_escaped}">'
                f"{name_escaped} (JAR)"
                "</a>\n"
            )

    index_html_file.write(
        "</pre>\n"
        "</body>\n"
        "</html>\n"
    )


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

jar_count = len(list(repo_jar_dir.glob("*.jar")))
apk_count = len(list(repo_apk_dir.glob("*.apk")))

print()
print("========================================")
print("Repository published successfully")
print("========================================")
print(f"Repository: {repo_dir}")
print(f"APK directory: {repo_apk_dir}")
print(f"JAR directory: {repo_jar_dir}")
print(f"Icon directory: {repo_icon_dir}")
print(f"APKs: {apk_count}")
print(f"JARs: {jar_count}")
print(f"Extensions rebuilt: {len(new_entries)}")
print(f"Extensions in index: {len(final_index)}")
print(f"Deleted modules: {len(to_delete)}")
print(f"Full rebuild: {full_rebuild}")
print(f"Commit: {current_sha}")
print("========================================")
