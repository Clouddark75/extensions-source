
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
# Directories
# ---------------------------------------------------------------------------

repo_apk_dir = repo_dir / "apk"
repo_icon_dir = repo_dir / "icon"

repo_apk_dir.mkdir(parents=True, exist_ok=True)
repo_icon_dir.mkdir(parents=True, exist_ok=True)


def clear_directory(directory: Path) -> None:
    for item in directory.iterdir():
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()


# A full rebuild makes the build output the source of truth.
if full_rebuild:
    print("Full rebuild: clearing previous APKs and icons")
    clear_directory(repo_apk_dir)
    clear_directory(repo_icon_dir)


# ---------------------------------------------------------------------------
# Android build tools / aapt
# ---------------------------------------------------------------------------

android_home = os.environ.get("ANDROID_HOME")

if not android_home:
    raise EnvironmentError("ANDROID_HOME is not set")

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

if not aapt.exists():
    raise FileNotFoundError(f"aapt not found: {aapt}")


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
    apk: Path,
) -> str:
    match = pattern.search(text)

    if match is None:
        raise ValueError(
            f"Could not find {description} in {apk.name}"
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


def normalize_apk_name(apk: Path) -> str:
    return apk.name.replace("-release.apk", ".apk")


def remove_module_files(module: str) -> None:
    apk_pattern = f"tachiyomi-{module}-v*.apk"
    icon_pattern = (
        f"eu.kanade.tachiyomi.extension.{module}.png"
    )

    for file in repo_apk_dir.glob(apk_pattern):
        print(f"  Removing APK: {file.name}")
        file.unlink(missing_ok=True)

    for file in repo_icon_dir.glob(icon_pattern):
        print(f"  Removing icon: {file.name}")
        file.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Read existing index and content hashes
# ---------------------------------------------------------------------------

index_path = repo_dir / "index.json"
hashes_path = repo_dir / "content-hashes.json"

if full_rebuild:
    remote_index = []
    content_hashes = {}
else:
    if index_path.exists():
        with index_path.open(encoding="utf-8") as file:
            remote_index = json.load(file)

        if not isinstance(remote_index, list):
            raise ValueError(
                f"{index_path} does not contain a JSON array"
            )
    else:
        remote_index = []

    if hashes_path.exists():
        with hashes_path.open(encoding="utf-8") as file:
            content_hashes = json.load(file)

        if not isinstance(content_hashes, dict):
            raise ValueError(
                f"{hashes_path} does not contain a JSON object"
            )
    else:
        content_hashes = {}


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
# Collect source-info files and APKs
# ---------------------------------------------------------------------------

info_files = (
    sorted(artifacts_dir.glob("**/keiyoushi-source-info.json"))
    if artifacts_dir.is_dir()
    else []
)

print(f"Found {len(info_files)} source-info files")

new_entries: list[dict] = []
rebuilt_packages: set[str] = set()

for info_file in info_files:
    with info_file.open(encoding="utf-8") as file:
        info = json.load(file)

    package_name = info["packageName"]
    module = info["module"]

    if not full_rebuild:
        print(f"Processing: {package_name}")

    apk_dir = info_file.parent / "outputs" / "apk" / "release"
    apk_files = sorted(apk_dir.glob("*.apk"))

    if not apk_files:
        raise FileNotFoundError(
            f"{package_name}: no release APK found under {apk_dir}"
        )

    apk = apk_files[0]
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
    language = get_language(normalize_apk_name(apk), sources)
    nsfw = get_nsfw(info, badging)

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
    # Copy APK to repo2/apk/
    # -----------------------------------------------------------------------

    final_apk_name = normalize_apk_name(apk)
    destination_apk = repo_apk_dir / final_apk_name

    shutil.copy2(apk, destination_apk)

    print(f"APK: {final_apk_name}")

    # -----------------------------------------------------------------------
    # Extract icon to repo2/icon/
    # -----------------------------------------------------------------------

    extract_icon(
        apk,
        package_name,
        badging,
    )

    # -----------------------------------------------------------------------
    # Build old-style index entry
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
        "lang": language,
        "code": version_code,
        "version": version_name,
        "nsfw": nsfw,
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

with index_path.open("w", encoding="utf-8") as index_file:
    json.dump(
        final_index,
        index_file,
        ensure_ascii=False,
        indent=2,
    )
    index_file.write("\n")


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

with hashes_path.open("w", encoding="utf-8") as hashes_file:
    json.dump(
        content_hashes,
        hashes_file,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    hashes_file.write("\n")


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
        "<title>apks</title>\n"
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
            f"{name_escaped}"
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

print()
print("========================================")
print("Repository published successfully")
print("========================================")
print(f"Repository: {repo_dir}")
print(f"APK directory: {repo_apk_dir}")
print(f"Icon directory: {repo_icon_dir}")
print(f"Extensions rebuilt: {len(new_entries)}")
print(f"Extensions in index: {len(final_index)}")
print(f"Deleted modules: {len(to_delete)}")
print(f"Full rebuild: {full_rebuild}")
print(f"Commit: {current_sha}")
print("========================================")
