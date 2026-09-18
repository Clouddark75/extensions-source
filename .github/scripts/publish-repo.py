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

if len(sys.argv) != 4:
    print(
        "Usage: publish-repo.py <delete-json> <commit-sha> <repo-dir>",
        file=sys.stderr,
    )
    sys.exit(1)

to_delete: list[str] = json.loads(sys.argv[1])
current_sha = sys.argv[2]
repo_dir = Path(sys.argv[3]).resolve()

artifacts_dir = Path.home() / "apk-artifacts"

if not repo_dir.is_dir():
    raise FileNotFoundError(f"Repository directory does not exist: {repo_dir}")

if not artifacts_dir.is_dir():
    raise FileNotFoundError(f"Artifacts directory does not exist: {artifacts_dir}")


# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------

repo_apk_dir = repo_dir / "apk"
repo_icon_dir = repo_dir / "icon"

repo_apk_dir.mkdir(parents=True, exist_ok=True)
repo_icon_dir.mkdir(parents=True, exist_ok=True)


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

    if match:
        return match.group(1)

    return None


def extract_icon(apk: Path, package_name: str, badging: str) -> None:
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


def get_language(apk_name: str, sources: list[dict]) -> str:
    match = LANGUAGE_REGEX.search(apk_name)

    if match:
        language = match.group(1)
    else:
        language = "all"

    if len(sources) == 1:
        source_language = sources[0].get("lang", language)

        if (
            source_language != language
            and source_language not in {"all", "other"}
            and language not in {"all", "other"}
        ):
            language = source_language

    return language


def get_nsfw(info: dict, badging: str) -> int:
    content_warning = info.get("contentWarning")

    if isinstance(content_warning, bool):
        return int(content_warning)

    if isinstance(content_warning, int):
        return content_warning

    if isinstance(content_warning, str):
        normalized = content_warning.lower()

        if normalized in {
            "true",
            "1",
            "yes",
        }:
            return 1

        if normalized in {
            "false",
            "0",
            "no",
            "",
        }:
            return 0

    match = IS_NSFW_REGEX.search(badging)

    if match:
        return int(match.group(1))

    return 0


def normalize_apk_name(apk: Path) -> str:
    return apk.name.replace("-release.apk", ".apk")


# ---------------------------------------------------------------------------
# Remove deleted modules
# ---------------------------------------------------------------------------

for module in to_delete:
    print(f"Removing deleted module: {module}")

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
# Collect source-info files and APKs
# ---------------------------------------------------------------------------

info_files = sorted(
    artifacts_dir.glob("**/keiyoushi-source-info.json")
)

if not info_files:
    raise FileNotFoundError(
        f"No keiyoushi-source-info.json files found in "
        f"{artifacts_dir}"
    )

print(f"Found {len(info_files)} source-info files")


# These entries represent the extensions rebuilt by this CI run.
new_entries: list[dict] = []

# Keep track of package names that were actually rebuilt.
rebuilt_packages: set[str] = set()


for info_file in info_files:
    with info_file.open(encoding="utf-8") as file:
        info = json.load(file)

    package_name = info["packageName"]
    module = info["module"]

    apk_dir = info_file.parent / "outputs" / "apk" / "release"

    apk_files = sorted(apk_dir.glob("*.apk"))

    if not apk_files:
        raise FileNotFoundError(
            f"{package_name}: no release APK found under "
            f"{apk_dir}"
        )

    # assembleRelease should produce one APK per extension.
    apk = apk_files[0]

    badging = get_apk_badging(apk)

    package_info = next(
        line
        for line in badging.splitlines()
        if line.startswith("package: ")
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

    version_code = int(
        info.get(
            "versionCode",
            get_match(
                VERSION_CODE_REGEX,
                package_info,
                "version code",
                apk,
            ),
        )
    )

    version_name = info.get(
        "versionName",
        get_match(
            VERSION_NAME_REGEX,
            package_info,
            "version name",
            apk,
        ),
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

    # -----------------------------------------------------------------------
    # Copy APK to repo2/apk/
    # -----------------------------------------------------------------------

    final_apk_name = normalize_apk_name(apk)
    destination_apk = repo_apk_dir / final_apk_name

    shutil.copy2(apk, destination_apk)

    print(
        f"APK: {final_apk_name} "
        f"({package_name})"
    )

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
        source_entries.append(
            {
                "name": source["name"],
                "lang": source["lang"],
                "id": source["id"],
                "baseUrl": source["baseUrl"],
            }
        )

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
# Read existing index.json from repo2
# ---------------------------------------------------------------------------

index_path = repo_dir / "index.json"

if index_path.exists():
    with index_path.open(encoding="utf-8") as file:
        remote_index = json.load(file)

    if not isinstance(remote_index, list):
        raise ValueError(
            f"{index_path} does not contain a JSON array"
        )
else:
    remote_index = []


# ---------------------------------------------------------------------------
# Remove deleted and rebuilt extensions from existing index
# ---------------------------------------------------------------------------

def is_deleted_or_rebuilt(item: dict) -> bool:
    package_name = item.get("pkg", "")

    if package_name in rebuilt_packages:
        return True

    return any(
        package_name.endswith(f".{module}")
        for module in to_delete
    )


final_index = [
    item
    for item in remote_index
    if not is_deleted_or_rebuilt(item)
]

# Add freshly built extensions.
final_index.extend(new_entries)

# Sort exactly like the old merge-repo.py.
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

index_min_path = repo_dir / "index.min.json"

with index_min_path.open("w", encoding="utf-8") as index_min_file:
    json.dump(
        final_index,
        index_min_file,
        ensure_ascii=False,
        separators=(",", ":"),
    )


# ---------------------------------------------------------------------------
# Write index.html
# ---------------------------------------------------------------------------

index_html_path = repo_dir / "index.html"

with index_html_path.open(
    "w",
    encoding="utf-8",
) as index_html_file:
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
        name_escaped = html.escape(
            entry["name"]
        )

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
print(f"Commit: {current_sha}")
print("========================================")
