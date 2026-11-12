
import itertools
import json
import os
import re
import subprocess
import sys
from pathlib import Path

EXTENSION_REGEX = re.compile(r"^src/(?P<lang>\w+)/(?P<extension>\w+)")
MULTISRC_LIB_REGEX = re.compile(r"^lib-multisrc/(?P<multisrc>\w+)")
LIB_REGEX = re.compile(r"^lib/(?P<lib>\w+)")
PKG_NAME_REGEX = re.compile(r"""pkgName\s*=\s*["']([^"']+)["']""")
CORE_FILES_REGEX = re.compile(
    r"^(common/|compiler/|core/|gradle/|build\.gradle\.kts|gradle\.properties|settings\.gradle\.kts)"
)
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def run_command(command: str) -> str:
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    if result.returncode != 0:
        print(result.stderr.strip())
        sys.exit(result.returncode)
    return result.stdout.strip()


def resolve_module_suffix(ref: str, lang: str, extension: str) -> str:
    build_file = Path("src", lang, extension, "build.gradle.kts")
    content = None

    if build_file.is_file():
        content = build_file.read_text("utf-8")
    elif ref:
        result = subprocess.run(
            f"git show {ref}:src/{lang}/{extension}/build.gradle.kts",
            capture_output=True,
            text=True,
            shell=True,
            check=False,
        )
        if result.returncode == 0:
            content = result.stdout

    if content:
        match = PKG_NAME_REGEX.search(content)
        if match:
            return match.group(1)

    return f"{lang}.{extension}"


def resolve_dependent_libs(libs: set[str]) -> set[str]:
    if not libs:
        return set()

    all_dependent_libs = set()
    to_process = set(libs)

    while to_process:
        current_libs = to_process
        to_process = set()

        lib_dependency = re.compile(
            rf"project\([\"']:(?:lib):({'|'.join(map(re.escape, current_libs))})[\"']\)"
        )

        for lib in Path("lib").iterdir():
            if lib.name in all_dependent_libs or lib.name in libs:
                continue

            build_file = lib / "build.gradle.kts"
            if not build_file.is_file():
                continue

            content = build_file.read_text("utf-8")

            if lib_dependency.search(content):
                all_dependent_libs.add(lib.name)
                to_process.add(lib.name)

    return all_dependent_libs


def resolve_multisrc_lib(libs: set[str]) -> set[str]:
    if not libs:
        return set()

    lib_dependency = re.compile(
        rf"project\([\"']:(?:lib):({'|'.join(map(re.escape, libs))})[\"']\)"
    )

    multisrcs = set()

    for multisrc in Path("lib-multisrc").iterdir():
        build_file = multisrc / "build.gradle.kts"
        if not build_file.is_file():
            continue

        content = build_file.read_text("utf-8")

        if lib_dependency.search(content):
            multisrcs.add(multisrc.name)

    return multisrcs


def resolve_ext(multisrcs: set[str], libs: set[str]) -> set[tuple[str, str]]:
    if not multisrcs and not libs:
        return set()

    patterns = []

    if multisrcs:
        multisrc_pattern = "|".join(map(re.escape, multisrcs))
        patterns.append(rf"theme\s*=\s*['\"]({multisrc_pattern})['\"]")

    if libs:
        lib_pattern = "|".join(map(re.escape, libs))
        patterns.append(
            rf"project\([\"']:(?:lib):({lib_pattern})['\"]\)"
        )

    regex = re.compile("|".join(patterns))
    extensions = set()

    for lang in Path("src").iterdir():
        for extension in lang.iterdir():
            build_file = extension / "build.gradle.kts"
            if not build_file.is_file():
                continue

            content = build_file.read_text("utf-8")

            if regex.search(content):
                extensions.add((lang.name, extension.name))

    return extensions


def get_all_modules(ref: str) -> tuple[list[str], list[str]]:
    modules = []
    deleted = []

    for lang in Path("src").iterdir():
        for extension in lang.iterdir():
            if not (extension / "build.gradle.kts").is_file():
                continue

            modules.append(f":src:{lang.name}:{extension.name}")
            deleted.append(
                resolve_module_suffix(ref, lang.name, extension.name)
            )

    return modules, deleted


def get_all_lint_modules() -> list[str]:
    modules = [":core"]

    modules.extend(
        f":{directory}:{module.name}"
        for directory in ("lib", "lib-multisrc")
        for module in Path(directory).iterdir()
        if (module / "build.gradle.kts").is_file()
    )

    return sorted(modules)


def get_module_list(
    ref: str,
    force_full_rebuild: bool = False,
) -> tuple[list[str], list[str], list[str], bool]:

    if force_full_rebuild:
        modules, deleted = get_all_modules(ref)

        return (
            sorted(modules),
            sorted(deleted),
            get_all_lint_modules(),
            True,
        )

    diff_output = run_command(
        f"git diff --name-status {ref}"
    ).splitlines()

    changed_files = [
        file
        for line in diff_output
        for file in line.split("\t", 2)[1:]
    ]

    modules = set()
    multisrcs = set()
    libs = set()
    deleted = set()
    core_files_changed = False

    for file in map(lambda x: Path(x).as_posix(), changed_files):
        if CORE_FILES_REGEX.search(file):
            core_files_changed = True

        elif match := EXTENSION_REGEX.search(file):
            lang = match.group("lang")
            extension = match.group("extension")

            if Path("src", lang, extension).is_dir():
                modules.add(f":src:{lang}:{extension}")

            deleted.add(
                resolve_module_suffix(ref, lang, extension)
            )

        elif match := MULTISRC_LIB_REGEX.search(file):
            multisrc = match.group("multisrc")

            if Path("lib-multisrc", multisrc).is_dir():
                multisrcs.add(multisrc)

        elif match := LIB_REGEX.search(file):
            lib = match.group("lib")

            if Path("lib", lib).is_dir():
                libs.add(lib)

    if core_files_changed:
        all_modules, all_deleted = get_all_modules(ref)

        modules.update(all_modules)
        deleted.update(all_deleted)

        return (
            sorted(modules),
            sorted(deleted),
            get_all_lint_modules(),
            True,
        )

    libs.update(resolve_dependent_libs(libs))
    multisrcs.update(resolve_multisrc_lib(libs))

    extensions = resolve_ext(multisrcs, libs)

    modules.update(
        f":src:{lang}:{extension}"
        for lang, extension in extensions
    )

    deleted.update(
        resolve_module_suffix(ref, lang, extension)
        for lang, extension in extensions
    )

    lint_modules = {
        *(f":lib:{lib}" for lib in libs),
        *(f":lib-multisrc:{multisrc}" for multisrc in multisrcs),
    }

    return (
        sorted(modules),
        sorted(deleted),
        sorted(lint_modules),
        False,
    )


def create_matrix(modules: list[str]) -> dict:
    return {
        "chunk": [
            {"number": i + 1, "modules": chunk}
            for i, chunk in enumerate(
                itertools.batched(
                    modules,
                    int(os.getenv("CI_CHUNK_SIZE", 65)),
                )
            )
        ]
    }


def main() -> None:
    if len(sys.argv) not in (2, 3):
        print(
            "Usage: generate-build-matrices.py <base-ref> [force-full-rebuild]",
            file=sys.stderr,
        )
        sys.exit(1)

    ref = sys.argv[1]
    force_full_rebuild = (
        len(sys.argv) == 3
        and sys.argv[2].lower() == "true"
    )

    modules, deleted, lint_modules, is_full_rebuild = get_module_list(
        ref,
        force_full_rebuild,
    )

    matrix = create_matrix(modules)

    print(
        f"Module chunks to build:\n{json.dumps(matrix, indent=2)}\n\n"
        f"Modules to lint:\n{json.dumps(lint_modules, indent=2)}\n\n"
        f"Modules to delete:\n{json.dumps(deleted, indent=2)}\n\n"
        f"Full rebuild: {is_full_rebuild}"
    )

    if os.getenv("CI") == "true":
        with open(os.getenv("GITHUB_OUTPUT"), "a") as out_file:
            out_file.write(f"matrix={json.dumps(matrix)}\n")
            out_file.write(f"lint_modules={json.dumps(lint_modules)}\n")
            out_file.write(f"delete={json.dumps(deleted)}\n")
            out_file.write(
                f"full_rebuild={'true' if is_full_rebuild else 'false'}\n"
            )


if __name__ == "__main__":
    main()
