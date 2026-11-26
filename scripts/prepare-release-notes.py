#!/usr/bin/env python3
"""Render a draft release page from reviewed notes and the actual built files."""
import argparse
import hashlib
import pathlib
import re


def prepare(root, version, commit, repository, notes):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?", version):
        raise ValueError("invalid release version")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("exact commit required")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid repository")
    root = pathlib.Path(root).resolve()
    notes = pathlib.Path(notes).resolve()
    notes.relative_to(root)
    body = notes.read_text(encoding="utf-8").strip()
    if not body:
        raise ValueError("reviewed release notes are empty")
    source = f"https://github.com/{repository}/blob/{commit}"
    download = f"https://github.com/{repository}/releases/download/v{version}"
    # Release bodies have no source-file directory: resolve their documentation
    # links against the reviewed notes, then pin them to this exact source.
    def link(match):
        target = match.group(2)
        if target.startswith(("#", "https://", "http://", "mailto:")):
            return match.group(0)
        path, separator, fragment = target.partition("#")
        resolved = (notes.parent / path).resolve()
        relative = resolved.relative_to(root).as_posix()
        if not resolved.is_file():
            raise ValueError(f"release documentation target missing: {relative}")
        return f"[{match.group(1)}]({source}/{relative}{separator}{fragment})"
    body = re.sub(r"\[([^]\n]+)\]\(([^)\s]+)\)", link, body)
    names = [f"RAZVILKA-{version}-entware.tar.gz", f"RAZVILKA-{version}-entware.zip"]
    names += [f"dist/razvilka-linux-{arch}" for arch in ("amd64", "arm64", "mips", "mipsle")]
    digests = []
    for name in names:
        path = root / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"actual release file missing/unsafe: {name}")
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        digests.append(f"{digest}  {path.name}")
    return f"""![RAZVILKA](https://raw.githubusercontent.com/{repository}/{commit}/docs/assets/razvilka-banner.png)

{body}

## Какой файл скачать

| Задача | Файл |
|---|---|
| Полный комплект для Entware, с установщиком и инструкцией | [RAZVILKA-{version}-entware.tar.gz]({download}/RAZVILKA-{version}-entware.tar.gz) |
| Тот же комплект в ZIP для просмотра на ПК | [RAZVILKA-{version}-entware.zip]({download}/RAZVILKA-{version}-entware.zip) |
| Отдельный бинарник для проверенного ручного сценария | `razvilka-linux-<архитектура>` — не заменяет установщик и журнал обновления; архитектура определяется по роутеру |

Файлы **Source code** создаёт GitHub: это исходники, без готового комплекта установки.
Наличие файла для архитектуры не означает испытания на физическом роутере.
[Порядок установки и совместимость]({source}/docs/INSTALL_RU.md) ·
[Матрица возможностей и проверки]({source}/docs/RUNTIME_SUPPORT_RU.md).

## Сборка и проверка файлов

Исходная ревизия: [`{commit}`](https://github.com/{repository}/commit/{commit}).
Версия Go закреплена в [`go.mod`]({source}/go.mod). Команды и параметры
сборки указаны в [процедуре выпуска]({source}/.github/workflows/release.yml).
Проверки CI, сетевого стенда и физического роутера учитываются отдельно;
эта страница сама по себе не подтверждает их прохождение.

<details>
<summary>SHA256 готовых файлов</summary>

```text
{chr(10).join(digests)}
```

</details>

На Windows: `Get-FileHash RAZVILKA-{version}-entware.zip -Algorithm SHA256`.
На Linux для обоих скачанных архивов:
`sha256sum -c RAZVILKA-{version}.SHA256SUMS`.
Для отдельных бинарников используйте приложенный `SHA256SUMS`.
Сверяйте с файлами именно этого выпуска. Побитовое совпадение самостоятельной
сборки с опубликованной отдельно не гарантируется.
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    for name in ("version", "commit", "repository", "notes", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    result = prepare(args.root, args.version, args.commit, args.repository, args.notes)
    pathlib.Path(args.output).write_text(result, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
