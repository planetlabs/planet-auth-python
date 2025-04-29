"""Generate the code reference pages."""

# Recipe to break up API docs into multiple pages from
# https://mkdocstrings.github.io/recipes/#automatic-code-reference-pages

from pathlib import Path

import mkdocs_gen_files

api_nav = mkdocs_gen_files.Nav()

repo_root = Path(__file__).parent.parent.parent
src = repo_root / "src"

for path in sorted(src.rglob("*.py")):
    module_path = path.relative_to(src).with_suffix("")
    doc_path = path.relative_to(src).with_suffix(".md")
    full_doc_path = Path("gen_reference", doc_path)

    parts = tuple(module_path.parts)

    if parts[-1] == "__init__":
        parts = parts[:-1]
    elif parts[-1] == "__main__":
        continue

    api_nav[parts] = doc_path.as_posix()

    with mkdocs_gen_files.open(full_doc_path, "w") as fd:
        identifier = ".".join(parts)
        print("::: " + identifier, file=fd)
        # TODO: add the options I want.  See my old manual api*.md files.

    mkdocs_gen_files.set_edit_path(full_doc_path, path.relative_to(repo_root))


with mkdocs_gen_files.open("gen_reference/API_NAV.md", "w") as nav_file:
    nav_file.writelines(api_nav.build_literate_nav())
