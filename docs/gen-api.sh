#!/bin/bash
set -e

# Helper script to generate .md files for API documentation.
# We do this rather than using the "show_submodules" option
# because that seems to generate all the APIs in a giant
# page of endless scrolling, which is not what I want.

for package_init in `find ../src/planet_auth ../src/planet_auth_utils -name __init__.py`
do
  package_doc_dir=`dirname $package_init | sed -e 's?\.\./src/??'`
  package=`dirname $package_init | sed -e 's?\.\./src/??' -e 's?/?.?g'`
  mkdir -p api/${package_doc_dir}
  cat <<EOF > api/${package_doc_dir}/pkg-api.md
## ::: ${package}
    options:
      show_root_full_path: true
      inherited_members: true
      show_submodules: false
      show_if_no_docstring: false

EOF
done
