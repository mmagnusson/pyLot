# Fingerprints

The fingerprints in this directory are derived from GRASSMARLIN 3.2 by the National Security Agency
(https://github.com/nsacyber/GRASSMARLIN, `GM3/data/fingerprint`). Like GRASSMARLIN, they are
licensed under the GNU Lesser General Public License, version 3 (LGPL-3.0): see `COPYING.LESSER`,
and `COPYING` for the GNU General Public License, version 3, that it builds on.

## Changes from GRASSMARLIN

In July 2025 the original XML fingerprints were converted to YAML: one file per fingerprint, with
underscores instead of spaces in file names, XML element and attribute names lowercased, and element
text stored under `_text`. Their content is otherwise unchanged. `tests/test_fingerprints.py` can
check that every YAML file loads to the same fingerprint as its GRASSMARLIN original.

## Adding fingerprints

pyLot loads every `.yaml`, `.yml` and `.xml` file here, and XML files can use GRASSMARLIN's own
format. Other files, such as this one and the license texts, are ignored.

The rest of pyLot is under the MIT License in the top-level `LICENSE` file.
