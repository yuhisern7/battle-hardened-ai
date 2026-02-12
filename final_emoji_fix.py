#!/usr/bin/env python3
"""Fix the remaining emoji corruptions in README.md."""

import shutil

readme_path = r'c:\Users\kidds\workspace\battle-hardened-ai\README.md'

# Create backup
shutil.copy(readme_path, readme_path + '.emoji_backup')

# Read file in binary mode
with open(readme_path, 'rb') as f:
    data = f.read()

# Fix the three remaining emoji corruptions found at lines 686, 687, 691
fixes = [
    # Home emoji: ðŸ�   → 🏠
    (b"\xc3\xb0\xc5\xb8\xc2\x8f\xc2\xa0 ", b"\xf0\x9f\x8f\xa0 "),
    # Office building emoji: ðŸ¢ → 🏢
    (b"\xc3\xb0\xc5\xb8\xc2\xa2 ", b"\xf0\x9f\x8f\xa2 "),
    # Factory emoji: ðŸ­ → 🏭
    (b"\xc3\xb0\xc5\xb8\xc2\xad ", b"\xf0\x9f\x8f\xad "),
]

for old, new in fixes:
    count = data.count(old)
    data = data.replace(old, new)
    print(f"Fixed {count} occurrence(s): {old[:10]}... → {new[:10]}...")

# Write fixed data
with open(readme_path, 'wb') as f:
    f.write(data)

print("\n✓ Fixed all emoji corruptions in README.md")
