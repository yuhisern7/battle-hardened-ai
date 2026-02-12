# -*- coding: utf-8 -*-
# COMPREHENSIVE fix for ALL README.md corruptions

with open('README.md', 'rb') as f:
    data = f.read()

# Create backup
with open('README.md.final_backup', 'wb') as f:
    f.write(data)

# ALL corruption patterns with exact byte sequences
fixes = [
    # Cross marks: 'Œ -> ❌
    (b"'\xc5\x92", b"\xe2\x9d\x8c"),
    (b" '\xc5\x92", b" \xe2\x9d\x8c"),
    
    # Down arrow emojis: '¬‡ï¸ -> ⬇️
    (b"'\xc2\xac\xe2\x80\xa1\xc3\xaf\xc2\xb8", b"\xe2\xac\x87\xef\xb8\x8f"),
    
    # House emoji: ðŸ  -> 🏠
    (b"\xc3\xb0\xc5\xb8\xc2\xa0", b"\xf0\x9f\x8f\xa0"),
    # Office building: ðŸ¢ -> 🏢
    (b"\xc3\xb0\xc5\xb8\xc2\xa2", b"\xf0\x9f\x8f\xa2"),
    # Factory: ðŸ­ -> 🏭
    (b"\xc3\xb0\xc5\xb8\xc2\xad", b"\xf0\x9f\x8f\xad"),
    # Computer: ðŸ� – -> 🖥
    (b"\xc3\xb0\xc5\xb8\xe2\x80\x93", b"\xf0\x9f\x96\xa5"),
    
    # Cloud: '˜ï¸ -> ☁️
    (b"'\xcb\x9c\xc3\xaf\xc2\xb8", b"\xe2\x98\x81\xef\xb8\x8f"),
    
    # Shield: 'š–ï¸ -> 🛡️
    (b"'\xc5\xa1\xe2\x80\x93\xc3\xaf\xc2\xb8", b"\xf0\x9f\x9b\xa1\xef\xb8\x8f"),
    
    # Greater than or equal: '‰¥ -> ≥
    (b"'\xe2\x80\xb0\xc2\xa5", b"\xe2\x89\xa5"),
    
    # Box drawing corruptions: └'"€ and └"€ -> └─
    (b"\xe2\x94\x94'\xe2\x80\x9d\xe2\x82\xac", b"\xe2\x94\x94\xe2\x94\x80"),
    (b"\xe2\x94\x94\xe2\x80\x9d\xe2\x82\xac", b"\xe2\x94\x94\xe2\x94\x80"),
    
    # Arrow corruptions CRITICAL:
    # ─→' should be ─→ (box drawing + arrow, remove apostrophe)
    (b"\xe2\x94\x80\xe2\x86\x92'", b"\xe2\x94\x80\xe2\x86\x92"),
    (b"\xe2\x94\x80\xe2\x86\x92\xe2\x80\x98", b"\xe2\x94\x80\xe2\x86\x92"),
    
    # →' should be → (arrow, remove apostrophe)  
    (b"\xe2\x86\x92'", b"\xe2\x86\x92"),
    (b"\xe2\x86\x92\xe2\x80\x98", b"\xe2\x86\x92"),
    
    # →" should be ↓ (down arrow)
    (b"\xe2\x86\x92\xe2\x80\x9d", b"\xe2\x86\x93"),
    
    # Quote corruptions: —œ -> ", — -> "
    (b"\xe2\x80\x94\xc5\x93", b"\xe2\x80\x9c"),
    (b"\xe2\x80\x94", b"\xe2\x80\x9d"),
    # Smart quote corruptions
    (b"\xe2\x80\x9d", b'"'),  # Right double quote to regular quote
    
    # Lightning: '„ -> ⚡
    (b"'\xe2\x80\x9e", b"\xe2\x9a\xa1"),
    
    # Star: '˜… -> ⭐
    (b"'\xcb\x9c\xe2\x80\xa6", b"\xe2\xad\x90"),
]

# Apply ALL fixes
for old_bytes, new_bytes in fixes:
    data = data.replace(old_bytes, new_bytes)

# Write result
with open('README.md', 'wb') as f:
    f.write(data)

print("Fixed README.md - all corruptions removed")
exit(0)
