#!/usr/bin/env python3
"""Check if arrows are fixed in README."""

with open(r'c:\Users\kidds\workspace\battle-hardened-ai\README.md', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Write to file to avoid encoding issues
with open('arrow_check.txt', 'w', encoding='utf-8') as out:
    out.write("=== Checking specific lines ===\n\n")
    out.write(f"Line 105: {lines[104]}\n")
    out.write(f"Line 121: {lines[120]}\n")
    out.write(f"Line 137: {lines[136]}\n\n")
    
    out.write("=== Checking for corruption patterns ===\n")
    apostrophe_count = sum(1 for line in lines if "─→'" in line or "→'" in line)
    out.write(f"Lines with arrow+apostrophe (─→' or →'): {apostrophe_count}\n\n")
    
    emoji_corruption = sum(1 for line in lines if "ðŸ" in line)
    out.write(f"Lines with emoji corruption (ðŸ): {emoji_corruption}\n\n")
    
    cross_corruption = sum(1 for line in lines if "'Œ" in line or "'�Œ" in line)
    out.write(f"Lines with cross corruption ('Œ or '�Œ): {cross_corruption}\n\n")
    
    if apostrophe_count == 0 and emoji_corruption == 0 and cross_corruption == 0:
        out.write("✓ SUCCESS: README.md is CLEAN!\n")
    else:
        out.write("⚠ Some corruptions still present\n")

print("Results written to arrow_check.txt")
