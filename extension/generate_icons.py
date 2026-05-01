"""Generate PNG icons for the Chrome extension."""
import struct, zlib, os

def write_png(filename, size):
    """Create a simple shield-shaped PNG icon."""
    # Draw icon using raw pixel data
    img = [[(0, 7, 17, 255)] * size for _ in range(size)]  # dark bg

    cx, cy = size // 2, size // 2
    r = size * 0.42

    for y in range(size):
        for x in range(size):
            dx, dy = x - cx, y - cy
            # Hexagon shape
            in_hex = (abs(dx) <= r * 0.87 and
                      abs(dy) <= r and
                      abs(dx) * 0.577 + abs(dy) * 0.333 <= r * 0.667)
            if in_hex:
                # Border ring
                dist = max(abs(dx) / (r * 0.87), abs(dy) / r)
                if dist > 0.78:
                    img[y][x] = (0, 245, 212, 255)  # cyan border
                elif dist > 0.45:
                    img[y][x] = (11, 26, 43, 255)   # dark fill
                else:
                    # Inner dot
                    if dx*dx + dy*dy < (r * 0.22) ** 2:
                        img[y][x] = (0, 245, 212, 255)  # cyan center dot

    # Encode as PNG
    def pack_png(data, width, height):
        def crc(data):
            return zlib.crc32(data) & 0xffffffff

        def chunk(name, data):
            c = name + data
            return struct.pack(">I", len(data)) + c + struct.pack(">I", crc(c))

        raw = b""
        for row in data:
            raw += b"\x00"
            for r, g, b, a in row:
                raw += bytes([r, g, b, a])

        compressed = zlib.compress(raw, 9)
        png  = b"\x89PNG\r\n\x1a\n"
        png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
        png += chunk(b"IDAT", compressed)
        png += chunk(b"IEND", b"")
        return png

    with open(filename, "wb") as f:
        f.write(pack_png(img, size, size))
    print(f"Created {filename} ({size}x{size})")

icons_dir = os.path.join(os.path.dirname(__file__), "icons")
os.makedirs(icons_dir, exist_ok=True)

write_png(os.path.join(icons_dir, "icon16.png"),  16)
write_png(os.path.join(icons_dir, "icon48.png"),  48)
write_png(os.path.join(icons_dir, "icon128.png"), 128)
print("Done!")
