import AppKit
import Foundation

let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
let iconDir = root.appendingPathComponent("src-tauri/icons", isDirectory: true)
let iconsetDir = iconDir.appendingPathComponent("Repoglance.iconset", isDirectory: true)
let background = NSColor(calibratedRed: 17 / 255, green: 17 / 255, blue: 17 / 255, alpha: 1)
let white = NSColor.white

func scaled(_ value: CGFloat, _ scale: CGFloat) -> CGFloat {
    value * scale
}

func render(size: Int, to url: URL) throws {
    let scale = CGFloat(size) / 1024
    guard let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: size,
        pixelsHigh: size,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: 0,
        bitsPerPixel: 0
    ) else {
        throw NSError(domain: "RepoglanceIcon", code: 1)
    }

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)

    background.setFill()
    NSRect(x: 0, y: 0, width: size, height: size).fill()

    let ring = NSBezierPath(ovalIn: NSRect(
        x: scaled(218, scale),
        y: scaled(218, scale),
        width: scaled(588, scale),
        height: scaled(588, scale)
    ))
    ring.lineWidth = scaled(32, scale)
    white.setStroke()
    ring.stroke()

    func strokeLine(from start: NSPoint, to end: NSPoint, width: CGFloat) {
        let path = NSBezierPath()
        path.lineCapStyle = .round
        path.lineWidth = scaled(width, scale)
        path.move(to: NSPoint(x: scaled(start.x, scale), y: scaled(start.y, scale)))
        path.line(to: NSPoint(x: scaled(end.x, scale), y: scaled(end.y, scale)))
        white.setStroke()
        path.stroke()
    }

    strokeLine(from: NSPoint(x: 364, y: 512), to: NSPoint(x: 660, y: 512), width: 46)
    strokeLine(from: NSPoint(x: 416, y: 430), to: NSPoint(x: 416, y: 594), width: 34)
    strokeLine(from: NSPoint(x: 608, y: 430), to: NSPoint(x: 608, y: 594), width: 34)

    func drawNode(center: NSPoint) {
        let rect = NSRect(
            x: scaled(center.x - 40, scale),
            y: scaled(center.y - 40, scale),
            width: scaled(80, scale),
            height: scaled(80, scale)
        )
        let node = NSBezierPath(ovalIn: rect)
        background.setFill()
        node.fill()
        node.lineWidth = scaled(28, scale)
        white.setStroke()
        node.stroke()
    }

    drawNode(center: NSPoint(x: 416, y: 430))
    drawNode(center: NSPoint(x: 608, y: 594))

    NSGraphicsContext.restoreGraphicsState()

    guard let data = rep.representation(using: .png, properties: [:]) else {
        throw NSError(domain: "RepoglanceIcon", code: 2)
    }
    try data.write(to: url)
}

func coverage(samples: Int, _ contains: (CGFloat, CGFloat) -> Bool) -> UInt8 {
    var hits = 0
    for y in 0..<samples {
        for x in 0..<samples {
            let sx = (CGFloat(x) + 0.5) / CGFloat(samples)
            let sy = (CGFloat(y) + 0.5) / CGFloat(samples)
            if contains(sx, sy) {
                hits += 1
            }
        }
    }
    return UInt8((CGFloat(hits) / CGFloat(samples * samples) * 255).rounded())
}

func distanceToSegment(px: CGFloat, py: CGFloat, ax: CGFloat, ay: CGFloat, bx: CGFloat, by: CGFloat) -> CGFloat {
    let abx = bx - ax
    let aby = by - ay
    let apx = px - ax
    let apy = py - ay
    let lengthSquared = abx * abx + aby * aby
    let t = max(0, min(1, (apx * abx + apy * aby) / lengthSquared))
    let cx = ax + abx * t
    let cy = ay + aby * t
    let dx = px - cx
    let dy = py - cy
    return sqrt(dx * dx + dy * dy)
}

func renderRawRgba(size: Int, to url: URL) throws {
    let samples = 4
    var data = Data(capacity: size * size * 4)

    for y in 0..<size {
        for x in 0..<size {
            let alpha = coverage(samples: samples) { sx, sy in
                let px = (CGFloat(x) + sx) / CGFloat(size) * 1024
                let py = (CGFloat(y) + sy) / CGFloat(size) * 1024
                let centerDistance = hypot(px - 512, py - 512)
                let onOuterRing = centerDistance >= 278 && centerDistance <= 310
                let onMainLine = distanceToSegment(px: px, py: py, ax: 364, ay: 512, bx: 660, by: 512) <= 23
                let onLeftLine = distanceToSegment(px: px, py: py, ax: 416, ay: 430, bx: 416, by: 594) <= 17
                let onRightLine = distanceToSegment(px: px, py: py, ax: 608, ay: 430, bx: 608, by: 594) <= 17
                let leftNodeDistance = hypot(px - 416, py - 430)
                let rightNodeDistance = hypot(px - 608, py - 594)
                let insideNodeFill = leftNodeDistance < 26 || rightNodeDistance < 26
                let onNodeStroke = (leftNodeDistance >= 26 && leftNodeDistance <= 54)
                    || (rightNodeDistance >= 26 && rightNodeDistance <= 54)

                if insideNodeFill {
                    return false
                }
                return onOuterRing || onMainLine || onLeftLine || onRightLine || onNodeStroke
            }

            let white = Int(alpha)
            let bg = 17
            let red = UInt8((white * 255 + (255 - white) * bg) / 255)
            let green = red
            let blue = red
            data.append(red)
            data.append(green)
            data.append(blue)
            data.append(255)
        }
    }

    try data.write(to: url)
}

try FileManager.default.createDirectory(at: iconDir, withIntermediateDirectories: true)
try? FileManager.default.removeItem(at: iconsetDir)
try FileManager.default.createDirectory(at: iconsetDir, withIntermediateDirectories: true)

try render(size: 1024, to: iconDir.appendingPathComponent("icon.png"))
try renderRawRgba(size: 128, to: iconDir.appendingPathComponent("icon_128.rgba"))

let sizes: [(String, Int)] = [
    ("icon_16x16.png", 16),
    ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32),
    ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128),
    ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256),
    ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512),
    ("icon_512x512@2x.png", 1024)
]

for (name, size) in sizes {
    try render(size: size, to: iconsetDir.appendingPathComponent(name))
}
