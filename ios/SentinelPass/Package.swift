// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SentinelPass",
    platforms: [
        .iOS(.v17)
    ],
    products: [
        .library(
            name: "SentinelPass",
            targets: ["SentinelPass"]
        ),
    ],
    dependencies: [
        // Add any external dependencies here
    ],
    targets: [
        .target(
            name: "SentinelPass",
            dependencies: [],
            path: "SentinelPass",
            linkerSettings: [
                .unsafeFlags([
                    "-L", "$(PROJECT_DIR)/../../target/release",
                    "-lsentinelpass_mobile_bridge"
                ])
            ]
        ),
    ]
)
