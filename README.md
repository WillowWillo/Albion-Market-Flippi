# 🛒 Albion Market Flippi (Go Collector)

> High-performance network packet parser and market data collector for Albion Online, engineered in Go.

---

## ⚡ Overview

**Albion-Market-Flippi** is a specialized tool designed to intercept, parse, and process live network traffic from Albion Online (utilizing the Photon protocol framework). Built with Go for maximum concurrency and minimal latency, this service serves as the core backend engine for capturing real-time market orders, tracking price discrepancies, and feeding trade arbitrage pipelines.

---

## 🚀 Key Features

- **Real-time Packet Interception:** Captures UDP/Photon network streams flowing from the game client.
- **Protocol Decoding:** Parses custom Albion Online binary operations and event structures (market orders, item IDs, quantities, silver values, and city locations).
- **High Concurrency & Low Footprint:** Leverages Go routines and channels to handle heavy packet throughput without lagging the system.
- **Arbitrage Pipeline Ready:** Designed to stream processed order book data straight into downstream databases or analytics frontends (e.g., Python/Django dashboards).

---

## 🛠️ Tech Stack

- **Language:** [Go (Golang)](https://golang.org/)
- **Protocol:** Photon Networking / UDP Sniffing
- **Architecture:** Concurrent event-driven packet processor

---

## ⚙️ Getting Started

### Prerequisites

Ensure you have the following installed on your machine:
- Go (`version 1.18+` recommended)
- Network packet capture dependencies (depending on your OS interface, e.g., Npcap on Windows or libpcap on Linux).

### Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/WillowWillo/Albion-Market-Flippi.git](https://github.com/WillowWillo/Albion-Market-Flippi.git)
   cd Albion-Market-Flippi
Install dependencies:

Bash
go mod tidy
Run the collector:

Bash
go run main.go
📊 How It Works
Sniffing: Listens to the local network interface for UDP traffic targeting or originating from the Albion Online game client.

Parsing: Identifies Photon opcodes associated with market board interactions (GetMarketOrders, OpenMarket, etc.).

Extraction: Pulls structured payloads containing item metadata, sell/buy orders, prices, enchantment levels, and quality tiers.

Exporting / Storing: Formats the extracted data to be consumed by local analytical tools or pricing calculators.

🛡️ Disclaimer
This project is developed solely for educational, analytical, and personal optimization purposes. It is not affiliated with, endorsed by, or connected to Sandbox Interactive GmbH.
