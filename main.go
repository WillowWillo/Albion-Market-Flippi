package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const JSON_FILE_PATH = "market_data.json"
const WEB_PORT = ":8080"
const ITEMS_URL = "https://raw.githubusercontent.com/broderickhyman/ao-bin-dumps/master/formatted/items.json"

type ItemTranslation struct {
	UniqueName     string            `json:"UniqueName"`
	LocalizedNames map[string]string `json:"LocalizedNames"`
}

type ItemSanitizer struct {
	mu      sync.RWMutex
	itemMap map[string]string
}

var sanitizer = &ItemSanitizer{
	itemMap: make(map[string]string),
}

func (s *ItemSanitizer) LoadTranslationsOnline(language string) {
	fmt.Println("🌐 Baixando dicionário de itens oficial do Albion Online...")

	client := http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(ITEMS_URL)
	if err != nil {
		fmt.Printf("⚠️ Erro ao carregar itens da web (%v). Usando IDs originais.\n", err)
		return
	}
	defer resp.Body.Close()

	var items []ItemTranslation
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		fmt.Printf("⚠️ Erro ao decodificar JSON de itens (%v).\n", err)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, item := range items {
		if item.UniqueName == "" {
			continue
		}

		nome, ok := item.LocalizedNames[language]
		if !ok || nome == "" {
			nome = item.LocalizedNames["EN-US"]
		}

		if nome != "" {
			s.itemMap[item.UniqueName] = nome
		}
	}

	fmt.Printf("✅ Dicionário de itens carregado com sucesso! (%d itens mapeados)\n", len(s.itemMap))
}

func (s *ItemSanitizer) SanitizarItemID(rawID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	parts := strings.Split(rawID, "@")
	baseID := parts[0]

	nomeReal, exists := s.itemMap[baseID]
	if !exists {
		nomeReal = baseID
	}

	if len(parts) > 1 && parts[1] != "0" && parts[1] != "" {
		return fmt.Sprintf("%s (.%s)", nomeReal, parts[1])
	}

	return nomeReal
}

type RawMarketOrder struct {
	ID              int64   `json:"Id"`
	ItemTypeID      string  `json:"ItemTypeId"`
	UnitPriceSilver float64 `json:"UnitPriceSilver"`
	Amount          int     `json:"Amount"`
	AuctionType     string  `json:"AuctionType"`
	BuyerName       string  `json:"BuyerName"`
	SellerName      string  `json:"SellerName"`
	LocationID      int     `json:"LocationId"`
	Enchantment     int     `json:"EnchantmentLevel"`
	Quality         int     `json:"QualityLevel"`
}

type OrderEntry struct {
	ID          int64   `json:"id"`
	ItemTypeID  string  `json:"item_id"`
	ItemName    string  `json:"item_name"`
	Price       float64 `json:"price"`
	Amount      int     `json:"amount"`
	OrderType   string  `json:"order_type"`
	BuyerSeller string  `json:"buyer_seller"`
	Location    string  `json:"location"`
	SampleID    int     `json:"sample_id"`
	SampleName  string  `json:"sample_name"`
	Timestamp   string  `json:"timestamp"`
	Quality     int     `json:"quality"`
	Enchantment int     `json:"enchantment"`
}

type MarketCache struct {
	sync.RWMutex
	Orders map[string]OrderEntry
}

var cache = MarketCache{
	Orders: make(map[string]OrderEntry),
}

var (
	sampleMutex     sync.RWMutex
	currentSampleID int  = 0
	isRecording     bool = false
)

var jsonRegex = regexp.MustCompile(`\{"Id":\d+,"UnitPriceSilver":.+?\}`)

func main() {
	clearJSON()

	go sanitizer.LoadTranslationsOnline("PT-BR")
	go startWebServer()

	device := `\Device\NPF_{A6FBE90B-FC41-4D7C-9E3A-39C2ADFC4923}`
	snaplen := int32(1600)
	promisc := false
	timeout := pcap.BlockForever

	handle, err := pcap.OpenLive(device, snaplen, promisc, timeout)
	if err != nil {
		log.Fatalf("Erro ao abrir dispositivo de rede: %v", err)
	}
	defer handle.Close()

	filter := "udp port 5055 or udp port 5056"
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("Erro ao definir filtro BPF: %v", err)
	}

	fmt.Println("=== MONITOR E COMPARADOR DE MERCADO DO ALBION INICIADO ===")
	fmt.Printf("Acesse a Interface Web em: http://localhost%s\n", WEB_PORT)
	fmt.Println("Use a interface Web para iniciar e parar as gravações de mercado.")
	fmt.Println("=============================================================")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

func processPacket(packet gopacket.Packet) {
	appLayer := packet.ApplicationLayer()
	if appLayer == nil || len(appLayer.Payload()) == 0 {
		return
	}

	payload := appLayer.Payload()
	matches := jsonRegex.FindAll(payload, -1)
	if len(matches) == 0 {
		return
	}

	sampleMutex.RLock()
	recording := isRecording
	activeSample := currentSampleID
	sampleMutex.RUnlock()

	if !recording {
		return
	}

	updatedItems := make(map[string]bool)

	for _, match := range matches {
		var raw RawMarketOrder
		if err := json.Unmarshal(match, &raw); err != nil {
			continue
		}

		location := resolveLocation(raw)
		
		// --- CORREÇÃO DA CLASSIFICAÇÃO DE ORDENS ---
		orderType := "SELL"
		if strings.ToLower(raw.AuctionType) == "request" {
			orderType = "BUY"
		}
		
		// Regra à prova de falhas para o Black Market e pacotes bugados do Albion:
		if raw.SellerName != "" {
			orderType = "SELL"
		} else if raw.BuyerName != "" {
			orderType = "BUY"
		}
		// -------------------------------------------

		realPrice := raw.UnitPriceSilver / 10000.0
		buyerSeller := getBuyerSellerName(raw)
		cleanName := sanitizer.SanitizarItemID(raw.ItemTypeID)

		entry := OrderEntry{
			ID:          raw.ID,
			ItemTypeID:  raw.ItemTypeID,
			ItemName:    cleanName,
			Price:       realPrice,
			Amount:      raw.Amount,
			OrderType:   orderType,
			BuyerSeller: buyerSeller,
			Location:    location,
			SampleID:    activeSample,
			SampleName:  fmt.Sprintf("Amostragem #%d", activeSample),
			Timestamp:   time.Now().Format("15:04:05"),
			Quality:     raw.Quality,
			Enchantment: raw.Enchantment,
		}

		key := fmt.Sprintf("%d_sample_%d", raw.ID, activeSample)

		cache.Lock()
		cache.Orders[key] = entry
		cache.Unlock()

		updatedItems[raw.ItemTypeID] = true
	}

	if len(updatedItems) > 0 {
		saveJSON()
	}
}

func resolveLocation(raw RawMarketOrder) string {
	if raw.BuyerName == "@BLACK_MARKET" || raw.SellerName == "@BLACK_MARKET" || raw.LocationID == 3003 {
		return "BlackMarket"
	}
	switch raw.LocationID {
	case 7: return "Martlock"
	case 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007: return "Lymhurst"
	case 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007: return "Bridgewatch"
	case 3000, 3001, 3002, 3004, 3005, 3006, 3007, 3008: return "Caerleon"
	case 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4007: return "FortSterling"
	case 5000, 5001, 5002, 5003, 5004, 5005, 5006, 5007: return "Thetford"
	case 50000, 5: return "Brecilien"
	}
	if raw.LocationID > 0 {
		return fmt.Sprintf("Zona_%d", raw.LocationID)
	}
	return "Indefinido"
}

func getBuyerSellerName(raw RawMarketOrder) string {
	if raw.BuyerName != "" { return raw.BuyerName }
	return raw.SellerName
}

func saveJSON() {
	cache.RLock()
	defer cache.RUnlock()
	data, err := json.MarshalIndent(cache.Orders, "", "  ")
	if err != nil { return }
	_ = os.WriteFile(JSON_FILE_PATH, data, 0644)
}

func clearJSON() {
	cache.Lock()
	cache.Orders = make(map[string]OrderEntry)
	cache.Unlock()
	
	_ = os.WriteFile(JSON_FILE_PATH, []byte("{}"), 0644)

	sampleMutex.Lock()
	currentSampleID = 0
	isRecording = false
	sampleMutex.Unlock()
}

func startWebServer() {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/market", handleAPIMarket)
	http.HandleFunc("/api/reset", handleAPIReset)
	http.HandleFunc("/api/record/start", handleAPIStartRecord)
	http.HandleFunc("/api/record/stop", handleAPIStopRecord)
	http.HandleFunc("/api/status", handleAPIStatus)

	if err := http.ListenAndServe(WEB_PORT, nil); err != nil {
		log.Printf("Erro no servidor Web: %v", err)
	}
}

func handleAPIMarket(w http.ResponseWriter, r *http.Request) {
	cache.RLock()
	defer cache.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(cache.Orders)
}

func handleAPIReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { return }
	clearJSON()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}

func handleAPIStartRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { return }

	sampleMutex.Lock()
	isRecording = true
	currentSampleID++
	sampleMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"recording_started"}`))
}

func handleAPIStopRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { return }
	
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "Amostragem Manual"
	}

	sampleMutex.Lock()
	isRecording = false
	activeID := currentSampleID
	sampleMutex.Unlock()

	cache.Lock()
	for k, v := range cache.Orders {
		if v.SampleID == activeID {
			v.SampleName = name
			cache.Orders[k] = v
		}
	}
	cache.Unlock()
	saveJSON()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"recording_stopped"}`))
}

func handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	sampleMutex.RLock()
	recording := isRecording
	sampleMutex.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{"is_recording": %t}`, recording)))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, htmlTemplate)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Albion Market - Comparador de Amostragens</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        body { background-color: #0f172a; color: #f8fafc; padding: 20px; }
        header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid #334155; padding-bottom: 15px; flex-wrap: wrap; gap: 15px; }
        h1 { color: #38bdf8; font-size: 1.5rem; }
        
        .comparator-box { background: #1e293b; border: 1px solid #0284c7; border-radius: 8px; padding: 15px; margin-bottom: 20px; display: flex; flex-wrap: wrap; gap: 15px; align-items: center; justify-content: space-between; }
        .comparator-group { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
        .label-group { display: flex; flex-direction: column; gap: 5px; font-size: 0.85rem; color: #94a3b8; }

        button, select, input { background: #0f172a; color: #fff; border: 1px solid #475569; padding: 8px 12px; border-radius: 6px; cursor: pointer; font-size: 0.9rem; font-weight: bold; }
        button:hover, select:hover { border-color: #38bdf8; }
        button.primary { background: #0284c7; border-color: #0369a1; }
        button.primary:hover { background: #0369a1; }
        button.danger { background: #991b1b; border-color: #7f1d1d; }
        button.danger:hover { background: #7f1d1d; }
		button.recording { background: #ef4444; border-color: #b91c1c; animation: pulse 1.5s infinite; }

		@keyframes pulse {
			0% { opacity: 1; }
			50% { opacity: 0.7; box-shadow: 0 0 10px #ef4444; }
			100% { opacity: 1; }
		}
        
        .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(480px, 1fr)); gap: 15px; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 15px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
        .card-header { font-weight: bold; color: #f1f5f9; font-size: 1.1rem; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid #334155; display: flex; justify-content: space-between; align-items: center; }
        .raw-id { font-size: 0.75rem; color: #64748b; font-weight: normal; margin-top: 2px; }

        .metrics-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 12px; background: #0f172a; padding: 10px; border-radius: 6px; }
        .metric-box { font-size: 0.85rem; }
        .metric-title { color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; margin-bottom: 2px; }
        .metric-value { font-weight: bold; font-size: 1rem; }

        .positive { color: #22c55e; }
        .negative { color: #ef4444; }
        .neutral { color: #fbbf24; }

        .badge { background: #334155; color: #94a3b8; padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; }
        .badge.base { background: #0369a1; color: #fff; }
        .badge.target { background: #0d9488; color: #fff; }

        table { width: 100%; border-collapse: collapse; margin-top: 5px; font-size: 0.85rem; }
        th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #334155; }
        th { color: #94a3b8; font-weight: 600; }
        .empty { text-align: center; color: #64748b; margin-top: 50px; font-size: 1.1rem; grid-column: 1 / -1; }
        
        .toggle-container { display: flex; align-items: center; gap: 8px; font-size: 0.85rem; cursor: pointer; }
    </style>
</head>
<body>

    <header>
        <h1>⚔️ Albion Market - Comparador & Lucratividade</h1>
        <div class="comparator-group">
            <button id="btnRecord" class="primary" onclick="toggleRecord()">🔴 Iniciar Gravação</button>
            <button class="danger" onclick="resetDatabase()">🗑️ Limpar Base</button>
        </div>
    </header>

    <div class="comparator-box">
        <div class="comparator-group">
            <div class="label-group">
                <span>🛒 Amostragem Base (Compra):</span>
                <select id="baseSample" onchange="render()"></select>
            </div>
            <span style="font-size: 1.2rem; font-weight: bold; margin-top: 15px;">➔</span>
            <div class="label-group">
                <span>🎯 Amostragem Destino (Venda):</span>
                <select id="targetSample" onchange="render()"></select>
            </div>
        </div>

        <div class="comparator-group">
            <input type="text" id="searchInput" placeholder="Filtrar item..." oninput="render()">
            <label class="toggle-container">
                <input type="checkbox" id="onlyProfitable" onchange="render()"> Apenas Lucrativos
            </label>
            
            <select id="sortBy" onchange="render()">
                <option value="profit">Maior Lucro Bruto (Prata)</option>
                <option value="roi">Maior ROI (%)</option>
            </select>

            <select id="autoRefresh" onchange="setupAutoRefresh()">
                <option value="0">Auto-Refresh: Off</option>
                <option value="2000" selected>Auto-Refresh: 2s</option>
                <option value="5000">Auto-Refresh: 5s</option>
            </select>
        </div>
    </div>

    <div id="content" class="grid"></div>

    <script>
        var rawData = {};
        var refreshInterval = null;
        var isRecording = false;

        function checkStatus() {
            fetch('/api/status')
                .then(res => res.json())
                .then(data => {
                    isRecording = data.is_recording;
                    updateRecordButton();
                });
        }

        function updateRecordButton() {
            var btn = document.getElementById('btnRecord');
            if (isRecording) {
                btn.innerText = "⏹️ Parar & Salvar";
                btn.className = "recording";
            } else {
                btn.innerText = "🔴 Iniciar Gravação";
                btn.className = "primary";
            }
        }

        function toggleRecord() {
            if (!isRecording) {
                fetch('/api/record/start', { method: 'POST' }).then(() => {
                    isRecording = true;
                    updateRecordButton();
                });
            } else {
                var name = prompt("Amostragem concluída! Dê um nome para este mercado:", "Mercado Novo");
                if (name === null) name = ""; 
                fetch('/api/record/stop?name=' + encodeURIComponent(name), { method: 'POST' }).then(() => {
                    isRecording = false;
                    updateRecordButton();
                    fetchData();
                });
            }
        }

        function fetchData() {
            fetch('/api/market')
                .then(function(res) { return res.json(); })
                .then(function(data) {
                    rawData = data;
                    updateSampleDropdowns();
                    render();
                });
        }

        function resetDatabase() {
            if (!confirm("Tem certeza que deseja apagar toda a base de dados capturada?")) return;
            fetch('/api/reset', { method: 'POST' }).then(() => {
                rawData = {};
                updateSampleDropdowns();
                render();
            });
        }

        function setupAutoRefresh() {
            if (refreshInterval) clearInterval(refreshInterval);
            var ms = parseInt(document.getElementById('autoRefresh').value);
            if (ms > 0) refreshInterval = setInterval(fetchData, ms);
        }

        function updateSampleDropdowns() {
            var baseSelect = document.getElementById('baseSample');
            var targetSelect = document.getElementById('targetSample');
            
            var currBase = baseSelect.value;
            var currTarget = targetSelect.value;

            var samplesMap = {};
            for (var key in rawData) {
                var o = rawData[key];
                if (o.sample_id) {
                    if (!samplesMap[o.sample_id]) {
                        samplesMap[o.sample_id] = { loc: o.location, name: o.sample_name || ("Amostragem #" + o.sample_id) };
                    }
                }
            }

            var sortedSamples = Object.keys(samplesMap).map(Number).sort(function(a, b) { return b - a; });

            if (sortedSamples.length === 0) {
                baseSelect.innerHTML = '<option value="">Sem amostragens</option>';
                targetSelect.innerHTML = '<option value="">Sem amostragens</option>';
                return;
            }

            var baseHtml = '';
            var targetHtml = '';

            sortedSamples.forEach(function(s) {
                var data = samplesMap[s];
                var display = data.name + ' (' + data.loc + ')';
                baseHtml += '<option value="' + s + '">' + display + '</option>';
                targetHtml += '<option value="' + s + '">' + display + '</option>';
            });

            baseSelect.innerHTML = baseHtml;
            targetSelect.innerHTML = targetHtml;

            if (currBase && sortedSamples.includes(parseInt(currBase))) baseSelect.value = currBase;
            else baseSelect.value = sortedSamples[1] || sortedSamples[0];

            if (currTarget && sortedSamples.includes(parseInt(currTarget))) targetSelect.value = currTarget;
            else targetSelect.value = sortedSamples[0];
        }

		function getQualityName(q) {
			switch(q) {
				case 1: return "Normal";
				case 2: return "Bom";
				case 3: return "Excecional";
				case 4: return "Excelente";
				case 5: return "Obra-Prima";
				default: return "Q" + q;
			}
		}
		
        function render() {
            var container = document.getElementById('content');
            var search = document.getElementById('searchInput').value.toLowerCase();
            var baseSampleId = document.getElementById('baseSample').value;
            var targetSampleId = document.getElementById('targetSample').value;
            var onlyProfitable = document.getElementById('onlyProfitable').checked;
            var sortBy = document.getElementById('sortBy').value;

            container.innerHTML = '';

            if (!baseSampleId || !targetSampleId) {
                container.innerHTML = '<div class="empty">Nenhuma amostragem disponível para comparação.</div>';
                return;
            }

			var itemsBase = {};
			var itemsTarget = {};

			for (var key in rawData) {
				var o = rawData[key];
				var uniqueKey = o.item_id + "@" + o.quality; 
				
				if (String(o.sample_id) === String(baseSampleId)) {
					if (!itemsBase[uniqueKey]) itemsBase[uniqueKey] = [];
					itemsBase[uniqueKey].push(o);
				}
				if (String(o.sample_id) === String(targetSampleId)) {
					if (!itemsTarget[uniqueKey]) itemsTarget[uniqueKey] = [];
					itemsTarget[uniqueKey].push(o);
				}
			}

			var allItemKeys = Object.keys(itemsBase);
			var results = [];

			allItemKeys.forEach(function(uniqueKey) {
				var baseOrders = itemsBase[uniqueKey] || [];
				var targetOrders = itemsTarget[uniqueKey] || [];

				var firstItem = baseOrders[0];
				var baseName = firstItem.item_name || firstItem.item_id;
				var qualityName = getQualityName(firstItem.quality);
				
				var itemName = baseName + " [" + qualityName + "]"; 

				if (search && !itemName.toLowerCase().includes(search) && !uniqueKey.toLowerCase().includes(search)) return;

                var baseSellOrders = baseOrders.filter(function(o) { return o.order_type === 'SELL'; });
                if (baseSellOrders.length === 0) return;
                
                var minBuyPrice = Math.min.apply(Math, baseSellOrders.map(function(o) { return o.price; }));
                var minBuyAmount = 0;
                baseSellOrders.forEach(function(o) { if (o.price === minBuyPrice) minBuyAmount += o.amount; });

                var targetBuyOrders = targetOrders.filter(function(o) { return o.order_type === 'BUY'; });
                var maxTargetBuyPrice = targetBuyOrders.length > 0 ? Math.max.apply(Math, targetBuyOrders.map(function(o) { return o.price; })) : 0;
                var maxTargetBuyAmount = 0;
                if (maxTargetBuyPrice > 0) {
                    targetBuyOrders.forEach(function(o) { if (o.price === maxTargetBuyPrice) maxTargetBuyAmount += o.amount; });
                }

                var instantProfit = maxTargetBuyPrice > 0 ? (maxTargetBuyPrice * 0.955) - minBuyPrice : 0;
                var instantROI = minBuyPrice > 0 && maxTargetBuyPrice > 0 ? (instantProfit / minBuyPrice) * 100 : 0;

                if (onlyProfitable && instantProfit <= 0) return;

                var targetSellOrders = targetOrders.filter(function(o) { return o.order_type === 'SELL'; });
                var similarSellAmount = 0;
                if (maxTargetBuyPrice > 0) {
                    targetSellOrders.forEach(function(o) {
                        if (o.price >= maxTargetBuyPrice - 10000 && o.price <= maxTargetBuyPrice + 10000) {
                            similarSellAmount += o.amount;
                        }
                    });
                }

                results.push({
                    itemId: firstItem.item_id, // CORREÇÃO PRINCIPAL: O ERRO FATAL ESTAVA AQUI
                    itemName: itemName,
                    minBuyPrice: minBuyPrice,
                    minBuyAmount: minBuyAmount,
                    maxTargetBuyPrice: maxTargetBuyPrice,
                    maxTargetBuyAmount: maxTargetBuyAmount,
                    instantProfit: instantProfit,
                    instantROI: instantROI,
                    similarSellAmount: similarSellAmount
                });
            });

            results.sort(function(a, b) {
                if (sortBy === 'profit') return b.instantProfit - a.instantProfit;
                if (sortBy === 'roi') return b.instantROI - a.instantROI;
                return 0;
            });

            results.forEach(function(item) {
                var card = document.createElement('div');
                card.className = 'card';

                var instantClass = item.instantProfit > 0 ? 'positive' : (item.instantProfit < 0 ? 'negative' : 'neutral');
                var compClass = item.similarSellAmount > 0 ? 'negative' : 'neutral'; 

                card.innerHTML = 
                    '<div class="card-header">' +
                        '<div>' +
                            '<div>' + item.itemName + '</div>' +
                            '<div class="raw-id">' + item.itemId + '</div>' +
                        '</div>' +
                        '<div>' +
                            '<span class="badge base">Base</span> ' +
                            '<span class="badge target">Destino</span>' +
                        '</div>' +
                    '</div>' +

                    '<div class="metrics-grid">' +
                        '<div class="metric-box">' +
                            '<div class="metric-title">Custo (Menor Venda Base)</div>' +
                            '<div class="metric-value neutral">' + Math.round(item.minBuyPrice).toLocaleString('pt-BR') + ' Silver</div>' +
                        '</div>' +
                        '<div class="metric-box">' +
                            '<div class="metric-title">Venda Direta (Maior Compra)</div>' +
                            '<div class="metric-value">' + (item.maxTargetBuyPrice > 0 ? Math.round(item.maxTargetBuyPrice).toLocaleString('pt-BR') + ' Silver' : '-') + '</div>' +
                        '</div>' +
                        '<div class="metric-box">' +
                            '<div class="metric-title">Lucro Real (Inst.)</div>' +
                            '<div class="metric-value ' + instantClass + '">' + Math.round(item.instantProfit).toLocaleString('pt-BR') + ' (' + item.instantROI.toFixed(1) + '%)</div>' +
                        '</div>' +
                        '<div class="metric-box">' +
                            '<div class="metric-title">Ordens Venda (+-10k)</div>' +
                            '<div class="metric-value ' + compClass + '">' + item.similarSellAmount + ' unidades no destino</div>' +
                        '</div>' +
                    '</div>' +

                    '<table>' +
                        '<thead>' +
                            '<tr>' +
                                '<th>Origem</th>' +
                                '<th>Tipo</th>' +
                                '<th>Preço</th>' +
                                '<th>Qtd.</th>' +
                            '</tr>' +
                        '</thead>' +
                        '<tbody>' +
                            '<tr>' +
                                '<td><span class="badge base">Base</span></td>' +
                                '<td class="type-SELL">SELL (Sua Compra)</td>' +
                                '<td class="price">' + Math.round(item.minBuyPrice).toLocaleString('pt-BR') + '</td>' +
                                '<td>' + item.minBuyAmount + '</td>' +
                            '</tr>' +
                            (item.maxTargetBuyPrice > 0 ? 
                            '<tr>' +
                                '<td><span class="badge target">Destino</span></td>' +
                                '<td class="type-BUY">BUY (Sua Venda)</td>' +
                                '<td class="price">' + Math.round(item.maxTargetBuyPrice).toLocaleString('pt-BR') + '</td>' +
                                '<td>' + item.maxTargetBuyAmount + '</td>' +
                            '</tr>' : '') +
                        '</tbody>' +
                    '</table>';

                container.appendChild(card);
            });

            if (results.length === 0) {
                container.innerHTML = '<div class="empty">Nenhum item com Buy Order lucrativa encontrado.</div>';
            }
        }

        checkStatus();
        fetchData();
        setupAutoRefresh();
    </script>
</body>
</html>`