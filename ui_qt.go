//go:build qt

package main

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/widgets"
)

// startQtUI runs the Qt GUI. Build with: go run -tags qt . -qt
func startQtUI(ctx context.Context, stats map[string]*HostStat, statsMu *sync.Mutex, buf *EventBuffer) error {
	app := widgets.NewQApplication(len([]string{}), []string{})

	w := widgets.NewQMainWindow(nil, 0)
	w.SetWindowTitle("ICMP 监控")
	w.Resize2(900, 600)

	central := widgets.NewQWidget(nil, 0)
	layout := widgets.NewQVBoxLayout2(central)

	// Events table
	evtLabel := widgets.NewQLabel2("最近事件", nil, 0)
	layout.AddWidget(evtLabel, 0, 0)
	evtTable := widgets.NewQTableWidget(nil)
	evtTable.SetColumnCount(5)
	evtTable.SetHorizontalHeaderLabels([]string{"时间", "设备", "协议", "来源", "目标"})
	layout.AddWidget(evtTable, 0, 0)

	// Summary table
	sumLabel := widgets.NewQLabel2("来源主机汇总", nil, 0)
	layout.AddWidget(sumLabel, 0, 0)
	sumTable := widgets.NewQTableWidget(nil)
	sumTable.SetColumnCount(5)
	sumTable.SetHorizontalHeaderLabels([]string{"来源", "次数", "最近", "协议", "网卡"})
	layout.AddWidget(sumTable, 0, 0)

	w.SetCentralWidget(central)
	w.Show()

	// Periodic refresh
	ticker := core.NewQTimer(nil)
	ticker.ConnectTimeout(func() {
		// Update events
		events := buf.List(200)
		evtTable.SetRowCount(len(events))
		for i, e := range events {
			row := i
			evtTable.SetItem(row, 0, widgets.NewQTableWidgetItem2(e.Time.Format("2006-01-02 15:04:05"), 0))
			evtTable.SetItem(row, 1, widgets.NewQTableWidgetItem2(e.Device, 0))
			evtTable.SetItem(row, 2, widgets.NewQTableWidgetItem2(e.Protocol, 0))
			evtTable.SetItem(row, 3, widgets.NewQTableWidgetItem2(e.SrcIP, 0))
			evtTable.SetItem(row, 4, widgets.NewQTableWidgetItem2(e.DstIP, 0))
		}

		// Update summary
		statsMu.Lock()
		rows := len(stats)
		sumTable.SetRowCount(rows)
		idx := 0
		for src, st := range stats {
			sumTable.SetItem(idx, 0, widgets.NewQTableWidgetItem2(src, 0))
			sumTable.SetItem(idx, 1, widgets.NewQTableWidgetItem2(fmt.Sprintf("%d", st.Count), 0))
			sumTable.SetItem(idx, 2, widgets.NewQTableWidgetItem2(st.LastSeen.Format("2006-01-02 15:04:05"), 0))
			sumTable.SetItem(idx, 3, widgets.NewQTableWidgetItem2(strings.Join(st.Protocols, ", "), 0))
			sumTable.SetItem(idx, 4, widgets.NewQTableWidgetItem2(strings.Join(st.Ifaces, ", "), 0))
			idx++
		}
		statsMu.Unlock()
	})
	ticker.Start(1500)

	go func() { <-ctx.Done(); ticker.Stop(); app.Quit() }()

	app.Exec()
	return nil
}