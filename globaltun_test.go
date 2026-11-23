package main

import (
	"github.com/egoist/mygo/ui"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/vpn"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The helper must be found from a development build directory, which is where
// "resources/<goos>-<goarch>/" holds it.
func TestMultitunPathFindsDevBuild(t *testing.T) {
	dir := t.TempDir()
	want := filepath.Join(dir, "resources", "zju-connect-multitun"+helperSuffix)
	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(want, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	wd, _ := os.Getwd()
	defer func() { _ = os.Chdir(wd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	got, _ := multitunPath()
	if st, err := os.Stat(got); err != nil || st.IsDir() {
		t.Fatalf("multitunPath() = %q，该文件不存在", got)
	}
}

// A missing helper must come back with the list of places that were tried.
func TestMultitunPathReportsTried(t *testing.T) {
	dir := t.TempDir()
	wd, _ := os.Getwd()
	defer func() { _ = os.Chdir(wd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	_, tried := multitunPath()
	if tried == "" {
		t.Fatal("找不到 helper 时应给出已尝试的路径")
	}
}

// 记住的开关位置要落在正确的接入点上：优先上次那个，不在线才用第一个在线的。
func TestPickResumePoint(t *testing.T) {
	views := []vpn.View{
		{ID: "a", State: vpn.StateOnline},
		{ID: "b", State: vpn.StateOffline},
	}
	if got := pickResumePoint("a", views); got != "a" {
		t.Errorf("首选在线项：got %q", got)
	}
	if got := pickResumePoint("b", views); got != "a" {
		t.Errorf("记住的不在线时用第一个在线项：got %q", got)
	}
	if got := pickResumePoint("", nil); got != "" {
		t.Errorf("没有在线项应返回空：got %q", got)
	}
}

// DNS 自检只能问域名：应用地址列表里还有 192.168.168.0/24 这类网段，
// 拿去解析必然失败，会让守卫误判成「DNS 挂了」。
func TestIsProbeName(t *testing.T) {
	good := []string{"gitlab.qctc.com.cn", "access.qctc.com.cn", "a.b"}
	bad := []string{"", "192.168.168.0/24", "10.18.11.3", "10.20.168.68:5237", "1-65535"}
	for _, n := range good {
		if !isProbeName(n) {
			t.Errorf("%q 应当可以用于探测", n)
		}
	}
	for _, n := range bad {
		if isProbeName(n) {
			t.Errorf("%q 不应当用于探测", n)
		}
	}
}

// 隧道保活：连续两次探测失败才算死，成功一次就清零。
func TestKeepAliveCounts(t *testing.T) {
	var k tunKeepAlive
	if k.result("p", false) {
		t.Fatal("第一次失败不该判定为死")
	}
	if !k.result("p", false) {
		t.Fatal("连续两次失败应当判定为死")
	}
	// 判定之后计数清零，再失败一次不能说死。
	if k.result("p", false) {
		t.Fatal("判定后计数应当清零")
	}
	k.result("p", false)
	if k.result("p", true) {
		t.Fatal("成功不该触发重建")
	}
	if k.result("p", false) {
		t.Fatal("成功之后计数应当清零")
	}
}

// 系统代理只在统一入口确实在监听时才允许存在：TUN 接管或端口死了都必须关掉，
// 否则整机断网。
func TestSystemProxyGuards(t *testing.T) {
	// 单元测试不能碰真实系统设置：CI 上会卡在管理员密码弹窗。
	orig := applySystemProxyFn
	applySystemProxyFn = func(string, bool) error { return nil }
	t.Cleanup(func() { applySystemProxyFn = orig })

	a := testApp(t)

	// TUN 开启时，开关不接受打开。
	a.tunOn = true
	a.sysProxyOn = false
	a.sysProxySwitch = true
	a.toggleSystemProxy()
	if a.sysProxySwitch {
		t.Error("TUN 开启时不应允许打开系统代理")
	}

	// 统一入口没在监听时，也不允许打开。
	a.tunOn = false
	a.sysProxySwitch = true
	a.toggleSystemProxy()
	if a.sysProxySwitch {
		t.Error("统一入口未监听时不应允许打开系统代理")
	}

	// 已经开着但监听没了：守卫要把它关掉。
	a.sysProxyOn = true
	a.guardSystemProxy()
	if a.sysProxyOn {
		t.Error("统一入口停止后应当自动关闭系统代理")
	}
}

// 退出清理必须清掉控制文件并把 tunOn 复位，否则下次启动以为 TUN 还在。
func TestTeardownTUNOnExit(t *testing.T) {
	a := testApp(t)
	a.tunOn = true
	a.tunPID = 0

	files := []string{"tun.stop", "tun.pid", "tun.reload", "tun.probe", "tun.probe.result"}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(a.dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	a.teardownTUNOnExit()

	if a.tunOn {
		t.Error("退出后 tunOn 应当复位")
	}
	for _, name := range files {
		if _, err := os.Stat(filepath.Join(a.dir, name)); err == nil {
			t.Errorf("退出后 %s 应当被删除", name)
		}
	}
}

// 接入点上配置的重定向规则必须一路带到 helper 的 tun-config：写 session 文件
// 让它成为可用点，再断言 tunConfigFor 把 210.76.17.0:3306 映射带过去了。
func TestTunConfigForCarriesMappings(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.address = "https://vpn.example.edu.cn"
	a.editor.username = "alice"
	a.editor.cred = "pw-for-test"
	a.editor.socksPort = "0"
	a.saveEditor()
	if a.editor.err != "" {
		t.Fatalf("save: %s", a.editor.err)
	}
	id := a.store.Config().Points[0].ID
	// 存下全局本地映射。
	if _, err := a.store.Update(func(c *model.Config) error {
		c.Settings.LocalMappings = map[string]string{"210.76.17.0:3306": "127.0.0.1:33060"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()

	a.mgr.Connect(id)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if v, _ := a.mgr.View(id); v.State == vpn.StateOnline {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// tunConfigFor 要求 session 与资源文件存在。
	atrustDir := filepath.Join(a.dir, "atrust")
	if err := os.MkdirAll(atrustDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sess := `{"cookies":[{"Name":"sid","Value":"SIDSID"}],"device_id":"DEV1"}`
	if err := os.WriteFile(filepath.Join(atrustDir, id+".json"), []byte(sess), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(atrustDir, id+".resource.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := a.tunConfigFor()
	if err != nil {
		t.Fatalf("tunConfigFor: %v", err)
	}
	if len(cfg.Points) != 1 {
		t.Fatalf("points = %d, want 1", len(cfg.Points))
	}
	got, ok := cfg.Mappings["210.76.17.0:3306"]
	if !ok || got != "127.0.0.1:33060" {
		t.Fatalf("mapping not carried: %v", cfg.Mappings)
	}
}

// 编辑器文本 <-> 重定向表 的解析与回写。
func TestParseAndFormatRedirects(t *testing.T) {
	m, err := parseRedirects("210.76.17.0:3306 -> 127.0.0.1:33060\n# 注释\n\n10.9.9.9=127.0.0.1:9000\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m["210.76.17.0:3306"] != "127.0.0.1:33060" || m["10.9.9.9"] != "127.0.0.1:9000" {
		t.Fatalf("parsed = %v", m)
	}
	text := formatRedirects(m)
	if !strings.Contains(text, "210.76.17.0:3306 -> 127.0.0.1:33060") {
		t.Fatalf("format = %q", text)
	}
	// 回写后再解析，等价。
	back, err := parseRedirects(text)
	if err != nil || len(back) != 2 || back["10.9.9.9"] != "127.0.0.1:9000" {
		t.Fatalf("round-trip: %v %v", back, err)
	}

	// 空文本 -> nil，不报错。
	if m, err := parseRedirects("  \n # x\n"); err != nil || m != nil {
		t.Fatalf("empty: %v %v", m, err)
	}

	// 错误输入。
	if _, err := parseRedirects("210.76.17.0:3306"); err == nil {
		t.Error("缺箭头应当报错")
	}
	if _, err := parseRedirects("not-an-ip -> 127.0.0.1:1"); err == nil {
		t.Error("目标不是 IP 应当报错")
	}
	if _, err := parseRedirects("210.76.17.0:3306 -> 127.0.0.1"); err == nil {
		t.Error("本地缺端口应当报错")
	}
}

// 端口映射弹窗：四输入框保存成映射表，落盘再读回，非法行被拒。
func TestSaveMapSettingsRows(t *testing.T) {
	a := testApp(t)
	a.openMapSettings()
	a.mapSettings.rows = []mapRow{
		{Enabled: true, TargetIP: "210.76.17.0", TargetPort: "3306", LocalIP: "127.0.0.1", LocalPort: "33060"},
	}
	a.saveMapSettings()
	if a.mapSettings.err != "" {
		t.Fatalf("save: %s", a.mapSettings.err)
	}
	if got := a.store.Config().Settings.LocalMappings["210.76.17.0:3306"]; got != "127.0.0.1:33060" {
		t.Fatalf("mappings = %v", a.store.Config().Settings.LocalMappings)
	}
	// 重新打开应回显成一条四输入框的行。
	a.openMapSettings()
	if len(a.mapSettings.rows) != 1 ||
		a.mapSettings.rows[0].TargetIP != "210.76.17.0" ||
		a.mapSettings.rows[0].TargetPort != "3306" ||
		a.mapSettings.rows[0].LocalIP != "127.0.0.1" ||
		a.mapSettings.rows[0].LocalPort != "33060" {
		t.Fatalf("rows = %+v", a.mapSettings.rows)
	}

	// 只填了部分字段应报错，不静默丢弃。
	a.openMapSettings()
	a.mapSettings.rows = []mapRow{{TargetIP: "10.0.0.1"}}
	a.saveMapSettings()
	if a.mapSettings.err == "" {
		t.Fatal("部分填写的行应当报错")
	}

	// 全空的行跳过，不产生映射。
	a.openMapSettings()
	a.mapSettings.rows = []mapRow{{}, {}}
	a.saveMapSettings()
	if a.mapSettings.err != "" {
		t.Fatalf("全空行应被跳过: %s", a.mapSettings.err)
	}
	if len(a.store.Config().Settings.LocalMappings) != 0 {
		t.Fatalf("不该有映射: %v", a.store.Config().Settings.LocalMappings)
	}
}

// 关掉的映射不生效，但值保留，重新打开后回到生效集合。
func TestMapSettingsToggleEnabled(t *testing.T) {
	a := testApp(t)
	a.openMapSettings()
	a.mapSettings.rows = []mapRow{
		{Enabled: true, TargetIP: "10.0.0.1", TargetPort: "5432", LocalIP: "127.0.0.1", LocalPort: "15432"},
		{Enabled: false, TargetIP: "10.0.0.2", TargetPort: "6379", LocalIP: "127.0.0.1", LocalPort: "16379"},
	}
	a.saveMapSettings()
	if a.mapSettings.err != "" {
		t.Fatalf("save: %s", a.mapSettings.err)
	}
	s := a.store.Config().Settings
	if len(s.LocalMappings) != 1 || s.LocalMappings["10.0.0.1:5432"] != "127.0.0.1:15432" {
		t.Fatalf("启用的映射 = %v", s.LocalMappings)
	}
	if len(s.DisabledMappings) != 1 || s.DisabledMappings["10.0.0.2:6379"] != "127.0.0.1:16379" {
		t.Fatalf("停用的映射 = %v", s.DisabledMappings)
	}

	// 重新打开：两条都回显，开关状态正确。
	a.openMapSettings()
	if len(a.mapSettings.rows) != 2 {
		t.Fatalf("应回显 2 条，got %d: %+v", len(a.mapSettings.rows), a.mapSettings.rows)
	}
	on := 0
	for _, r := range a.mapSettings.rows {
		if r.Enabled {
			on++
		}
	}
	if on != 1 {
		t.Fatalf("启用条数 = %d，想要 1（rows=%+v）", on, a.mapSettings.rows)
	}

	// 把停用的那条打开，保存后应进入生效集合。
	for i := range a.mapSettings.rows {
		a.mapSettings.rows[i].Enabled = true
	}
	a.saveMapSettings()
	s = a.store.Config().Settings
	if len(s.LocalMappings) != 2 || len(s.DisabledMappings) != 0 {
		t.Fatalf("全开之后 = %v / %v", s.LocalMappings, s.DisabledMappings)
	}
}

// 没有在线接入点、但配了端口映射时，tunConfigFor 不应报错，且带上映射。
func TestTunConfigForMappingOnlyNoPoints(t *testing.T) {
	a := testApp(t)
	// 没有任何接入点，只设一条全局映射。
	if _, err := a.store.Update(func(c *model.Config) error {
		c.Settings.LocalMappings = map[string]string{"127.0.0.1:8080": "127.0.0.1:8080"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()
	if !a.hasMappings() {
		t.Fatal("hasMappings 应为 true")
	}
	cfg, err := a.tunConfigFor()
	if err != nil {
		t.Fatalf("有映射且无接入点时应允许：%v", err)
	}
	if len(cfg.Points) != 0 {
		t.Fatalf("不该有接入点，got %d", len(cfg.Points))
	}
	if cfg.Mappings["127.0.0.1:8080"] != "127.0.0.1:8080" {
		t.Fatalf("映射未带上：%v", cfg.Mappings)
	}

	// 既无接入点又无映射：仍应报错。
	a2 := testApp(t)
	if _, err := a2.tunConfigFor(); err == nil {
		t.Fatal("无接入点无映射应报错")
	}
}

// TUN 映射的连接要出现在访问日志里，并标注映射到本机哪个地址。
func TestPublishAccessShowsMapping(t *testing.T) {
	a := testApp(t)
	a.publishAccess(accessRecord{
		Time: time.Now().Unix(), Point: "本地映射",
		Target: "210.76.17.0", Port: 3306, OK: true,
		Via: "127.0.0.1:33060",
	})
	found := false
	for _, e := range a.bus.Tail(50) {
		if e.Source != vpn.AccessOK {
			continue
		}
		if strings.Contains(e.Line, "210.76.17.0:3306") &&
			strings.Contains(e.Line, "127.0.0.1:33060") &&
			strings.Contains(e.Line, "本地映射") {
			found = true
			break
		}
	}
	if !found {
		var lines []string
		for _, e := range a.bus.Tail(50) {
			lines = append(lines, e.Line)
		}
		t.Fatalf("访问日志缺少映射记录；现有 = %v", lines)
	}
}

// 端口映射弹窗必须有「启用」列（每行的开关），否则用户看不到开关。
func TestMapSettingsDialogHasEnableColumn(t *testing.T) {
	a := testApp(t)
	a.openMapSettings()
	tt := ui.NewTester(a.mapSettingsView, 660, 540)
	texts := strings.Join(tt.Texts(), "|")
	for _, want := range []string{"端口映射", "启用", "目标 IP", "映射 IP", "添加一条映射"} {
		if !strings.Contains(texts, want) {
			t.Errorf("弹窗缺少 %q；texts = %s", want, texts)
		}
	}
	// 默认会有一条空行，且默认启用。
	if len(a.mapSettings.rows) != 1 || !a.mapSettings.rows[0].Enabled {
		t.Fatalf("默认行应启用：%+v", a.mapSettings.rows)
	}
}
