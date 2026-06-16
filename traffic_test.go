package forwardproxy

import (
	"encoding/json"
	"os"
	"testing"
)

func resetTraffic() {
	globalTraffic.mu.Lock()
	if globalTraffic.cancel != nil {
		globalTraffic.cancel()
	}
	globalTraffic.data = make(map[string]*userStats)
	globalTraffic.file = ""
	globalTraffic.cancel = nil
	globalTraffic.mu.Unlock()
}

func TestAddTraffic(t *testing.T) {
	resetTraffic()

	addTraffic("alice", 100, 50)
	addTraffic("alice", 200, 100)
	addTraffic("bob", 50, 25)

	snap := GetSnapshot()

	if len(snap.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(snap.Users))
	}

	alice, ok := snap.Users["alice"]
	if !ok {
		t.Fatal("alice not found")
	}
	if alice.RxBytes != 300 {
		t.Errorf("alice rx: want 300, got %d", alice.RxBytes)
	}
	if alice.TxBytes != 150 {
		t.Errorf("alice tx: want 150, got %d", alice.TxBytes)
	}

	bob, ok := snap.Users["bob"]
	if !ok {
		t.Fatal("bob not found")
	}
	if bob.RxBytes != 50 {
		t.Errorf("bob rx: want 50, got %d", bob.RxBytes)
	}
	if bob.TxBytes != 25 {
		t.Errorf("bob tx: want 25, got %d", bob.TxBytes)
	}
}

func TestConnCount(t *testing.T) {
	resetTraffic()

	incConn("alice")
	incConn("alice")
	incConn("bob")
	decConn("alice")

	snap := GetSnapshot()

	if snap.Users["alice"].ConnCount != 1 {
		t.Errorf("alice conns: want 1, got %d", snap.Users["alice"].ConnCount)
	}
	if snap.Users["bob"].ConnCount != 1 {
		t.Errorf("bob conns: want 1, got %d", snap.Users["bob"].ConnCount)
	}
}

func TestDecConnBelowZero(t *testing.T) {
	resetTraffic()

	decConn("nobody")

	snap := GetSnapshot()
	if _, ok := snap.Users["nobody"]; ok {
		t.Error("nobody should not appear in stats")
	}
}

func TestEmptyUserIgnored(t *testing.T) {
	resetTraffic()

	addTraffic("", 100, 100)
	incConn("")

	snap := GetSnapshot()
	if len(snap.Users) != 0 {
		t.Error("empty username should be ignored")
	}
}

func TestConcurrentAddTraffic(t *testing.T) {
	resetTraffic()

	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			addTraffic("concurrent", 1, 1)
			done <- true
		}()
	}
	for i := 0; i < 100; i++ {
		<-done
	}

	snap := GetSnapshot()
	u := snap.Users["concurrent"]
	total := u.RxBytes + u.TxBytes
	if total != 200 {
		t.Errorf("concurrent total (rx+tx): want 200, got %d", total)
	}
}

func TestSnapshotImmutability(t *testing.T) {
	resetTraffic()

	addTraffic("alice", 100, 50)

	snap1 := GetSnapshot()
	snap1.Users["alice"] = userStatsJSON{RxBytes: 999, TxBytes: 999}

	snap2 := GetSnapshot()
	if snap2.Users["alice"].RxBytes != 100 {
		t.Error("snapshot mutation should not affect internal state")
	}
}

func TestSnapshotJSON(t *testing.T) {
	resetTraffic()

	addTraffic("user1", 1024, 512)
	incConn("user1")
	incConn("user1")

	snap := GetSnapshot()
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var parsed TrafficSnapshot
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	u := parsed.Users["user1"]
	if u.RxBytes != 1024 || u.TxBytes != 512 || u.ConnCount != 2 {
		t.Errorf("round-trip mismatch: rx=%d tx=%d conns=%d", u.RxBytes, u.TxBytes, u.ConnCount)
	}

	if snap.UpdatedAt == 0 {
		t.Error("updated_at should not be zero")
	}
}

func TestFlushToFile(t *testing.T) {
	resetTraffic()

	tmpFile := "/tmp/test_naive_traffic_flush.json"
	os.Remove(tmpFile)
	os.Remove(tmpFile + ".tmp")

	globalTraffic.mu.Lock()
	globalTraffic.file = tmpFile
	globalTraffic.mu.Unlock()

	addTraffic("flushtest", 777, 333)

	snap := GetSnapshot()
	data, _ := json.Marshal(snap)
	os.WriteFile(tmpFile+".tmp", data, 0600)
	os.Rename(tmpFile+".tmp", tmpFile)

	readData, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read flush file: %v", err)
	}

	var parsed TrafficSnapshot
	json.Unmarshal(readData, &parsed)

	if parsed.Users["flushtest"].RxBytes != 777 {
		t.Errorf("flush rx: want 777, got %d", parsed.Users["flushtest"].RxBytes)
	}

	os.Remove(tmpFile)
	os.Remove(tmpFile + ".tmp")
}

func TestPruneStaleUsers(t *testing.T) {
	resetTraffic()

	addTraffic("active", 100, 50)
	globalTraffic.mu.Lock()
	globalTraffic.data["stale"] = &userStats{}
	globalTraffic.mu.Unlock()

	globalTraffic.mu.Lock()
	globalTraffic.pruneStaleLocked()
	globalTraffic.mu.Unlock()

	snap := GetSnapshot()
	if _, ok := snap.Users["stale"]; ok {
		t.Error("stale user should be pruned")
	}
	if _, ok := snap.Users["active"]; !ok {
		t.Error("active user should not be pruned")
	}
}

func TestRestoreFromFile(t *testing.T) {
	resetTraffic()

	tmpFile := "/tmp/test_naive_traffic_restore.json"
	os.Remove(tmpFile)
	os.Remove(tmpFile + ".tmp")

	initial := TrafficSnapshot{
		Users: map[string]userStatsJSON{
			"saved": {RxBytes: 999, TxBytes: 888},
		},
		UpdatedAt: 12345,
	}
	data, _ := json.Marshal(initial)
	os.WriteFile(tmpFile, data, 0600)

	globalTraffic.mu.Lock()
	globalTraffic.file = tmpFile
	globalTraffic.data = make(map[string]*userStats)
	globalTraffic.restoreFromFile()
	globalTraffic.mu.Unlock()

	snap := GetSnapshot()
	u, ok := snap.Users["saved"]
	if !ok {
		t.Fatal("saved user not restored")
	}
	if u.RxBytes != 999 || u.TxBytes != 888 {
		t.Errorf("restored values mismatch: rx=%d tx=%d", u.RxBytes, u.TxBytes)
	}

	os.Remove(tmpFile)
	os.Remove(tmpFile + ".tmp")
}
