package instance

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
)

func TestBoundSRPCorruptKeyPublicStartNeverWrites(t *testing.T) {
	for _, mode := range []string{"legacy", "truncated", "version", "checksum"} {
		t.Run(mode, func(t *testing.T) {
			pair := newSRPPair(t, false)
			mustSRPLoop(t, pair.client.inst, func() error {
				if _, err := pair.client.inst.loadSRPKey(); err != nil {
					return err
				}
				record, err := pair.store.Get(srpKeySlot, 0)
				if err != nil {
					return err
				}
				switch mode {
				case "legacy":
					record = make([]byte, 16)
				case "truncated":
					record = record[:20]
				case "version":
					record[4]++
				case "checksum":
					record[10] ^= 0x80
				}
				if err := pair.store.SimSettings.Set(srpKeySlot, record); err != nil {
					return err
				}
				binding, err := pair.client.inst.StartSRP(pair.config)
				if binding != nil || !errors.Is(err, goterrors.ErrParse) {
					return fmt.Errorf("corrupt existing identity accepted: %v", err)
				}
				after, _ := pair.store.Get(srpKeySlot, 0)
				if !bytes.Equal(record, after) || pair.store.keyWrites != 1 ||
					pair.client.inst.udpManager.IsPortInUse(pair.config.Local.Port) || len(pair.client.driver.captures) != 0 {
					return fmt.Errorf("failed public StartSRP overwrote identity/leaked port/transmitted")
				}
				return nil
			})
		})
	}
}
