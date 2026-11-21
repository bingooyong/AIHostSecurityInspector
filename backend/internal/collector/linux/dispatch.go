package linux

import (
	"context"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func CollectModule(ctx context.Context, root string, live bool, now func() time.Time, req collector.Request) collector.Result {
	switch req.ModuleID {
	case ModuleHostIdentity:
		got, _ := (System{Root: root, Now: now, Live: live}).Collect(ctx, req)
		return got
	case ModuleProcessInventory:
		got, _ := (Process{Root: root, Now: now, Live: live}).Collect(ctx, req)
		return got
	case ModuleNetworkInventory:
		got, _ := (Network{Root: root, Now: now, Live: live}).Collect(ctx, req)
		return got
	case ModuleAccountInventory:
		got, _ := (Accounts{Root: root, Now: now, Live: live}).Collect(ctx, req)
		return got
	case ModuleServiceInventory, ModulePersistenceInventory:
		got, _ := (Persistence{Root: root, Now: now, Live: live}).Collect(ctx, req)
		return got
	case ModuleSecurityConfig:
		got, _ := (Security{Root: root, Now: now, Live: live}).Collect(ctx, req)
		return got
	case ModulePackageInventory:
		got, _ := (Packages{Root: root, Now: now, Live: live}).Collect(ctx, req)
		return got
	case ModuleTargetedFileScan:
		got, _ := (Files{Root: root, Now: now, Live: live}).Collect(ctx, req)
		return got
	default:
		return collector.Result{
			ModuleID: req.ModuleID, Version: collector.Version, Status: domain.CollectionNotAvailable,
			Completeness: domain.CompletenessUnavailable, Records: []map[string]any{}, RawRefs: []string{},
			Warnings: []string{"module_not_implemented"}, ErrorCode: "MODULE_NOT_AVAILABLE",
		}
	}
}
