package backend

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/provider"
)

type cache struct {
	Config   *persistence.ConfigEntry
	Provider provider.Provider
	cancel   context.CancelFunc
}

func (c *cache) Close() {
	c.cancel()
}

func newCache(c *persistence.ConfigEntry, r *provider.Registry) (*cache, error) {
	ctx, cancel := context.WithCancel(context.Background())

	p, err := r.NewAt(ctx, c.ProviderName, c.ProviderVersion, c.ProviderOptions)
	if err != nil {
		cancel()
		return nil, err
	}

	return &cache{
		Config:   c,
		Provider: p,
		cancel:   cancel,
	}, nil
}

func (b *backend) getCache(ctx context.Context, storage logical.Storage, providerOptionsOverride ...map[string]string) (*cache, error) {
	b.mut.Lock()
	defer b.mut.Unlock()

	if b.cache == nil {
		cfg, err := b.data.Managers(storage).Config().ReadConfig(ctx)
		if err != nil || cfg == nil {
			return nil, err
		}

		// This override is needed for cases when
		// some provider options apply to auth0 URLs.
		//
		// For example, microsoft_azure_ad has tetant id
		// that is used inside of authorization url.
		// In cases when using one multitentant app it's
		// convenient to write clientId and clientSecret once
		// and override tenant id for different tenants.
		if len(providerOptionsOverride) > 0 {
			for k, v := range providerOptionsOverride[0] {
				cfg.ProviderOptions[k] = v
			}
		}

		// TODO: Remove logging
		for k, v := range cfg.ProviderOptions {
			b.GetLogger().Info(fmt.Sprintf("cfg.ProviderOptions %s=%s", k, v))
		}

		cache, err := newCache(cfg, b.providerRegistry)
		if err != nil {
			return nil, err
		}

		b.cache = cache
	}

	return b.cache, nil
}
