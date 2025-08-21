package main

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/corazawaf/coraza/v3"
	"github.com/cybercoder/waf/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

var wafCache sync.Map

var rdb = redis.NewClient(&redis.Options{
	Addr: "localhost:6379",
})

// const crsDirectives = `
// SecRuleEngine On
// Include /etc/coraza/crs-setup.conf.example
// Include /etc/coraza/rules/*.conf
// `

func removeWAF(profile string) error {
	if _, ok := wafCache.Load(profile); ok {
		wafCache.Delete(profile)
	}
	return nil
}

func getWAF(profile string) (coraza.WAF, error) {
	if x, ok := wafCache.Load(profile); ok {
		return x.(coraza.WAF), nil
	}

	// get all matching rule keys from Redis using SCAN
	pattern := "WAF_RULE:" + profile + ":*"
	var keys []string
	iter := rdb.Scan(context.Background(), 0, pattern, 0).Iterator()

	for iter.Next(context.Background()) {
		keys = append(keys, iter.Val())
	}

	if err := iter.Err(); err != nil {
		logger.Errorf("err on scanning rule keys: %s", err)
		return nil, err
	}

	// collect all rules from matching keys
	var allRules strings.Builder
	for _, key := range keys {
		rules, err := rdb.Get(context.Background(), key).Result()
		if err != nil {
			logger.Warnf("err on getting rules from %s: %s", key, err)
			continue
		}
		allRules.WriteString(rules)
		allRules.WriteString("\n")
	}

	// build WAF with all collected rules
	logger.Debugf("rules: %s", allRules.String())
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().WithDirectives(allRules.String()),
	)

	if err == nil {
		wafCache.Store(profile, waf)
	}
	return waf, err
}

func main() {
	router := gin.Default()

	router.GET("/health", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	router.GET("/remove/:profile", func(c *gin.Context) {
		profile := c.Param("profile")
		logger.Debug("Profile:", profile)
		if profile == "" {
			profile = "default"
		}
		err := removeWAF(profile)
		if err != nil {
			logger.Errorf("err on removing waf: %s", err)
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		c.String(http.StatusOK, "OK")
	})

	router.POST("/pre", func(c *gin.Context) {
		profile := c.GetHeader("X-WAF-Profile")
		logger.Debugf("Profile: %s", profile)
		if profile == "" {
			profile = "default"
		}
		waf, err := getWAF(profile)
		if err != nil {
			logger.Errorf("err on getting waf: %s", err)
			c.String(http.StatusInternalServerError, err.Error())
			return
		}

		tx := waf.NewTransaction()

		logger.Debugf("ip: %s host: %s", c.GetHeader("X-Client-IP"), c.Request.Host)
		tx.ProcessConnection(c.ClientIP(), 0, c.Request.Host, 443)
		for key, values := range c.Request.Header {
			if key == "X-WAF-Profile" {
				continue
			}
			for _, v := range values {
				tx.AddRequestHeader(key, v)
			}
		}

		if it := tx.ProcessRequestHeaders(); it != nil {
			logger.Debugf("Transaction was interrupted with status %d", it.Status)
			c.String(it.Status, it.Data)
		}
	})

	router.Run(":3000")
}
