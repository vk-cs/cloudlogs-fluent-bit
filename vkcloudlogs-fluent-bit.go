package main

import (
	"C"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/vk-cs/cloudlogs-fluent-bit/gen"
	"github.com/vk-cs/cloudlogs-fluent-bit/vkcloudlogs"

	fluent "github.com/fluent/fluent-bit-go/output"
)

var (
	BuildGitVersion string
	BuildTime       string
	buildVersion    = fmt.Sprintf("VK Cloudlog Fluent Bit Plugin %s compiled at %s on %s",
		BuildGitVersion,
		BuildTime,
		runtime.Version())
)

//export FLBPluginRegister
func FLBPluginRegister(def unsafe.Pointer) int {
	return fluent.FLBPluginRegister(def, "vkcloudlogs", buildVersion)
}

//export FLBPluginInit
func FLBPluginInit(plugin unsafe.Pointer) int {
	getCompatKey := func(keys ...string) (result string) {
		for _, key := range keys {
			result = fluent.FLBPluginConfigKey(plugin, key)
			if result != "" {
				break
			}
		}
		return
	}

	cfg := vkcloudlogs.VKCloudLogsConfig{
		// Auth
		IdentityEndpoint: getCompatKey("auth_url", "auth-url"),
		KeyFile:          fluent.FLBPluginConfigKey(plugin, "key_file"),
		UserID:           getCompatKey("user_id", "user-id"),
		Username:         getCompatKey("user_name", "user-name"),
		Password:         fluent.FLBPluginConfigKey(plugin, "password"),
		ProjectID:        getCompatKey("project_id", "project-id"),
		// Server
		ServerHostPort: getCompatKey("server_host_port", "serverhostport"),
		Tls:            fluent.FLBPluginConfigKey(plugin, "tls_on"),
		TlsVerify:      fluent.FLBPluginConfigKey(plugin, "tls_verify"),
		// Tagging
		ServiceID:      fluent.FLBPluginConfigKey(plugin, "service_id"),
		GroupID:        getCompatKey("groupid", "group_id"),
		StreamID:       getCompatKey("streamid", "stream_id"),
		DefaultPayload: fluent.FLBPluginConfigKey(plugin, "default_payload"),
		InternalRaw:    fluent.FLBPluginConfigKey(plugin, "internal"),
		// Parsing
		MessageKey:   fluent.FLBPluginConfigKey(plugin, "message_key"),
		LevelKey:     fluent.FLBPluginConfigKey(plugin, "level_key"),
		DefaultLevel: fluent.FLBPluginConfigKey(plugin, "default_level"),
		GroupIDKey:   fluent.FLBPluginConfigKey(plugin, "group_id_key"),
		StreamIDKey:  fluent.FLBPluginConfigKey(plugin, "stream_id_key"),
	}

	instance, err := vkcloudlogs.NewVKCloudLogs(&cfg, buildVersion)
	if err != nil {
		return fluent.FLB_ERROR
	}
	err = instance.Init()
	if err != nil {
		return fluent.FLB_ERROR
	}

	fluent.FLBPluginSetContext(plugin, instance)
	return fluent.FLB_OK
}

//export FLBPluginFlushCtx
func FLBPluginFlushCtx(ctx, data unsafe.Pointer, length C.int, tag *C.char) int {
	// get plugin instance
	instance := fluent.FLBPluginGetContext(ctx).(*vkcloudlogs.VKCloudLogs)
	return flush(instance, data, int(length), C.GoString(tag))
}

func flush(instance *vkcloudlogs.VKCloudLogs, data unsafe.Pointer, length int, fluentTag string) int {
	var tagEntries = make(map[vkcloudlogs.Tag][]*gen.LogEntry)

	const (
		decoderOk   = 0
		decoderDone = -1
	)
	decoder := fluent.NewDecoder(data, int(length))

	for {
		// Extract data from MessagePack
		decoderCode, recordTimestamp, record := fluent.GetRecord(decoder)
		if decoderCode != decoderOk {
			if decoderCode != decoderDone {
				instance.Logger.Warn("Cannot decode record")
			}
			break
		}
		entry, tag := instance.Parse(recordTimestamp, record)
		if tag.GroupID == "" {
			tag.GroupID = fluentTag
		}
		tagEntries[tag] = append(tagEntries[tag], entry)
	}

	for tag, entries := range tagEntries {
		result := instance.Write(tag, entries)
		if result != fluent.FLB_OK {
			return result
		}
	}

	return fluent.FLB_OK
}

//export FLBPluginExit
func FLBPluginExit() int {
	return fluent.FLB_OK
}

func main() {
}
