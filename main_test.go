//go:generate moq -stub -skip-ensure -pkg vkcloudlogs -out vkcloudlogs/vkcloudlogs_mock.go ./gen LogServiceClient

package main

import (
	"testing"
	"unsafe"

	"github.com/vk-cs/cloudlogs-fluent-bit/gen"
	"github.com/vk-cs/cloudlogs-fluent-bit/vkcloudlogs"

	fluent "github.com/fluent/fluent-bit-go/output"
	"github.com/stretchr/testify/assert"
)

func TestMainExists(t *testing.T) {
	main() // no action
}

func TestRegister(t *testing.T) {
	def := unsafe.Pointer(&fluent.FLBPluginProxyDef{})
	resultCode := FLBPluginRegister(def)
	assert.Equal(t, 0, resultCode)
}

//func TestInit(t *testing.T) {
//	data := output.FLBOutPlugin{}
//	plugin := unsafe.Pointer(&data)
//	resultCode := FLBPluginInit(plugin)
//	assert.Equal(t, output.FLB_OK, resultCode)
//}

//func TestFlushCtx(t *testing.T) {
//	resultCode := main.FLBPluginFlushCtx(ctx, data, length, tag)
//	assert.Equal(t, output.FLB_OK, resultCode)
//}

func TestFlush(t *testing.T) {
	// see https://github.com/fluent/fluent-bit-go/blob/master/output/decoder_test.go#L27
	dummyRecord := [29]byte{0x92, /* fix array 2 */
		0xd7, 0x00, 0x5e, 0xa9, 0x17, 0xe0, 0x00, 0x00, 0x00, 0x00, /* 2020/04/29 06:00:00*/
		0x82,                                           /* fix map 2*/
		0xa7, 0x63, 0x6f, 0x6e, 0x70, 0x61, 0x63, 0x74, /* fix str 7 "compact" */
		0xc3,                                     /* true */
		0xa6, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, /* fix str 6 "schema" */
		0x01, /* fix int 1 */
	}

	cfg := vkcloudlogs.VKCloudLogsConfig{
		IdentityEndpoint: "http://aurl-url",
		UserID:           "user-id",
		Password:         "password",
		ProjectID:        "project-id",
		ServerHostPort:   "server:8080",
	}
	plugin, err := vkcloudlogs.NewVKCloudLogs(&cfg, "test_version")
	assert.NoError(t, err)
	writerMock := vkcloudlogs.LogServiceClientMock{}
	plugin.Apiclient = &writerMock
	plugin.Token = "token"

	resultCode := flush(plugin, unsafe.Pointer(&dummyRecord), len(dummyRecord), "tag")
	assert.Equal(t, fluent.FLB_OK, resultCode)

	mockCalls := writerMock.WriteCalls()
	assert.Equal(t, len(mockCalls), 1)
	msg := mockCalls[0].In
	assert.Equal(t, "default", msg.ServiceId)
	assert.Equal(t, "tag", msg.GroupId)
	assert.Equal(t, "", msg.StreamId)
	assert.Equal(t, 1, len(msg.Entries))
	assert.Equal(t, "", msg.Entries[0].Message)
	assert.Equal(t, gen.LogEntry_info, msg.Entries[0].Level)
}

func TestExit(t *testing.T) {
	resultCode := FLBPluginExit()
	assert.Equal(t, fluent.FLB_OK, resultCode)
}
