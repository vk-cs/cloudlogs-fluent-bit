package vkcloudlogs

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vk-cs/cloudlogs-fluent-bit/gen"

	fluent "github.com/fluent/fluent-bit-go/output"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestConfig(t *testing.T) {
	pwd, err := os.Getwd()
	assert.NoError(t, err)

	cases := []struct {
		name    string
		noError bool
		authOps *tokens.AuthOptions
		goodCfg bool
		cfg     VKCloudLogsConfig
	}{
		{
			name: "no auth",
			cfg: VKCloudLogsConfig{
				UserID:         "user_id",
				Password:       "password",
				ProjectID:      "project_id",
				ServerHostPort: "server:8080",
			},
		},
		{
			name: "no user info",
			cfg: VKCloudLogsConfig{
				IdentityEndpoint: "http://aurl_url",
				Password:         "password",
				ProjectID:        "project_id",
				ServerHostPort:   "server:8080",
			},
		},
		{
			name: "no password",
			cfg: VKCloudLogsConfig{
				IdentityEndpoint: "http://aurl_url",
				UserID:           "user_id",
				ProjectID:        "project_id",
				ServerHostPort:   "server:8080",
			},
		},
		{
			name: "no project",
			cfg: VKCloudLogsConfig{
				IdentityEndpoint: "http://aurl_url",
				UserID:           "user_id",
				Password:         "password",
				ServerHostPort:   "server:8080",
			},
		},
		{
			name: "no server host",
			cfg: VKCloudLogsConfig{
				IdentityEndpoint: "http://aurl_url",
				UserID:           "user_id",
				Password:         "password",
				ProjectID:        "project_id",
			},
		},
		{
			name: "bad auth url",
			cfg: VKCloudLogsConfig{
				IdentityEndpoint: "broken",
				UserID:           "user_id",
				Password:         "password",
				ProjectID:        "project_id",
				ServerHostPort:   "server:8080",
			},
		},
		{
			name: "bad server url",
			cfg: VKCloudLogsConfig{
				IdentityEndpoint: "http://aurl_url",
				UserID:           "user_id",
				Password:         "password",
				ProjectID:        "project_id",
				ServerHostPort:   "broken",
			},
		},
		{
			name:    "ok auth by user id",
			noError: true,
			cfg: VKCloudLogsConfig{
				IdentityEndpoint: "http://aurl_url",
				UserID:           "user_id",
				Password:         "password",
				ProjectID:        "project_id",
				ServerHostPort:   "server:8080",
			},
			authOps: &tokens.AuthOptions{
				IdentityEndpoint: "http://aurl_url",
				UserID:           "user_id",
				Password:         "password",
				Scope:            tokens.Scope{ProjectID: "project_id"},
				AllowReauth:      false,
			},
		},
		{
			name:    "ok auth by user name",
			noError: true,
			cfg: VKCloudLogsConfig{
				IdentityEndpoint: "http://aurl_url",
				Username:         "user_name",
				Password:         "password",
				ProjectID:        "project_id",
				ServerHostPort:   "server:8080",
			},
			authOps: &tokens.AuthOptions{
				IdentityEndpoint: "http://aurl_url",
				Username:         "user_name",
				DomainID:         "users",
				Password:         "password",
				Scope:            tokens.Scope{ProjectID: "project_id"},
				AllowReauth:      false,
			},
		},
		{
			name:    "ok auth by key file",
			noError: true,
			cfg: VKCloudLogsConfig{
				IdentityEndpoint: "http://aurl_url",
				KeyFile:          pwd + "/fixtures/good.json",
				ProjectID:        "project_id",
				ServerHostPort:   "server:8080",
			},
			authOps: &tokens.AuthOptions{
				IdentityEndpoint: "http://aurl_url",
				UserID:           "user",
				Password:         "pass",
				Scope:            tokens.Scope{ProjectID: "project_id"},
				AllowReauth:      false,
			},
		},
		{
			name: "bad missing key-file",
			cfg: VKCloudLogsConfig{
				IdentityEndpoint: "http://aurl_url",
				KeyFile:          pwd + "/missing_path",
				ProjectID:        "project_id",
				ServerHostPort:   "server:8080",
			},
		},
		{
			name: "bad key-file broken json",
			cfg: VKCloudLogsConfig{
				IdentityEndpoint: "http://aurl_url",
				KeyFile:          pwd + "/fixtures/broken.json",
				ProjectID:        "project_id",
				ServerHostPort:   "server:8080",
			},
		},
		{
			name: "bad key-file missing key",
			cfg: VKCloudLogsConfig{
				IdentityEndpoint: "http://aurl_url",
				KeyFile:          pwd + "/fixtures/missing_key.json",
				ProjectID:        "project_id",
				ServerHostPort:   "server:8080",
			},
		},
		{
			name:    "broken payload",
			goodCfg: true,
			cfg: VKCloudLogsConfig{
				DefaultPayload: "bad",
			},
		},
		{
			name:    "empty payload",
			goodCfg: true,
			cfg: VKCloudLogsConfig{
				DefaultPayload: "{}",
			},
		},
		{
			name:    "ok payload",
			noError: true,
			goodCfg: true,
			cfg: VKCloudLogsConfig{
				DefaultPayload: `{"a": [1,2,3], "b": {"nested": true}}`,
			},
		},
		{
			name:    "ok tls true",
			noError: true,
			goodCfg: true,
			cfg: VKCloudLogsConfig{
				Tls: "true",
			},
		},
		{
			name:    "bad long groupid",
			goodCfg: true,
			cfg: VKCloudLogsConfig{
				GroupID: strings.Repeat("a", 85),
			},
		},
		{
			name:    "bad long streamid",
			goodCfg: true,
			cfg: VKCloudLogsConfig{
				StreamID: strings.Repeat("a", 85),
			},
		},
		{
			name:    "bad char streamid",
			goodCfg: true,
			cfg: VKCloudLogsConfig{
				StreamID: "!",
			},
		},
		{
			name:    "bad char groupid",
			goodCfg: true,
			cfg: VKCloudLogsConfig{
				GroupID: "!",
			},
		},
		{
			name:    "ok tls verify true",
			noError: true,
			goodCfg: true,
			cfg: VKCloudLogsConfig{
				Tls:       "true",
				TlsVerify: "true",
			},
		},
		{
			name:    "bad default log level",
			goodCfg: true,
			cfg: VKCloudLogsConfig{
				DefaultLevel: "broken",
			},
		},
		{
			name:    "bad internal",
			goodCfg: true,
			cfg: VKCloudLogsConfig{
				InternalRaw: "broken",
			},
		},
		{
			name:    "ok internal",
			noError: true,
			goodCfg: true,
			cfg: VKCloudLogsConfig{
				InternalRaw: "1",
			},
		},
		{
			name:    "collision level key",
			goodCfg: true,
			cfg:     VKCloudLogsConfig{LevelKey: "MESSAGE"},
		},
		{
			name:    "collision group id key",
			goodCfg: true,
			cfg:     VKCloudLogsConfig{GroupIDKey: "MESSAGE"},
		},
		{
			name:    "collision stream id key",
			goodCfg: true,
			cfg:     VKCloudLogsConfig{StreamIDKey: "MESSAGE"},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.goodCfg {
				testCase.cfg.IdentityEndpoint = "http://aurl_url"
				testCase.cfg.UserID = "user_id"
				testCase.cfg.Password = "password"
				testCase.cfg.ProjectID = "project_id"
				testCase.cfg.ServerHostPort = "server:8080"
			}
			plugin, err := NewVKCloudLogs(&testCase.cfg, "test_version")
			if testCase.noError {
				assert.NoError(t, err)
				assert.NotNil(t, plugin)
				if testCase.authOps != nil {
					assert.Equal(t, plugin.authOpts, testCase.authOps)
				}
				assert.Equal(t, testCase.cfg.Internal, testCase.cfg.InternalRaw != "")
			} else {
				assert.Error(t, err)
				assert.Nil(t, plugin)
			}
		})
	}
}

func TestParse(t *testing.T) {

	now := time.Date(2022, time.Month(2), 1, 0, 0, 0, 0, time.Local)
	cases := []struct {
		name             string
		ts               interface{}
		record           map[interface{}]interface{}
		cfgOverride      VKCloudLogsConfig
		expectedTS       *timestamppb.Timestamp
		expectedMessage  string
		expectedLevel    gen.LogEntry_Level
		expectedPayload  string
		expectedStreamID string
		expectedGroupID  string
	}{
		{
			name:            "entry proper",
			ts:              fluent.FLBTime{Time: now},
			record:          map[interface{}]interface{}{"message": "text", "level": "debug", 10: "broken", nil: "broken", "k": 10},
			expectedTS:      timestamppb.New(now),
			expectedMessage: "text",
			expectedLevel:   gen.LogEntry_debug,
			expectedPayload: `{"k":"10"}`,
		},
		{
			name:            "entry convertion",
			ts:              uint64(now.Unix()),
			record:          map[interface{}]interface{}{"message": 10, "level": 10, 10: 10, nil: 10},
			expectedTS:      timestamppb.New(now),
			expectedMessage: "10",
			expectedLevel:   gen.LogEntry_info,
		},
		{
			name:            "entry wrong",
			ts:              "wrong",
			record:          map[interface{}]interface{}{"message": nil, "level": nil, 10: nil, nil: nil},
			expectedMessage: "<nil>",
			expectedLevel:   gen.LogEntry_info,
		},
		{
			name:            "entry nil",
			ts:              nil,
			record:          nil,
			expectedMessage: "",
			expectedLevel:   gen.LogEntry_info,
		},
		{
			name:            "message as byte array",
			ts:              fluent.FLBTime{Time: now},
			record:          map[interface{}]interface{}{"message": [][]byte{[]byte("hello"), []byte("world")}},
			expectedLevel:   gen.LogEntry_info,
			expectedMessage: "[hello world]",
		},
		{
			name:            "custom as byte array",
			ts:              fluent.FLBTime{Time: now},
			record:          map[interface{}]interface{}{"custom": [][]byte{[]byte("hello"), []byte("world")}},
			expectedLevel:   gen.LogEntry_info,
			expectedPayload: `{"custom":"[hello world]"}`,
		},
		{
			name:          "entry log level override",
			cfgOverride:   VKCloudLogsConfig{DefaultLevel: "DEbug"},
			expectedLevel: gen.LogEntry_debug,
		},
		{
			name:          "entry level key override",
			record:        map[interface{}]interface{}{"mylevel": "debug"},
			cfgOverride:   VKCloudLogsConfig{LevelKey: "MYlevel"},
			expectedLevel: gen.LogEntry_debug,
		},
		{
			name:            "entry message key override",
			record:          map[interface{}]interface{}{"mymessage": "mysg"},
			cfgOverride:     VKCloudLogsConfig{MessageKey: "MYmessage"},
			expectedMessage: "mysg",
			expectedLevel:   gen.LogEntry_info,
		},
		{
			name:            "entry jsonpayload override",
			cfgOverride:     VKCloudLogsConfig{DefaultPayload: `{"a": 1}`},
			expectedLevel:   gen.LogEntry_info,
			expectedPayload: `{"a":1}`,
		},
		{
			name:            "entry jsonpayload override and add",
			record:          map[interface{}]interface{}{"k": 10},
			cfgOverride:     VKCloudLogsConfig{DefaultPayload: `{"a": 1}`},
			expectedLevel:   gen.LogEntry_info,
			expectedPayload: `{"a":1,"k":"10"}`,
		},
		{
			name:          "entry service override",
			cfgOverride:   VKCloudLogsConfig{ServiceID: "MYservice"},
			expectedLevel: gen.LogEntry_info,
		},
		{
			name:          "entry group override",
			cfgOverride:   VKCloudLogsConfig{GroupID: "mygroup"},
			expectedLevel: gen.LogEntry_info,
		},
		{
			name:          "entry stream override",
			cfgOverride:   VKCloudLogsConfig{StreamID: "mystream"},
			expectedLevel: gen.LogEntry_info,
		},
		{
			name:          "internal override",
			cfgOverride:   VKCloudLogsConfig{Internal: true},
			expectedLevel: gen.LogEntry_info,
		},
		{
			name:            "override group_id",
			record:          map[interface{}]interface{}{"my_group": "group"},
			cfgOverride:     VKCloudLogsConfig{GroupIDKey: "my_group"},
			expectedGroupID: "group",
			expectedLevel:   gen.LogEntry_info,
		},
		{
			name:             "override stream_id",
			record:           map[interface{}]interface{}{"my_stream": "stream"},
			cfgOverride:      VKCloudLogsConfig{StreamIDKey: "my_stream"},
			expectedStreamID: "stream",
			expectedLevel:    gen.LogEntry_info,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// init
			cfg := VKCloudLogsConfig{
				IdentityEndpoint: "http://aurl_url",
				UserID:           "user_id",
				Password:         "password",
				ProjectID:        "project_id",
				ServerHostPort:   "server:8080",
				DefaultLevel:     testCase.cfgOverride.DefaultLevel,
				LevelKey:         testCase.cfgOverride.LevelKey,
				MessageKey:       testCase.cfgOverride.MessageKey,
				DefaultPayload:   testCase.cfgOverride.DefaultPayload,
				ServiceID:        testCase.cfgOverride.ServiceID,
				GroupID:          testCase.cfgOverride.GroupID,
				StreamID:         testCase.cfgOverride.StreamID,
				GroupIDKey:       testCase.cfgOverride.GroupIDKey,
				StreamIDKey:      testCase.cfgOverride.StreamIDKey,
			}
			plugin, err := NewVKCloudLogs(&cfg, "test_version")
			assert.NoError(t, err)

			// mock
			writerMock := LogServiceClientMock{}
			plugin.Apiclient = &writerMock
			plugin.Token = "token"

			// parse
			entry, tag := plugin.Parse(testCase.ts, testCase.record)
			if testCase.expectedTS != nil {
				assert.Equal(t, testCase.expectedTS.AsTime(), entry.Timestamp.AsTime())
			}
			assert.Equal(t, testCase.expectedMessage, entry.Message)
			assert.Equal(t, testCase.expectedLevel, entry.Level)
			assert.Equal(t, testCase.expectedPayload, entry.JsonPayload)

			// write
			var entries []*gen.LogEntry
			entries = append(entries, entry)
			code := plugin.Write(tag, entries)
			assert.Equal(t, code, fluent.FLB_OK)
			mockCalls := writerMock.WriteCalls()
			assert.Equal(t, len(mockCalls), 1)
			msg := mockCalls[0].In
			if cfg.ServiceID == "" {
				assert.Equal(t, "default", msg.ServiceId)
			} else {
				assert.Equal(t, strings.ToLower(cfg.ServiceID), msg.ServiceId)
			}
			if testCase.expectedGroupID == "" {
				assert.Equal(t, cfg.GroupID, msg.GroupId)
			} else {
				assert.Equal(t, testCase.expectedGroupID, msg.GroupId)
			}
			if testCase.expectedStreamID == "" {
				assert.Equal(t, cfg.StreamID, msg.StreamId)
			} else {
				assert.Equal(t, testCase.expectedStreamID, msg.StreamId)
			}
			assert.Equal(t, cfg.Internal, msg.Internal)
			assert.Equal(t, 1, len(msg.Entries))
			if testCase.expectedTS != nil {
				assert.Equal(t, testCase.expectedTS.AsTime(), msg.Entries[0].Timestamp.AsTime())
			}
			assert.Equal(t, testCase.expectedMessage, msg.Entries[0].Message)
			assert.Equal(t, testCase.expectedLevel, msg.Entries[0].Level)
			assert.Equal(t, testCase.expectedPayload, msg.Entries[0].JsonPayload)
		})
	}
}

func TestMultiMessage(t *testing.T) {

	cfg := VKCloudLogsConfig{
		IdentityEndpoint: "http://aurl_url",
		UserID:           "user_id",
		Password:         "password",
		ProjectID:        "project_id",
		ServerHostPort:   "server:8080",
	}
	plugin, err := NewVKCloudLogs(&cfg, "test_version")
	assert.NoError(t, err)
	writerMock := LogServiceClientMock{}
	plugin.Apiclient = &writerMock
	plugin.Token = "token"

	var tagEntries = make(map[Tag][]*gen.LogEntry)
	for i := 0; i < 110; i++ {
		entry, tag := plugin.Parse(nil, map[interface{}]interface{}{"message": strconv.Itoa(i)})
		tagEntries[tag] = append(tagEntries[tag], entry)
	}

	for tag, entries := range tagEntries {
		code := plugin.Write(tag, entries)
		assert.Equal(t, code, fluent.FLB_OK)
		mockCalls := writerMock.WriteCalls()
		assert.Equal(t, len(mockCalls[0].In.Entries), 100)
		for i := 0; i < 100; i++ {
			assert.Equal(t, mockCalls[0].In.Entries[i].Message, strconv.Itoa(i))
		}
		assert.Equal(t, len(mockCalls[1].In.Entries), 10)
		for i := 0; i < 10; i++ {
			assert.Equal(t, mockCalls[1].In.Entries[i].Message, strconv.Itoa(i+100))
		}
	}
}
