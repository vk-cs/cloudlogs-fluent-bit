package vkcloudlogs

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vk-cs/cloudlogs-fluent-bit/gen"

	fluent "github.com/fluent/fluent-bit-go/output"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type keyFile struct {
	UserID   string `json:"user_id"`
	Password string `json:"password"`
}

var (
	tagRegexp = regexp.MustCompile(`^[a-zA-Z0-9-_]*$`)
)

const (
	maxEntries   = 100
	connTimeout  = 15 * time.Second
	writeTimeout = 15 * time.Second
	tagLength    = 84

	defaultMessageKey = "message"
	defaultLevelKey   = "level"
	defaultLogLevel   = "info"
	defaultServiceId  = "default"
)

type VKCloudLogsConfig struct {
	// Auth
	IdentityEndpoint string
	KeyFile          string
	UserID           string
	Username         string
	Password         string
	ProjectID        string
	// Server
	ServerHostPort string
	Tls            string
	TlsVerify      string
	// Tagging
	ServiceID       string
	GroupID         string
	StreamID        string
	DefaultPayload  string
	PayloadTemplate map[string]interface{}
	InternalRaw     string
	Internal        bool
	// Parsing
	MessageKey   string
	LevelKey     string
	DefaultLevel string
	GroupIDKey   string
	StreamIDKey  string
}

type Tag struct {
	StreamID string
	GroupID  string
}

func (cfg *VKCloudLogsConfig) validate(logger *zap.SugaredLogger) (err error) {
	if cfg.IdentityEndpoint == "" {
		return errors.New(`Require config "auth_url"`)
	}
	if cfg.ProjectID == "" {
		return errors.New(`Require config "project_id"`)
	}
	if cfg.ServerHostPort == "" {
		return errors.New(`Require config "server_host_port"`)
	}
	if _, err := url.ParseRequestURI(cfg.ServerHostPort); err != nil {
		return fmt.Errorf(`Invalid url "server_host_port": %q`, cfg.ServerHostPort)
	}
	if _, err := url.ParseRequestURI(cfg.IdentityEndpoint); err != nil {
		return fmt.Errorf(`Invalid url "auth_url": %q`, cfg.IdentityEndpoint)
	}

	if cfg.KeyFile == "" && cfg.Password == "" {
		return errors.New(`Require config "key_file" or "password"`)
	}

	if cfg.InternalRaw != "" {
		internal, err := strconv.ParseBool(cfg.InternalRaw)
		if err != nil {
			return errors.New(`Invalid config "internal"`)
		}
		cfg.Internal = internal
	}

	cleanKey := func(key, defaultValue string) string {
		if key == "" {
			key = defaultValue
		}
		key = strings.ToLower(key)
		return key
	}

	keyOverrides := make(map[string]string)
	checkCollision := func(key, keyName string) error {
		if key != "" {
			if v, ok := keyOverrides[key]; ok {
				return fmt.Errorf(`Same key for %q and %q`, keyName, v)
			}
			keyOverrides[key] = keyName
		}
		return nil
	}

	cfg.MessageKey = cleanKey(cfg.MessageKey, defaultMessageKey)
	err = checkCollision(cfg.MessageKey, "message_key")
	if err != nil {
		return err
	}
	cfg.LevelKey = cleanKey(cfg.LevelKey, defaultLevelKey)
	err = checkCollision(cfg.LevelKey, "level_key")
	if err != nil {
		return err
	}
	cfg.GroupIDKey = cleanKey(cfg.GroupIDKey, "")
	err = checkCollision(cfg.GroupIDKey, "group_id_key")
	if err != nil {
		return err
	}
	cfg.StreamIDKey = cleanKey(cfg.StreamIDKey, "")
	err = checkCollision(cfg.StreamIDKey, "stream_id_key")
	if err != nil {
		return err
	}

	cfg.DefaultLevel = cleanKey(cfg.DefaultLevel, defaultLogLevel)
	if _, ok := gen.LogEntry_Level_value[cfg.DefaultLevel]; !ok {
		return errors.New(`Incorrect "default_config" value`)
	}

	cfg.ServiceID = cleanKey(cfg.ServiceID, defaultServiceId)

	groupOk := tagRegexp.MatchString(cfg.GroupID)
	if len(cfg.GroupID) > tagLength || !groupOk {
		return errors.New(`Config "group_id" too long or have invalid characters`)
	}
	streamOk := tagRegexp.MatchString(cfg.StreamID)
	if len(cfg.StreamID) > tagLength || !streamOk {
		return errors.New(`Config "stream_id" too long or have invalid characters`)
	}

	if cfg.DefaultPayload != "" {
		err := json.Unmarshal([]byte(cfg.DefaultPayload), &cfg.PayloadTemplate)
		if err != nil || len(cfg.PayloadTemplate) == 0 {
			return errors.New(`Config "default_payload" must be valid json`)
		}
	}

	return nil
}

func (cfg *VKCloudLogsConfig) validateAuth() (authOpts *tokens.AuthOptions, err error) {

	if cfg.KeyFile != "" {
		b, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf(`Cannot read file %q error %v`, cfg.KeyFile, err)
		}
		key := keyFile{}
		if err := json.Unmarshal(b, &key); err != nil {
			return nil, fmt.Errorf(`Cannot parse json %q error %v`, cfg.KeyFile, err)
		}
		if key.UserID == "" {
			return nil, errors.New(`Require key_file "user_id"`)
		}
		if key.Password == "" {
			return nil, errors.New(`Require key_file "password"`)
		}
		authOpts = &tokens.AuthOptions{
			IdentityEndpoint: cfg.IdentityEndpoint,
			UserID:           key.UserID,
			Password:         key.Password,
			Scope:            tokens.Scope{ProjectID: cfg.ProjectID},
			AllowReauth:      false,
		}
	} else if cfg.UserID != "" {
		authOpts = &tokens.AuthOptions{
			IdentityEndpoint: cfg.IdentityEndpoint,
			UserID:           cfg.UserID,
			Password:         cfg.Password,
			Scope:            tokens.Scope{ProjectID: cfg.ProjectID},
			AllowReauth:      false,
		}
	} else if cfg.Username != "" {
		authOpts = &tokens.AuthOptions{
			IdentityEndpoint: cfg.IdentityEndpoint,
			Username:         cfg.Username,
			DomainID:         "users",
			Password:         cfg.Password,
			Scope:            tokens.Scope{ProjectID: cfg.ProjectID},
			AllowReauth:      false,
		}
	} else {
		return nil, errors.New(`Require config "key_file", "user_id" or "user_name"`)
	}
	return authOpts, nil
}

type VKCloudLogs struct {
	authOpts *tokens.AuthOptions
	conn     *grpc.ClientConn
	grpcUrl  string

	Apiclient gen.LogServiceClient
	Token     string
	Logger    *zap.SugaredLogger

	cfg *VKCloudLogsConfig
}

func NewVKCloudLogs(cfg *VKCloudLogsConfig, buildVersion string) (*VKCloudLogs, error) {

	logger := zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
		os.Stdout,
		zap.InfoLevel,
	)).Sugar()

	logger.Infof("Init %s", buildVersion)

	err := cfg.validate(logger)
	if err != nil {
		logger.Error(err)
		return nil, err
	}
	authOpts, err := cfg.validateAuth()
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	tlsOn, err := strconv.ParseBool(cfg.Tls)
	if err != nil {
		tlsOn = true
	}
	tlsVerify, err := strconv.ParseBool(cfg.TlsVerify)
	if err != nil {
		tlsVerify = true
	}

	var creds credentials.TransportCredentials
	if tlsOn {
		creds = credentials.NewTLS(&tls.Config{InsecureSkipVerify: !tlsVerify})
	} else {
		creds = insecure.NewCredentials()
	}

	conn, err := grpc.Dial(cfg.ServerHostPort, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}

	return &VKCloudLogs{
		authOpts:  authOpts,
		conn:      conn,
		Apiclient: gen.NewLogServiceClient(conn),
		Logger:    logger,
		cfg:       cfg,
		grpcUrl:   cfg.ServerHostPort}, nil
}

func (p *VKCloudLogs) Init() (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), connTimeout)
	defer cancel()

	p.conn.Connect()
	p.conn.WaitForStateChange(ctx, connectivity.Idle)
	p.conn.WaitForStateChange(ctx, connectivity.Connecting)
	state := p.conn.GetState()

	if state != connectivity.Ready {
		p.Logger.Errorf("Cannot connect to %s", p.grpcUrl)
		return errors.New("Bad server")
	}

	err = p.auth()
	if err != nil {
		p.Logger.Errorf("Cannot authorize: %v", err)
		return err
	}
	return nil
}

func (p *VKCloudLogs) auth() (err error) {
	if p.authOpts.UserID != "" {
		p.Logger.Infof("Getting token from %q for user_id %q project_id %q",
			p.authOpts.IdentityEndpoint,
			p.authOpts.UserID,
			p.authOpts.Scope.ProjectID,
		)
	} else {
		p.Logger.Infof("Getting token from %q for user_name %q project_id %q",
			p.authOpts.IdentityEndpoint,
			p.authOpts.Username,
			p.authOpts.Scope.ProjectID,
		)
	}

	start := time.Now()
	client, err := openstack.NewClient(p.authOpts.IdentityEndpoint)
	if err != nil {
		return
	}

	v3Client, err := openstack.NewIdentityV3(client, gophercloud.EndpointOpts{})
	if err != nil {
		return
	}

	token, err := tokens.Create(v3Client, p.authOpts).ExtractTokenID()
	if err != nil {
		return
	}

	p.Token = token
	p.Logger.Debugf("Got token in %v", time.Since(start))
	return
}

func (p *VKCloudLogs) Parse(ts interface{}, record map[interface{}]interface{}) (entry *gen.LogEntry, tag Tag) {
	var (
		timestamp time.Time
		message   string
		level     string
		streamId  string
		groupId   string
	)

	// parse timestamp
	switch typed := ts.(type) {
	case fluent.FLBTime:
		timestamp = typed.Time
	case uint64:
		timestamp = time.Unix(int64(typed), 0)
	default:
		p.Logger.Warnf("time provided invalid %v, defaulting to now.", typed)
		timestamp = time.Now()
	}

	jsonPayload := make(map[string]interface{})
	for key, value := range p.cfg.PayloadTemplate {
		jsonPayload[key] = value
	}

	// parse record
	for k, v := range record {
		key, ok := k.(string)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case p.cfg.MessageKey:
			message = toString(v)
		case p.cfg.LevelKey:
			level = toString(v)
		case p.cfg.GroupIDKey:
			groupId = toString(v)
		case p.cfg.StreamIDKey:
			streamId = toString(v)
		default:
			jsonPayload[key] = toString(v)
		}
	}
	strJsonPayload := ""
	if len(jsonPayload) > 0 {
		b, _ := json.Marshal(jsonPayload)
		strJsonPayload = string(b)
	}
	levelInt, ok := gen.LogEntry_Level_value[strings.ToLower(level)]
	if !ok {
		levelInt = gen.LogEntry_Level_value[p.cfg.DefaultLevel]
	}

	if streamId == "" {
		streamId = p.cfg.StreamID
	}

	if groupId == "" {
		groupId = p.cfg.GroupID
	}

	entry = &gen.LogEntry{
		Timestamp:   timestamppb.New(timestamp),
		Message:     message,
		Level:       gen.LogEntry_Level(levelInt),
		JsonPayload: strJsonPayload,
	}
	return entry, Tag{GroupID: groupId, StreamID: streamId}
}

func (p *VKCloudLogs) Write(tag Tag, entries []*gen.LogEntry) int {
	for len(entries) > 0 {
		var toSend []*gen.LogEntry
		if len(entries) > maxEntries {
			toSend = entries[:maxEntries]
			entries = entries[maxEntries:]
		} else {
			toSend = entries
			entries = nil
		}

		p.Logger.Debugf("Writing logs %s/%s %v", tag.GroupID, tag.StreamID, toSend)
		req := &gen.WriteRequest{
			ServiceId: p.cfg.ServiceID,
			GroupId:   tag.GroupID,
			StreamId:  tag.StreamID,
			Entries:   toSend,
			Internal:  p.cfg.Internal,
		}

		if p.Token == "" {
			err := p.auth()
			if err != nil {
				return fluent.FLB_ERROR
			}
		}
		start := time.Now()
		reqCtx, cancel := context.WithTimeout(context.Background(), writeTimeout)
		defer cancel()

		resp, err := p.Apiclient.Write(
			metadata.NewOutgoingContext(reqCtx, metadata.Pairs("X-Auth-Token", p.Token)),
			req,
		)
		p.Logger.Debugf("WriterAPI response %v in %v", resp, time.Since(start))
		if err != nil {
			if requestStatus, ok := status.FromError(err); ok {
				switch requestStatus.Code() {
				case codes.ResourceExhausted,
					codes.FailedPrecondition,
					codes.Unavailable,
					codes.Unknown,
					codes.Canceled,
					codes.DeadlineExceeded:
					p.Logger.Infof("WriterAPI retrying due %v", err)
					return fluent.FLB_RETRY
				case codes.Unauthenticated:
					p.Token = ""
					p.Logger.Debugf("WriterAPI retrying due unauthorized")
					return fluent.FLB_RETRY
				}
			}
			p.Logger.Errorf("WriterAPI error %v", err)
			return fluent.FLB_ERROR
		}
	}
	return fluent.FLB_OK
}

func toString(raw interface{}) string {
	switch typed := raw.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	case [][]byte:
		strs := make([]string, 0, len(typed))
		for _, k := range typed {
			strs = append(strs, toString(k))
		}
		return toString(strs)
	default:
		return fmt.Sprintf("%v", typed)
	}
}
