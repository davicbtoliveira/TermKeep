package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const defaultAuditRetention = 90 * 24 * time.Hour
const defaultAuditPageSize = 50
const maximumAuditPageSize = 100

type AuditEvent struct {
	EventID    string    `json:"event_id"`
	Type       string    `json:"type"`
	AccountID  string    `json:"account_id,omitempty"`
	ActorID    string    `json:"actor_id,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
	InviteID   string    `json:"invite_id,omitempty"`
	SourceIP   string    `json:"source_ip,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

type AuditQuery struct {
	AccountID string
	BeforeAt  time.Time
	BeforeID  string
	Limit     int
}

type AuditStore interface {
	CreateAuditEvent(ctx context.Context, event AuditEvent) error
	ListAuditEvents(ctx context.Context, query AuditQuery) ([]AuditEvent, error)
	DeleteAuditEventsBefore(ctx context.Context, cutoff time.Time) error
}

type AuditLog struct {
	store     AuditStore
	retention time.Duration
	now       func() time.Time
}

func NewAuditLog(store AuditStore, retention time.Duration) *AuditLog {
	if retention <= 0 {
		retention = defaultAuditRetention
	}
	return &AuditLog{store: store, retention: retention, now: time.Now}
}

func ParseAuditRetention(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultAuditRetention, nil
	}
	days, err := strconv.ParseInt(value, 10, 64)
	maxDays := int64(^uint64(0)>>1) / int64(24*time.Hour)
	if err != nil || days < 1 || days > maxDays {
		return 0, errors.New("AUDIT_RETENTION_DAYS must be a positive integer")
	}
	return time.Duration(days) * 24 * time.Hour, nil
}

func (l *AuditLog) list(ctx context.Context, query AuditQuery) ([]AuditEvent, error) {
	if err := l.store.DeleteAuditEventsBefore(ctx, l.now().Add(-l.retention)); err != nil {
		return nil, err
	}
	return l.store.ListAuditEvents(ctx, query)
}

func (l *AuditLog) Record(ctx context.Context, event AuditEvent) error {
	if event.Type == "" {
		return errors.New("audit event type is required")
	}
	if event.EventID == "" {
		eventID, err := newAccountID()
		if err != nil {
			return err
		}
		event.EventID = eventID
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = l.now()
	}
	if err := l.store.DeleteAuditEventsBefore(ctx, l.now().Add(-l.retention)); err != nil {
		return err
	}
	return l.store.CreateAuditEvent(ctx, event)
}

func recordAudit(ctx context.Context, audit *AuditLog, event AuditEvent) {
	if audit == nil {
		return
	}
	if err := audit.Record(ctx, event); err != nil {
		slog.Error("record audit event", "event_type", event.Type, "error", err)
	}
}

type ActivityService struct {
	audit *AuditLog
	auth  *AuthService
}

func NewActivityService(audit *AuditLog, auth *AuthService) *ActivityService {
	return &ActivityService{audit: audit, auth: auth}
}

func (s *ActivityService) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/activity", s.listOwn)
	mux.HandleFunc("GET /api/v1/admin/activity", s.listAll)
}

func (s *ActivityService) listOwn(w http.ResponseWriter, r *http.Request) {
	token, err := s.auth.AuthenticateToken(r.Context(), bearerToken(r))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.list(w, r, token.AccountID, token.Administrator)
}

func (s *ActivityService) listAll(w http.ResponseWriter, r *http.Request) {
	if _, err := authenticateAdministrator(s.auth, r); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.list(w, r, "", true)
}

func (s *ActivityService) list(
	w http.ResponseWriter,
	r *http.Request,
	accountID string,
	canViewAll bool,
) {
	query, err := auditQuery(r, accountID)
	if err != nil {
		http.Error(w, "invalid activity query", http.StatusBadRequest)
		return
	}
	events, err := s.audit.list(r.Context(), query)
	if err != nil {
		http.Error(w, "failed to list activity", http.StatusInternalServerError)
		return
	}
	pageSize := query.Limit - 1
	var nextCursor string
	if len(events) > pageSize {
		events = events[:pageSize]
		nextCursor = encodeAuditCursor(events[len(events)-1])
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events":       events,
		"next_cursor":  nextCursor,
		"can_view_all": canViewAll,
	})
}

type auditCursor struct {
	OccurredAt time.Time `json:"occurred_at"`
	EventID    string    `json:"event_id"`
}

func auditQuery(r *http.Request, accountID string) (AuditQuery, error) {
	limit := defaultAuditPageSize
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > maximumAuditPageSize {
			return AuditQuery{}, errors.New("invalid limit")
		}
		limit = parsed
	}
	query := AuditQuery{AccountID: accountID, Limit: limit + 1}
	if value := r.URL.Query().Get("cursor"); value != "" {
		cursor, err := decodeAuditCursor(value)
		if err != nil {
			return AuditQuery{}, err
		}
		query.BeforeAt = cursor.OccurredAt
		query.BeforeID = cursor.EventID
	}
	return query, nil
}

func encodeAuditCursor(event AuditEvent) string {
	encoded, _ := json.Marshal(auditCursor{
		OccurredAt: event.OccurredAt,
		EventID:    event.EventID,
	})
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func decodeAuditCursor(value string) (auditCursor, error) {
	encoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return auditCursor{}, errors.New("invalid cursor")
	}
	var cursor auditCursor
	if err := json.Unmarshal(encoded, &cursor); err != nil ||
		cursor.OccurredAt.IsZero() || cursor.EventID == "" {
		return auditCursor{}, errors.New("invalid cursor")
	}
	return cursor, nil
}
