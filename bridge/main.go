// ScamSaathi WhatsApp bridge (channel adapter).
//
// Built directly on go.mau.fi/whatsmeow (pinned in go.mod). It implements only the SRS 6.2
// contract:
//   inbound : POST $WEBHOOK_URL  {msg_id, sender_jid, chat_type, type, text, caption,
//                                  media_path, forwarded, timestamp}
//   outbound: POST /api/send     {recipient, message}   (X-Bridge-Token required)
//   health  : GET  /api/health   {status, connected, logged_in}
//   login   : GET  /qr           PNG of the current pairing QR (bind to localhost only)
//
// Security (SRS 3.3, rule 2): /api/send only delivers to direct chats that messaged the bot
// within REPLY_WINDOW_HOURS, or to ADMIN_JID. Groups, status and newsletters are never
// forwarded or sent to. Swapping to the official Cloud API only replaces this adapter.
package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/mdp/qrterminal/v3"
	qrcode "github.com/skip2/go-qrcode"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"
)

type config struct {
	webhookURL   string
	token        string
	storeDir     string
	mediaDir     string
	listen       string
	adminJID     string
	replyWindow  time.Duration
	maxMediaSize uint64
	allowlist    map[string]bool // phone digits; empty = everyone
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func loadConfig() config {
	hours, _ := strconv.Atoi(env("REPLY_WINDOW_HOURS", "24"))
	return config{
		webhookURL:   env("WEBHOOK_URL", "http://n8n:5678/webhook/wa-inbound"),
		token:        os.Getenv("BRIDGE_TOKEN"),
		storeDir:     env("STORE_DIR", "/store"),
		mediaDir:     env("MEDIA_DIR", "/media"),
		listen:       env("LISTEN_ADDR", ":8080"),
		adminJID:     os.Getenv("ADMIN_JID"),
		replyWindow:  time.Duration(hours) * time.Hour,
		maxMediaSize: 10 << 20,
		allowlist:    parseAllowlist(os.Getenv("SENDER_ALLOWLIST")),
	}
}

var nonDigit = regexp.MustCompile(`[^0-9]`)

// parseAllowlist turns "919000000001, +91 90000 00002" into a set of digit strings.
func parseAllowlist(s string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		if d := nonDigit.ReplaceAllString(part, ""); d != "" {
			out[d] = true
		}
	}
	return out
}

// senderAllowed applies SENDER_ALLOWLIST (dev mode on personal numbers). Senders addressed by
// LID are resolved to their phone number through the session store.
func (b *bridge) senderAllowed(info types.MessageInfo) bool {
	if len(b.cfg.allowlist) == 0 {
		return true
	}
	for _, j := range []types.JID{info.Chat, info.Sender, info.SenderAlt} {
		if j.IsEmpty() {
			continue
		}
		if j.Server == types.HiddenUserServer {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			pn, err := b.client.Store.LIDs.GetPNForLID(ctx, j.ToNonAD())
			cancel()
			if err != nil || pn.IsEmpty() {
				continue
			}
			j = pn
		}
		if b.cfg.allowlist[j.User] {
			return true
		}
	}
	return false
}

// InboundPayload is the SRS 6.2 webhook body.
type InboundPayload struct {
	MsgID     string `json:"msg_id"`
	SenderJID string `json:"sender_jid"`
	ChatType  string `json:"chat_type"`
	Type      string `json:"type"`
	Text      string `json:"text"`
	Caption   string `json:"caption"`
	MediaPath string `json:"media_path"`
	Forwarded bool   `json:"forwarded"`
	Timestamp int64  `json:"timestamp"`
}

type bridge struct {
	cfg    config
	client *whatsmeow.Client
	http   *http.Client

	mu       sync.Mutex
	seen     map[string]time.Time // chat JID -> last inbound time (reply window)
	qrCode   string
	loggedIn bool
}

var safeID = regexp.MustCompile(`[^A-Za-z0-9]`)

// allowedRecipient enforces rule 2 in the adapter as a second line of defence.
func (b *bridge) allowedRecipient(jid types.JID) error {
	if jid.Server != types.DefaultUserServer && jid.Server != types.HiddenUserServer {
		return fmt.Errorf("recipient must be a direct chat")
	}
	if b.cfg.adminJID != "" && jid.String() == b.cfg.adminJID {
		return nil
	}
	b.mu.Lock()
	last, ok := b.seen[jid.String()]
	b.mu.Unlock()
	if !ok || time.Since(last) > b.cfg.replyWindow {
		return fmt.Errorf("recipient has not messaged the bot within the reply window")
	}
	return nil
}

func (b *bridge) markSeen(jid types.JID) {
	b.mu.Lock()
	b.seen[jid.String()] = time.Now()
	b.mu.Unlock()
}

func (b *bridge) handleEvent(evt interface{}) {
	switch v := evt.(type) {
	case *events.Message:
		go b.onMessage(v)
	case *events.Connected:
		b.mu.Lock()
		b.loggedIn, b.qrCode = true, ""
		b.mu.Unlock()
		log.Println("connected to WhatsApp")
	case *events.LoggedOut:
		b.mu.Lock()
		b.loggedIn = false
		b.mu.Unlock()
		log.Println("logged out: a new QR scan is needed (restart the container)")
	}
}

func (b *bridge) onMessage(evt *events.Message) {
	info := evt.Info
	// FR-3: ignore own messages, groups, status updates, broadcasts and newsletters.
	if info.IsFromMe || info.IsGroup || info.Chat.Server == types.BroadcastServer ||
		info.Chat.Server == types.NewsletterServer || info.Chat.Server == types.GroupServer {
		return
	}
	if !b.senderAllowed(info) {
		log.Printf("ignored message %s from a sender outside SENDER_ALLOWLIST", info.ID)
		return
	}
	msg := evt.Message
	p := InboundPayload{
		MsgID:     info.ID,
		SenderJID: info.Chat.String(),
		ChatType:  "direct",
		Type:      "text",
		Timestamp: info.Timestamp.Unix(),
	}
	switch {
	case msg.GetConversation() != "":
		p.Text = msg.GetConversation()
	case msg.GetExtendedTextMessage() != nil:
		et := msg.GetExtendedTextMessage()
		p.Text = et.GetText()
		p.Forwarded = et.GetContextInfo().GetIsForwarded()
	case msg.GetImageMessage() != nil:
		img := msg.GetImageMessage()
		p.Type = "image"
		p.Caption = img.GetCaption()
		p.Forwarded = img.GetContextInfo().GetIsForwarded()
		path, err := b.saveImage(info.ID, img)
		if err != nil {
			log.Printf("media download failed for %s: %v", info.ID, err)
		}
		p.MediaPath = path
	default:
		p.Type = "unsupported"
	}
	b.markSeen(info.Chat)
	b.post(p)
}

func (b *bridge) saveImage(id string, img *waE2E.ImageMessage) (string, error) {
	if img.GetFileLength() > b.cfg.maxMediaSize {
		return "", fmt.Errorf("image too large")
	}
	ext := ".jpg"
	switch img.GetMimetype() {
	case "image/png":
		ext = ".png"
	case "image/jpeg", "":
	default:
		return "", fmt.Errorf("unsupported mimetype %q", img.GetMimetype())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	data, err := b.client.Download(ctx, img)
	if err != nil {
		return "", err
	}
	name := safeID.ReplaceAllString(id, "") + ext
	if err := os.WriteFile(filepath.Join(b.cfg.mediaDir, name), data, 0o644); err != nil {
		return "", err
	}
	return "/media/" + name, nil
}

func (b *bridge) post(p InboundPayload) {
	body, _ := json.Marshal(p)
	for attempt := 1; attempt <= 3; attempt++ {
		req, _ := http.NewRequest(http.MethodPost, b.cfg.webhookURL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Bridge-Token", b.cfg.token)
		resp, err := b.http.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 300 {
				return
			}
			err = fmt.Errorf("status %d", resp.StatusCode)
		}
		log.Printf("webhook attempt %d for %s failed: %v", attempt, p.MsgID, err)
		time.Sleep(time.Duration(attempt) * time.Second)
	}
}

func (b *bridge) authorized(r *http.Request) bool {
	got := r.Header.Get("X-Bridge-Token")
	return b.cfg.token != "" && subtle.ConstantTimeCompare([]byte(got), []byte(b.cfg.token)) == 1
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (b *bridge) handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"success": false, "message": "POST only"})
		return
	}
	if !b.authorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "message": "unauthorized"})
		return
	}
	var req struct {
		Recipient string `json:"recipient"`
		Message   string `json:"message"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "message": "bad json"})
		return
	}
	jid, err := types.ParseJID(strings.TrimSpace(req.Recipient))
	if err != nil || req.Message == "" || len(req.Message) > 4096 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "message": "bad recipient or message"})
		return
	}
	if err := b.allowedRecipient(jid); err != nil {
		log.Printf("send refused to %s: %v", jid, err)
		writeJSON(w, http.StatusForbidden, map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	_, err = b.client.SendMessage(ctx, jid, &waE2E.Message{Conversation: proto.String(req.Message)})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "message": "sent"})
}

func (b *bridge) handleHealth(w http.ResponseWriter, _ *http.Request) {
	b.mu.Lock()
	logged := b.loggedIn
	b.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ok", "connected": b.client.IsConnected(), "logged_in": logged && b.client.Store.ID != nil,
	})
}

func (b *bridge) handleQR(w http.ResponseWriter, _ *http.Request) {
	b.mu.Lock()
	code := b.qrCode
	b.mu.Unlock()
	if code == "" {
		http.Error(w, "no QR pending (already logged in, or not generated yet)", http.StatusNotFound)
		return
	}
	png, err := qrcode.Encode(code, qrcode.Medium, 384)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

func main() {
	cfg := loadConfig()
	if cfg.token == "" {
		log.Fatal("BRIDGE_TOKEN is required")
	}
	if err := os.MkdirAll(cfg.mediaDir, 0o755); err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	dbLog := waLog.Stdout("db", "WARN", true)
	container, err := sqlstore.New(ctx, "sqlite3", "file:"+filepath.Join(cfg.storeDir, "wa.db")+"?_foreign_keys=on", dbLog)
	if err != nil {
		log.Fatal(err)
	}
	device, err := container.GetFirstDevice(ctx)
	if err != nil {
		log.Fatal(err)
	}
	b := &bridge{cfg: cfg, http: &http.Client{Timeout: 30 * time.Second}, seen: map[string]time.Time{}}
	b.client = whatsmeow.NewClient(device, waLog.Stdout("wa", "WARN", true))
	b.client.AddEventHandler(b.handleEvent)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/send", b.handleSend)
	mux.HandleFunc("/api/health", b.handleHealth)
	mux.HandleFunc("/qr", b.handleQR)
	srv := &http.Server{Addr: cfg.listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Printf("bridge API on %s", cfg.listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	if b.client.Store.ID == nil {
		qrChan, _ := b.client.GetQRChannel(ctx)
		if err := b.client.Connect(); err != nil {
			log.Fatal(err)
		}
		go func() {
			for evt := range qrChan {
				if evt.Event == "code" {
					b.mu.Lock()
					b.qrCode = evt.Code
					b.mu.Unlock()
					log.Println("scan this QR with WhatsApp > Linked devices (or open http://127.0.0.1:8080/qr):")
					qrterminal.GenerateHalfBlock(evt.Code, qrterminal.L, os.Stdout)
				} else {
					log.Printf("login event: %s", evt.Event)
				}
			}
		}()
	} else if err := b.client.Connect(); err != nil {
		log.Fatal(err)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	b.client.Disconnect()
	_ = srv.Shutdown(context.Background())
}
