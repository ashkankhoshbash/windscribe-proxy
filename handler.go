package main

import (
	"encoding/base64"
	"fmt"
	"github.com/Snawoot/windscribe-proxy/wndclient"
	"math/rand"
	"net/http"
	"strings"
	"sync"
)

const BAD_REQ_MSG = "Bad Request\n"

type AuthProvider func() string

type DialerClientPair struct {
	Dialer    ContextDialer
	WndClient *wndclient.WndClient
	Username  string
	Password  string
}

type ProxyHandler struct {
	logger        *CondLogger
	dialerClients []DialerClientPair
	httpTransport http.RoundTripper
	mu            sync.Mutex
}

func NewProxyHandler(dialerClients []DialerClientPair, logger *CondLogger) *ProxyHandler {
	return &ProxyHandler{
		logger:        logger,
		dialerClients: dialerClients,
	}
}

func (s *ProxyHandler) getRandomDialerClient() DialerClientPair {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dialerClients[rand.Intn(len(s.dialerClients))]
}

func (s *ProxyHandler) HandleTunnel(wr http.ResponseWriter, req *http.Request, clientPair DialerClientPair) {
	conn, err := clientPair.Dialer.DialContext(req.Context(), "tcp", req.RequestURI)
	if err != nil {
		s.logger.Error("Can't satisfy CONNECT request: %v", err)
		http.Error(wr, "Can't satisfy CONNECT request", http.StatusBadGateway)
		return
	}

	if req.ProtoMajor == 0 || req.ProtoMajor == 1 {
		// Upgrade client connection
		localconn, _, err := hijack(wr)
		if err != nil {
			s.logger.Error("Can't hijack client connection: %v", err)
			http.Error(wr, "Can't hijack client connection", http.StatusInternalServerError)
			return
		}
		defer localconn.Close()

		// Inform client connection is built
		fmt.Fprintf(localconn, "HTTP/%d.%d 200 OK\r\n\r\n", req.ProtoMajor, req.ProtoMinor)

		proxy(req.Context(), localconn, conn)
	} else if req.ProtoMajor == 2 {
		wr.Header()["Date"] = nil
		wr.WriteHeader(http.StatusOK)
		flush(wr)
		proxyh2(req.Context(), req.Body, wr, conn)
	} else {
		s.logger.Error("Unsupported protocol version: %s", req.Proto)
		http.Error(wr, "Unsupported protocol version.", http.StatusBadRequest)
		return
	}
}

func (s *ProxyHandler) HandleRequest(wr http.ResponseWriter, req *http.Request, clientPair DialerClientPair) {
	httpTransport := &http.Transport{
		DialContext: clientPair.Dialer.DialContext,
	}

	// Prepare the request
	req.RequestURI = ""
	if req.ProtoMajor == 2 {
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
	}

	resp, err := httpTransport.RoundTrip(req)
	if err != nil {
		s.logger.Error("HTTP fetch error: %v", err)
		http.Error(wr, "Server Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	s.logger.Info("%v %v %v %v", req.RemoteAddr, req.Method, req.URL, resp.Status)
	delHopHeaders(resp.Header)
	copyHeader(wr.Header(), resp.Header)
	wr.WriteHeader(resp.StatusCode)
	flush(wr)
	copyBody(wr, resp.Body)
}

func (s *ProxyHandler) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	authHeader := req.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		s.logger.Info("Unauthorized")
		wr.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(wr, "Unauthorized", http.StatusUnauthorized)
		return
	}

	authParts := strings.SplitN(authHeader, " ", 2)
	if len(authParts) != 2 || authParts[0] != "Basic" {
		s.logger.Info("Invalid Authorization header")
		http.Error(wr, "Invalid Authorization header", http.StatusUnauthorized)
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(authParts[1])
	if err != nil {
		s.logger.Info("Invalid Base64 encoding")
		http.Error(wr, "Invalid Base64 encoding", http.StatusUnauthorized)
		return
	}

	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		s.logger.Info("Invalid credentials format")
		http.Error(wr, "Invalid credentials format", http.StatusUnauthorized)
		return
	}

	username, password := credentials[0], credentials[1]
	s.logger.Info("Username: %s, Password: %s", username, password)

	var clientPair *DialerClientPair
	s.mu.Lock()
	for i := range s.dialerClients {
		if s.dialerClients[i].Username == username && s.dialerClients[i].Password == password {
			clientPair = &s.dialerClients[i]
			break
		}
	}
	s.mu.Unlock()

	if clientPair == nil {
		s.logger.Info("Authentication failed for user: %s", username)
		http.Error(wr, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	s.logger.Info("Authentication successful for user: %s", username)

	isConnect := strings.ToUpper(req.Method) == "CONNECT"
	if (req.URL.Host == "" || req.URL.Scheme == "" && !isConnect) && req.ProtoMajor < 2 ||
		req.Host == "" && req.ProtoMajor == 2 {
		http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
		return
	}
	delHopHeaders(req.Header)
	if isConnect {
		s.HandleTunnel(wr, req, *clientPair)
	} else {
		s.HandleRequest(wr, req, *clientPair)
	}
}
