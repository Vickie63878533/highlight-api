package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/pbkdf2"
)

// --- 全局变量和常量 ---

const (
	highlightBaseURL = "https://chat-backend.highlightai.com"
	userAgent        = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Highlight/1.3.61 Chrome/132.0.6834.210 Electron/34.5.8 Safari/537.36"
)

var (
	accessTokens = &TokenCache{cache: make(map[string]AccessTokenInfo)}
	modelCache   = &ModelCache{cache: make(map[string]ModelInfo)}
)

// Hr 和 jr 的数据，直接从 TS 代码转换而来
var Hr = struct {
	R []int
	M []int
}{
	R: []int{87, 78, 72, 56, 79, 48, 122, 79, 107, 104, 82, 119, 51, 100, 78, 90, 85, 85, 69, 107, 90, 116, 87, 48, 108, 53, 83, 84, 70, 81, 121, 69},
	M: []int{27, 26, 25, 22, 24, 21, 17, 12, 30, 19, 20, 14, 31, 8, 18, 10, 13, 5, 29, 7, 16, 6, 28, 23, 9, 15, 4, 0, 11, 2, 3, 1},
}

var jr = struct {
	R []int
	M []int
}{
	R: []int{87, 90, 109, 107, 53, 105, 81, 89, 103, 107, 68, 49, 68, 105, 106, 77, 49, 106, 53, 78, 77, 78, 106, 106, 61, 77, 89, 51, 66, 79, 86, 89, 106, 65, 106, 52, 89, 77, 87, 106, 89, 122, 78, 90, 65, 89, 50, 105, 61, 90, 106, 66, 48, 53, 71, 89, 87, 52, 81, 84, 78, 90, 74, 78, 103, 50, 70, 79, 51, 50, 50, 77, 122, 108, 84, 81, 120, 90, 89, 89, 89, 79, 119, 122, 121, 108, 69, 77},
	M: []int{65, 20, 1, 6, 31, 63, 74, 12, 85, 78, 33, 3, 41, 19, 45, 52, 75, 21, 23, 16, 56, 36, 5, 71, 87, 68, 72, 15, 18, 32, 82, 8, 17, 54, 83, 35, 28, 48, 49, 77, 30, 25, 10, 38, 22, 50, 29, 11, 86, 64, 57, 70, 47, 67, 81, 44, 61, 7, 58, 13, 84, 76, 42, 24, 46, 37, 62, 80, 27, 51, 73, 34, 69, 39, 53, 2, 79, 60, 26, 0, 66, 40, 55, 9, 59, 43, 14, 4},
}

// --- 数据结构定义 ---

// UserInfo 结构对应于API Key中编码的用户信息
type UserInfo struct {
	RT         string `json:"rt"`
	UserID     string `json:"user_id"`
	Email      string `json:"email"`
	ClientUUID string `json:"client_uuid"`
}

// Message 结构用于聊天请求
type Message struct {
	Role       string      `json:"role"`
	Content    interface{} `json:"content"` // 可以是 string 或 OpenAIMessageContent[]
	ToolCallID string      `json:"tool_call_id,omitempty"`
	ToolCalls  []any       `json:"tool_calls,omitempty"`
}

// OpenAIMessageContent 结构
type OpenAIMessageContent struct {
	Type     string            `json:"type"`
	Text     string            `json:"text,omitempty"`
	ImageURL map[string]string `json:"image_url,omitempty"`
}

// OpenAITool 结构
type OpenAITool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
		Parameters  any    `json:"parameters,omitempty"`
	} `json:"function"`
}

// ChatCompletionRequest 结构
type ChatCompletionRequest struct {
	Messages []Message    `json:"messages"`
	Stream   bool         `json:"stream,omitempty"`
	Model    string       `json:"model,omitempty"`
	Tools    []OpenAITool `json:"tools,omitempty"`
}

// AccessTokenInfo 用于缓存 Access Token
type AccessTokenInfo struct {
	AccessToken string `json:"access_token"`
	ExpiresAt   int64  `json:"expires_at"`
}

// TokenCache 是一个线程安全的 AccessTokenInfo 缓存
type TokenCache struct {
	sync.RWMutex
	cache map[string]AccessTokenInfo
}

func (tc *TokenCache) Get(key string) (AccessTokenInfo, bool) {
	tc.RLock()
	defer tc.RUnlock()
	val, ok := tc.cache[key]
	return val, ok
}

func (tc *TokenCache) Set(key string, value AccessTokenInfo) {
	tc.Lock()
	defer tc.Unlock()
	tc.cache[key] = value
}

// ModelInfo 用于缓存模型信息
type ModelInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	IsFree   bool   `json:"isFree"`
}

// ModelCache 是一个线程安全的 ModelInfo 缓存
type ModelCache struct {
	sync.RWMutex
	cache map[string]ModelInfo
}

func (mc *ModelCache) Get(key string) (ModelInfo, bool) {
	mc.RLock()
	defer mc.RUnlock()
	val, ok := mc.cache[key]
	return val, ok
}

func (mc *ModelCache) Set(key string, value ModelInfo) {
	mc.Lock()
	defer mc.Unlock()
	mc.cache[key] = value
}

func (mc *ModelCache) Size() int {
	mc.RLock()
	defer mc.RUnlock()
	return len(mc.cache)
}

func (mc *ModelCache) Clear() {
	mc.Lock()
	defer mc.Unlock()
	mc.cache = make(map[string]ModelInfo)
}

func (mc *ModelCache) Entries() map[string]ModelInfo {
	mc.RLock()
	defer mc.RUnlock()
	// 返回一个副本以避免外部修改
	newMap := make(map[string]ModelInfo)
	for k, v := range mc.cache {
		newMap[k] = v
	}
	return newMap
}

// --- 加密和辅助函数 ---

// Ah 函数的 Go 实现
func Ah(n, e []int) []byte {
	t := make([]byte, len(n))
	for s := 0; s < len(e); s++ {
		t[e[s]] = byte(n[s])
	}
	return t
}

// reverseBytes 反转字节切片
func reverseBytes(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

// Fl 函数的 Go 实现
func Fl(n, e []int) (string, error) {
	t := Ah(n, e)
	s := string(t)
	o, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	i := reverseBytes(o)
	return string(i), nil
}

// Th 函数的 Go 实现
func Th(n string) ([]byte, error) {
	saltStr, err := Fl(Hr.R, Hr.M)
	if err != nil {
		return nil, err
	}
	salt := []byte(saltStr)
	return pbkdf2.Key([]byte(n), salt, 100000, 32, sha256.New), nil
}

// pkcs7Pad 实现 PKCS7 填充
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// kh 函数的 Go 实现
func kh(userId, clientUUID string, fixedIv []byte) (string, error) {
	e, err := Th(userId)
	if err != nil {
		return "", err
	}

	var t []byte
	if fixedIv != nil {
		t = fixedIv
	} else {
		t = make([]byte, 16)
		if _, err := rand.Read(t); err != nil {
			return "", err
		}
	}

	apiKey, err := Fl(jr.R, jr.M)
	if err != nil {
		return "", err
	}

	data := map[string]string{
		"userId":     userId,
		"clientUUID": clientUUID,
		"apiKey":     apiKey,
	}
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	paddedData := pkcs7Pad(jsonBytes, aes.BlockSize)

	block, err := aes.NewCipher(e)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCEncrypter(block, t)
	encrypted := make([]byte, len(paddedData))
	mode.CryptBlocks(encrypted, paddedData)

	tHex := hex.EncodeToString(t)
	encryptedHex := hex.EncodeToString(encrypted)

	return fmt.Sprintf("%s:%s", tHex, encryptedHex), nil
}

// H7t 函数的 Go 实现
func H7t(t int) (string, error) {
	randomBytes := make([]byte, t)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(randomBytes), nil
}

// getIdentifier 函数的 Go 实现
func getIdentifier(userId, clientUUID string) (string, error) {
	t, err := kh(userId, clientUUID, nil)
	if err != nil {
		return "", err
	}
	h, err := H7t(12)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%s", h, t), nil
}

// --- 认证和 API 调用逻辑 ---

// login 函数执行完整的登录流程
func login(code string) (*UserInfo, error) {
	log.Println("开始登录流程...")

	chromeDeviceID := uuid.New().String()
	deviceID := uuid.New().String()

	// 1. 交换 code
	exchangeBody, _ := json.Marshal(map[string]string{
		"code":              code,
		"amplitudeDeviceId": chromeDeviceID,
	})
	exchangeResp, err := http.Post(highlightBaseURL+"/api/v1/auth/exchange", "application/json", bytes.NewBuffer(exchangeBody))
	if err != nil {
		return nil, fmt.Errorf("交换 code 请求失败: %w", err)
	}
	defer exchangeResp.Body.Close()

	if exchangeResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(exchangeResp.Body)
		return nil, fmt.Errorf("交换 code 失败, 状态: %d, 响应: %s", exchangeResp.StatusCode, string(bodyBytes))
	}

	var exchangeData struct {
		Success bool `json:"success"`
		Data    struct {
			AccessToken  string `json:"accessToken"`
			RefreshToken string `json:"refreshToken"`
		} `json:"data"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(exchangeResp.Body).Decode(&exchangeData); err != nil {
		return nil, err
	}

	if !exchangeData.Success {
		return nil, fmt.Errorf("登录失败: %s", exchangeData.Error)
	}
	accessToken := exchangeData.Data.AccessToken
	refreshToken := exchangeData.Data.RefreshToken

	// 2. 注册客户端 (可选，失败不中断)
	clientBody, _ := json.Marshal(map[string]string{"client_uuid": deviceID})
	clientReq, _ := http.NewRequest("POST", highlightBaseURL+"/api/v1/users/me/client", bytes.NewBuffer(clientBody))
	clientReq.Header.Set("Content-Type", "application/json")
	clientReq.Header.Set("Authorization", "Bearer "+accessToken)
	clientResp, err := http.DefaultClient.Do(clientReq)
	if err != nil || clientResp.StatusCode != http.StatusOK {
		log.Printf("警告: 客户端注册失败，但继续执行。")
	}
	if clientResp != nil {
		clientResp.Body.Close()
	}

	// 3. 获取用户信息
	profileReq, _ := http.NewRequest("GET", highlightBaseURL+"/api/v1/auth/profile", nil)
	profileReq.Header.Set("Authorization", "Bearer "+accessToken)
	profileResp, err := http.DefaultClient.Do(profileReq)
	if err != nil {
		return nil, fmt.Errorf("获取用户信息请求失败: %w", err)
	}
	defer profileResp.Body.Close()

	if profileResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取用户信息失败, 状态: %d", profileResp.StatusCode)
	}

	var profileData struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(profileResp.Body).Decode(&profileData); err != nil {
		return nil, err
	}

	log.Printf("登录成功: %s %s", profileData.ID, profileData.Email)
	userInfo := &UserInfo{
		RT:         refreshToken,
		UserID:     profileData.ID,
		Email:      profileData.Email,
		ClientUUID: deviceID,
	}

	userInfoBytes, _ := json.Marshal(userInfo)
	apiKey := base64.StdEncoding.EncodeToString(userInfoBytes)
	log.Println("----API KEY----")
	log.Println(apiKey)
	log.Println("----API KEY----")

	return userInfo, nil
}

// parseApiKey 解码并解析 Base64 编码的 API Key
func parseApiKey(apiKeyBase64 string) (*UserInfo, error) {
	decoded, err := base64.StdEncoding.DecodeString(apiKeyBase64)
	if err != nil {
		return nil, err
	}
	var userInfo UserInfo
	err = json.Unmarshal(decoded, &userInfo)
	if err != nil {
		return nil, err
	}
	return &userInfo, nil
}

// parseJwtPayload 解析 JWT 的 payload 部分
func parseJwtPayload(jwtToken string) (map[string]interface{}, error) {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("无效的 JWT token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	err = json.Unmarshal(payload, &data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// refreshAccessToken 使用 refresh token 获取新的 access token
func refreshAccessToken(rt string) (string, error) {
	body, _ := json.Marshal(map[string]string{"refreshToken": rt})
	resp, err := http.Post(highlightBaseURL+"/api/v1/auth/refresh", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("刷新 token 失败, 状态: %d", resp.StatusCode)
	}

	var respJson struct {
		Success bool `json:"success"`
		Data    struct {
			AccessToken string `json:"accessToken"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respJson); err != nil {
		return "", err
	}

	if !respJson.Success {
		return "", errors.New("刷新 token 失败")
	}

	newAccessToken := respJson.Data.AccessToken
	payload, err := parseJwtPayload(newAccessToken)
	var expiresAt int64
	if err == nil && payload["exp"] != nil {
		if exp, ok := payload["exp"].(float64); ok {
			expiresAt = int64(exp)
			log.Printf("newAccessToken: %s, expiresAt: %d", newAccessToken, expiresAt)
		}
	} else {
		expiresAt = time.Now().Unix() + 3600 // 默认1小时
	}

	log.Printf("newAccessToken: %s", newAccessToken)

	accessTokens.Set(rt, AccessTokenInfo{
		AccessToken: newAccessToken,
		ExpiresAt:   expiresAt,
	})

	return newAccessToken, nil
}

// getAccessToken 从缓存获取或刷新 access token
func getAccessToken(rt string) (string, error) {
	tokenInfo, ok := accessTokens.Get(rt)
	currentTime := time.Now().Unix()

	if ok && tokenInfo.ExpiresAt > currentTime+60 {
		return tokenInfo.AccessToken, nil
	}

	return refreshAccessToken(rt)
}

// fetchModelsFromUpstream 从上游获取并缓存模型列表
func fetchModelsFromUpstream(accessToken string) error {
	req, _ := http.NewRequest("GET", highlightBaseURL+"/api/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取模型列表失败, 状态: %d", resp.StatusCode)
	}

	var respJson struct {
		Success bool `json:"success"`
		Data    []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Provider string `json:"provider"`
			Pricing  struct {
				IsFree bool `json:"isFree"`
			} `json:"pricing"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respJson); err != nil {
		return err
	}

	if !respJson.Success {
		return errors.New("获取模型数据失败")
	}

	modelCache.Clear()
	for _, model := range respJson.Data {
		modelCache.Set(model.Name, ModelInfo{
			ID:       model.ID,
			Name:     model.Name,
			Provider: model.Provider,
			IsFree:   model.Pricing.IsFree,
		})
	}
	return nil
}

// getModels 从缓存获取模型列表
func getModels(accessToken string) (map[string]ModelInfo, error) {
	if modelCache.Size() == 0 {
		if err := fetchModelsFromUpstream(accessToken); err != nil {
			return nil, err
		}
	}
	return modelCache.Entries(), nil
}

// formatMessagesToPrompt 将消息列表格式化为字符串
func formatMessagesToPrompt(messages []Message) string {
	var formattedMessages []string
	for _, message := range messages {
		var contentStr string
		if content, ok := message.Content.(string); ok {
			contentStr = content
		} else if contentArr, ok := message.Content.([]interface{}); ok {
			var texts []string
			for _, item := range contentArr {
				if itemMap, ok := item.(map[string]interface{}); ok {
					if text, ok := itemMap["text"].(string); ok {
						texts = append(texts, text)
					}
				}
			}
			contentStr = strings.Join(texts, "\n")
		}

		var parts []string
		if message.Role != "" {
			parts = append(parts, message.Role+":")
		}
		if contentStr != "" {
			parts = append(parts, contentStr)
		}
		if message.ToolCalls != nil {
			toolCallsJSON, _ := json.Marshal(message.ToolCalls)
			parts = append(parts, string(toolCallsJSON))
		}
		if message.ToolCallID != "" {
			parts = append(parts, fmt.Sprintf("tool_call_id: %s %s", message.ToolCallID, contentStr))
		}
		formattedMessages = append(formattedMessages, strings.Join(parts, " "))
	}
	return strings.Join(formattedMessages, "\n\n")
}

// --- HTTP 处理器 ---

// corsMiddleware 添加 CORS 头部并处理 OPTIONS 请求
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// writeErrorResponse 辅助函数，用于写入 JSON 错误响应
func writeErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// handleRoot 处理根路径，返回前端页面
func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	// HTML and JS code is embedded here as a string constant
	// (The full HTML from the prompt is stored in `htmlContent` variable below)
	fmt.Fprint(w, htmlContent)
}

// handleHealth 健康检查端点
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
	})
}

// handleLogin 处理登录请求
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if body.Code == "" {
		writeErrorResponse(w, "Missing code parameter", http.StatusBadRequest)
		return
	}

	userInfo, err := login(body.Code)
	if err != nil {
		writeErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(userInfo)
}

// authMiddleware 提取并验证 API Key
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeErrorResponse(w, "Missing authorization token", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		userInfo, err := parseApiKey(token)
		if err != nil || userInfo.RT == "" {
			writeErrorResponse(w, "Invalid authorization token", http.StatusUnauthorized)
			return
		}
		// 将 userInfo 存储在请求上下文中，以便后续处理器使用
		ctx := r.Context()
		r = r.WithContext(context.WithValue(ctx, "userInfo", userInfo))
		next.ServeHTTP(w, r)
	})
}

// handleModels 处理模型列表请求
func handleModels(w http.ResponseWriter, r *http.Request) {
	userInfo, ok := r.Context().Value("userInfo").(*UserInfo)
	if !ok {
		writeErrorResponse(w, "Internal server error: user info not found", http.StatusInternalServerError)
		return
	}

	accessToken, err := getAccessToken(userInfo.RT)
	if err != nil {
		writeErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	models, err := getModels(accessToken)
	if err != nil {
		writeErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var modelList []map[string]interface{}
	for modelName, modelInfo := range models {
		modelList = append(modelList, map[string]interface{}{
			"id":       modelName,
			"object":   "model",
			"created":  time.Now().Unix(),
			"owned_by": modelInfo.Provider,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"object": "list",
		"data":   modelList,
	})
}

// handleChatCompletions 处理聊天请求
func handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	userInfo, ok := r.Context().Value("userInfo").(*UserInfo)
	if !ok {
		writeErrorResponse(w, "Internal server error: user info not found", http.StatusInternalServerError)
		return
	}

	var reqData ChatCompletionRequest
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		writeErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if reqData.Messages == nil || len(reqData.Messages) == 0 {
		writeErrorResponse(w, "Missing 'messages' in request body", http.StatusBadRequest)
		return
	}

	if userInfo.UserID == "" || userInfo.ClientUUID == "" {
		writeErrorResponse(w, "Invalid authorization token - missing required fields", http.StatusUnauthorized)
		return
	}

	accessToken, err := getAccessToken(userInfo.RT)
	if err != nil {
		writeErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	models, err := getModels(accessToken)
	if err != nil {
		writeErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	modelName := reqData.Model
	if modelName == "" {
		modelName = "gpt-4o"
	}
	modelInfo, ok := models[modelName]
	if !ok {
		writeErrorResponse(w, fmt.Sprintf("Model '%s' not found", modelName), http.StatusBadRequest)
		return
	}

	prompt := formatMessagesToPrompt(reqData.Messages)
	identifier, err := getIdentifier(userInfo.UserID, userInfo.ClientUUID)
	if err != nil {
		writeErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tools := reqData.Tools
	if tools == nil {
		tools = make([]OpenAITool, 0) // 创建一个空的、非 nil 的切片
	}

	highlightData := map[string]interface{}{
		"prompt":          prompt,
		"attachedContext": []interface{}{},
		"modelId":         modelInfo.ID,
		"additionalTools": tools,
		"backendPlugins":  []interface{}{},
		"useMemory":       false,
		"useKnowledge":    false,
		"ephemeral":       false,
		"timezone":        "America/New_York",
	}

	highlightBody, _ := json.Marshal(highlightData)

	log.Printf("ReqData: %s", highlightBody)
	
	upstreamReq, _ := http.NewRequest("POST", highlightBaseURL+"/api/v1/chat", bytes.NewBuffer(highlightBody))
	upstreamReq.Header.Set("Content-Type", "application/json")
	upstreamReq.Header.Set("Accept", "*/*")
	upstreamReq.Header.Set("Authorization", "Bearer "+accessToken)
	upstreamReq.Header.Set("User-Agent", userAgent)
	upstreamReq.Header.Set("Identifier", identifier)

	upstreamResp, err := http.DefaultClient.Do(upstreamReq)
	if err != nil {
		writeErrorResponse(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer upstreamResp.Body.Close()

	if upstreamResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(upstreamResp.Body)
		log.Printf("Upstream error: %s", string(bodyBytes))
		writeErrorResponse(w, fmt.Sprintf("Upstream API returned status code %d", upstreamResp.StatusCode), http.StatusBadGateway)
		return
	}

	if reqData.Stream {
		// 流式响应
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
			return
		}

		responseID := "chatcmpl-" + uuid.New().String()
		created := time.Now().Unix()

		// 发送初始消息
		initialChunk := map[string]interface{}{
			"id":      responseID,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   modelName,
			"choices": []map[string]interface{}{{
				"index":         0,
				"delta":         map[string]string{"role": "assistant"},
				"finish_reason": nil,
			}},
		}
		initialChunkBytes, _ := json.Marshal(initialChunk)
		fmt.Fprintf(w, "data: %s\n\n", initialChunkBytes)
		flusher.Flush()

		scanner := bufio.NewScanner(upstreamResp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				data := strings.TrimPrefix(line, "data: ")
				var eventData struct {
					Type    string `json:"type"`
					Content string `json:"content"`
				}
				if err := json.Unmarshal([]byte(data), &eventData); err == nil && eventData.Type == "text" && eventData.Content != "" {
					chunkData := map[string]interface{}{
						"id":      responseID,
						"object":  "chat.completion.chunk",
						"created": created,
						"model":   modelName,
						"choices": []map[string]interface{}{{
							"index":         0,
							"delta":         map[string]string{"content": eventData.Content},
							"finish_reason": nil,
						}},
					}
					chunkBytes, _ := json.Marshal(chunkData)
					fmt.Fprintf(w, "data: %s\n\n", chunkBytes)
					flusher.Flush()
				}
			}
		}

		// 发送结束消息
		finalChunk := map[string]interface{}{
			"id":      responseID,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   modelName,
			"choices": []map[string]interface{}{{
				"index":         0,
				"delta":         map[string]interface{}{},
				"finish_reason": "stop",
			}},
		}
		finalChunkBytes, _ := json.Marshal(finalChunk)
		fmt.Fprintf(w, "data: %s\n\n", finalChunkBytes)
		fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()

	} else {
		// 非流式响应
		var fullResponseContent strings.Builder
		scanner := bufio.NewScanner(upstreamResp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				data := strings.TrimPrefix(line, "data: ")
				var eventData struct {
					Type    string `json:"type"`
					Content string `json:"content"`
				}
				if err := json.Unmarshal([]byte(data), &eventData); err == nil && eventData.Type == "text" {
					fullResponseContent.WriteString(eventData.Content)
				}
			}
		}

		responseID := "chatcmpl-" + uuid.New().String()
		responseData := map[string]interface{}{
			"id":      responseID,
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   modelName,
			"choices": []map[string]interface{}{{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": fullResponseContent.String(),
				},
				"finish_reason": "stop",
			}},
			"usage": map[string]int{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(responseData)
	}
}

// --- Main 函数 ---

func main() {
	// 命令行登录功能
	if len(os.Args) > 1 && os.Args[1] == "login" {
		if len(os.Args) < 3 {
			fmt.Println("使用方法: go run main.go login <code>")
			fmt.Println("浏览器打开: https://chat-backend.highlightai.com/api/v1/auth/signin?screenHint=sign-in")
			fmt.Println("完成登录后复制 code 参数值")
			os.Exit(1)
		}
		code := os.Args[2]
		_, err := login(code)
		if err != nil {
			log.Fatalf("登录失败: %v", err)
		}
		return
	}

	// HTTP 服务器
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// 创建认证路由
	authedMux := http.NewServeMux()
	authedMux.HandleFunc("/v1/models", handleModels)
	authedMux.HandleFunc("/v1/chat/completions", handleChatCompletions)

	// 创建主路由
	mainMux := http.NewServeMux()
	mainMux.HandleFunc("/", handleRoot)
	mainMux.HandleFunc("/health", handleHealth)
	mainMux.HandleFunc("/login", handleLogin)
	mainMux.Handle("/v1/", authMiddleware(authedMux))

	log.Printf("Highlight AI API 代理服务器启动在端口 %s", port)
	log.Printf("访问 http://localhost:%s/ 查看前端页面", port)
	log.Printf("健康检查: http://localhost:%s/health", port)

	// 应用 CORS 中间件
	handler := corsMiddleware(mainMux)

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatalf("无法启动服务器: %v", err)
	}
}

// --- 内嵌的前端 HTML ---
const htmlContent = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Highlight AI API</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: #f5f5f7;
            color: #1d1d1f;
            line-height: 1.6;
            font-size: 16px;
            -webkit-font-smoothing: antialiased;
            text-rendering: optimizeLegibility;
        }

        .container {
            max-width: 720px;
            margin: 0 auto;
            padding: 20px 16px;
        }

        .header {
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 1px solid #e5e5e7;
        }

        .header h1 {
            font-size: 36px;
            font-weight: 700;
            letter-spacing: -0.02em;
            color: #1d1d1f;
            margin-bottom: 12px;
        }

        .header p {
            font-size: 18px;
            color: #6e6e73;
            font-weight: 400;
        }

        .section {
            background: #ffffff;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
            border: 1px solid #e5e5e7;
        }

        .section-title {
            font-size: 20px;
            font-weight: 600;
            color: #1d1d1f;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .step-number {
            width: 28px;
            height: 28px;
            background: #1d1d1f;
            color: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            font-weight: 600;
        }

        .section-content {
            color: #6e6e73;
            font-size: 15px;
            line-height: 1.4;
            margin-bottom: 16px;
        }

        .url-box {
            background: #f5f5f7;
            border: 1px solid #d2d2d7;
            border-radius: 8px;
            padding: 12px;
            margin: 12px 0;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 13px;
            color: #1d1d1f;
            word-break: break-all;
            line-height: 1.3;
        }

        .form-group {
            margin: 16px 0;
        }

        .form-label {
            display: block;
            font-size: 15px;
            font-weight: 500;
            color: #1d1d1f;
            margin-bottom: 6px;
        }

        .form-input {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid #d2d2d7;
            border-radius: 8px;
            font-size: 15px;
            background: #ffffff;
            color: #1d1d1f;
            transition: border-color: 0.15s ease;
        }

        .form-input:focus {
            outline: none;
            border-color: #007aff;
        }

        .form-input::placeholder {
            color: #a1a1a6;
        }

        .btn {
            display: inline-block;
            width: 100%;
            padding: 12px 20px;
            background: #1d1d1f;
            color: #ffffff;
            text-decoration: none;
            font-size: 15px;
            font-weight: 500;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: background-color 0.15s ease;
            text-align: center;
        }

        .btn:hover {
            background: #424245;
        }

        .btn:disabled {
            background: #d2d2d7;
            color: #a1a1a6;
            cursor: not-allowed;
        }

        .btn-secondary {
            background: #f5f5f7;
            color: #1d1d1f;
            border: 1px solid #d2d2d7;
        }

        .btn-secondary:hover {
            background: #e5e5e7;
        }

        .btn-small {
            padding: 8px 16px;
            font-size: 14px;
            width: auto;
            display: inline-block;
        }

        .btn-test {
            background: #007aff;
            margin-left: 8px;
        }

        .btn-test:hover {
            background: #0056cc;
        }

        .loading {
            display: none;
            text-align: center;
            padding: 16px;
            color: #6e6e73;
            font-size: 15px;
        }

        .loading-spinner {
            width: 16px;
            height: 16px;
            border: 2px solid #d2d2d7;
            border-top: 2px solid #1d1d1f;
            border-radius: 50%;
            display: inline-block;
            animation: spin 1s linear infinite;
            margin-right: 8px;
            vertical-align: middle;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .result {
            margin-top: 16px;
            padding: 16px;
            border-radius: 8px;
            display: none;
        }

        .result.success {
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            color: #166534;
        }

        .result.error {
            background: #fef2f2;
            border: 1px solid #fecaca;
            color: #dc2626;
        }

        .result h4 {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 8px;
        }

        .api-key-section {
            margin-top: 16px;
            padding: 16px;
            background: #f8f9fa;
            border-radius: 8px;
            border: 1px solid #e5e5e7;
        }

        .api-key-label {
            font-weight: 600;
            margin-bottom: 8px;
            color: #1d1d1f;
            font-size: 14px;
        }

        .api-key-box {
            background: #ffffff;
            border: 1px solid #d2d2d7;
            border-radius: 6px;
            padding: 12px;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 12px;
            word-break: break-all;
            color: #1d1d1f;
            margin-bottom: 8px;
        }

        .copy-btn {
            background: #007aff;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
        }

        .copy-btn:hover {
            background: #0056cc;
        }

        .success-message {
            margin-top: 16px;
            padding: 16px;
            background: #f0fdf4;
            border-radius: 8px;
            border: 1px solid #bbf7d0;
        }

        .success-title {
            font-weight: 600;
            color: #166534;
            margin-bottom: 6px;
            font-size: 14px;
        }

        .success-content {
            color: #166534;
            line-height: 1.4;
            font-size: 14px;
        }

        .success-content code {
            background: #ffffff;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 12px;
            border: 1px solid #bbf7d0;
        }

        .info-section {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 16px;
            margin-top: 16px;
            border: 1px solid #e5e5e7;
        }

        .info-title {
            font-size: 16px;
            font-weight: 600;
            color: #1d1d1f;
            margin-bottom: 12px;
        }

        .models-grid {
            display: grid;
            gap: 8px;
            margin-top: 12px;
        }

        .model-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            background: #ffffff;
            border: 1px solid #e5e5e7;
            border-radius: 6px;
        }

        .model-name {
            font-weight: 500;
            color: #1d1d1f;
            font-size: 14px;
        }

        .model-provider {
            font-size: 12px;
            color: #6e6e73;
        }

        .input-row {
            display: flex;
            gap: 8px;
            align-items: stretch;
        }

        .input-row .form-input {
            flex: 1;
        }

        .input-row .btn {
            height: auto;
            min-height: 44px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        @media (max-width: 768px) {
            .container {
                padding: 16px 12px;
            }

            .header h1 {
                font-size: 28px;
            }

            .header p {
                font-size: 16px;
            }

            .section {
                padding: 16px;
            }

            .input-row {
                flex-direction: column;
                gap: 8px;
            }

            .btn-small {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Highlight 2 API</h1>
        </div>

        <div class="info-section">
            <div class="info-title">支持的模型</div>
            <div id="modelsList">
                <div style="text-align: center; color: #6e6e73; padding: 20px;">
                    请先获取 API Key 以查看可用模型
                </div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">
                <span class="step-number">1</span>
                API Key 有效性检测
            </div>
            <div class="section-content">
                您可以使用现有的 API Key，或者通过登录生成新的 API Key：
            </div>

            <div class="form-group">
                <label class="form-label" for="apiKeyInput">API Key</label>
                <div class="input-row">
                    <input
                        type="text"
                        id="apiKeyInput"
                        class="form-input"
                        placeholder="粘贴您的 API Key 或点击下方生成新的"
                    />
                    <button class="btn btn-small btn-test" onclick="testApiKey()">
                        测试并获取可用模型
                    </button>
                </div>
            </div>

            <div class="result" id="testResult">
                <div id="testResultContent"></div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">
                <span class="step-number">2</span>
                生成新的 API Key
            </div>
            <div class="section-content">
                如果您没有 API Key，请通过登录生成：
            </div>
            <div class="url-box">
                https://chat-backend.highlightai.com/api/v1/auth/signin?screenHint=sign-in
            </div>
            <button class="btn btn-secondary" onclick="openLoginPage()">
                打开登录页面
            </button>

            <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 12px; margin: 12px 0; color: #856404; font-size: 14px;">
                <strong>重要提示：</strong><br>
                1. 点击上方按钮打开登录页面<br>
                2. 完成登录后，浏览器会跳转到新页面<br>
                3. 在浏览器地址栏中找到类似这样的链接：<br>
                <code style="background: #fff; padding: 2px 4px; border-radius: 3px;">https://highlightai.com/deeplink?code=01CKIO2YTC359TRVJ1QVNQP21A</code><br>
                4. 复制 <strong>code=</strong> 后面的值（如：01CKIO2YTC359TRVJ1QVNQP21A）<br>
                5. 粘贴到下方输入框中
            </div>

            <div class="form-group">
                <label class="form-label" for="codeInput">授权代码（浏览器地址栏中 code= 后面的值）</label>
                <input
                    type="text"
                    id="codeInput"
                    class="form-input"
                    placeholder="例如：01CKIO2YTC359TRVJ1QVNQP21A"
                />
            </div>

            <button class="btn" onclick="login()" id="loginBtn">
                生成 API Key
            </button>

            <div class="loading" id="loading">
                <span class="loading-spinner"></span>
                正在处理...
            </div>
        </div>

        <div class="result" id="result">
            <div id="resultContent"></div>
        </div>

        <div class="info-section">
            <div class="info-title">API 端点</div>
            <div style="font-size: 14px; color: #6e6e73; line-height: 1.5;">
                <strong>模型列表:</strong> GET /v1/models<br>
                <strong>请求聊天:</strong> POST /v1/chat/completions<br>
            </div>
        </div>

        <div style="text-align: center; margin-top: 40px; padding: 20px; border-top: 1px solid #e5e5e7;">
            <div style="color: #6e6e73; font-size: 14px; margin-bottom: 8px;">
                项目开源 · 由 <strong>三文鱼</strong> 开发
            </div>
            <div style="margin-bottom: 12px;">
                <a href="https://linux.do/u/462642146/summary" target="_blank" style="color: #007aff; text-decoration: none; font-size: 14px;">
                    🐟 Linux DO @三文鱼
                </a>
            </div>
            <div style="color: #a1a1a6; font-size: 12px;">
                感谢使用 Highlight 2 API 代理服务
            </div>
        </div>
    </div>

    <script>
        function openLoginPage() {
            window.open('https://chat-backend.highlightai.com/api/v1/auth/signin?screenHint=sign-in', '_blank');
        }

        async function login() {
            const codeInput = document.getElementById('codeInput');
            const loginBtn = document.getElementById('loginBtn');
            const loading = document.getElementById('loading');
            const result = document.getElementById('result');
            const resultContent = document.getElementById('resultContent');

            const code = codeInput.value.trim();
            if (!code) {
                showResult('error', '<h4>错误</h4><p>请输入授权代码</p>');
                return;
            }

            loginBtn.disabled = true;
            loading.style.display = 'block';
            result.style.display = 'none';

            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code })
                });

                const data = await response.json();

                if (response.ok) {
                    const apiKey = btoa(JSON.stringify(data));
                    showResult('success',
                        '<h4>登录成功</h4>' +
                        '<p><strong>用户：</strong>' + data.email + '</p>' +
                        '<p><strong>用户 ID：</strong>' + data.user_id + '</p>' +
                        '<div class="api-key-section">' +
                        '    <div class="api-key-label">您的 API Key</div>' +
                        '    <div class="api-key-box" id="apiKeyText">' + apiKey + '</div>' +
                        '    <button class="copy-btn" onclick="copyApiKey()">复制 API Key</button>' +
                        '</div>' +
                        '<div class="success-message">' +
                        '    <div class="success-title">设置完成</div>' +
                        '    <div class="success-content">' +
                        '        您现在可以使用此 API Key 调用 OpenAI 兼容的接口。<br>' +
                        '        请在 Authorization header 中添加：<br>' +
                        '        <code>Authorization: Bearer YOUR_API_KEY</code>' +
                        '    </div>' +
                        '</div>'
                    );
                    await loadModels(apiKey);
                } else {
                    showResult('error', '<h4>登录失败</h4><p>' + data.error + '</p>');
                }
            } catch (error) {
                showResult('error', '<h4>请求失败</h4><p>' + error.message + '</p>');
            } finally {
                loginBtn.disabled = false;
                loading.style.display = 'none';
            }
        }

        function showResult(type, content) {
            const result = document.getElementById('result');
            const resultContent = document.getElementById('resultContent');
            result.className = 'result ' + type;
            resultContent.innerHTML = content;
            result.style.display = 'block';
            result.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }

        function copyApiKey() {
            const apiKeyText = document.getElementById('apiKeyText').textContent;
            navigator.clipboard.writeText(apiKeyText).then(() => {
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = '已复制';
                setTimeout(() => {
                    btn.textContent = originalText;
                }, 2000);
            }).catch(err => {
                console.error('复制失败:', err);
                const selection = window.getSelection();
                const range = document.createRange();
                range.selectNodeContents(document.getElementById('apiKeyText'));
                selection.removeAllRanges();
                selection.addRange(range);
            });
        }

        async function testApiKey() {
            const apiKeyInput = document.getElementById('apiKeyInput');
            const apiKey = apiKeyInput.value.trim();
            if (!apiKey) {
                showTestResult('error', '<h4>错误</h4><p>请先输入 API Key</p>');
                return;
            }

            try {
                const response = await fetch('/v1/models', {
                    headers: { 'Authorization': 'Bearer ' + apiKey }
                });

                if (response.ok) {
                    const data = await response.json();
                    showTestResult('success', '<h4>API Key 有效</h4><p>成功获取到 ' + data.data.length + ' 个可用模型</p>');
                    displayModels(data.data);
                } else {
                    const errorData = await response.json();
                    showTestResult('error', '<h4>API Key 无效</h4><p>' + (errorData.error || '验证失败') + '</p>');
                }
            } catch (error) {
                showTestResult('error', '<h4>测试失败</h4><p>' + error.message + '</p>');
            }
        }

        function showTestResult(type, content) {
            const testResult = document.getElementById('testResult');
            const testResultContent = document.getElementById('testResultContent');
            testResult.className = 'result ' + type;
            testResultContent.innerHTML = content;
            testResult.style.display = 'block';
        }

        async function loadModels(apiKey) {
            const modelsList = document.getElementById('modelsList');
            modelsList.innerHTML =
                '<div style="text-align: center; color: #6e6e73; padding: 16px;">' +
                '    <span class="loading-spinner" style="margin-right: 8px;"></span>' +
                '    正在加载模型列表...' +
                '</div>';

            try {
                const response = await fetch('/v1/models', {
                    headers: { 'Authorization': 'Bearer ' + apiKey }
                });

                if (response.ok) {
                    const data = await response.json();
                    displayModels(data.data);
                } else {
                    modelsList.innerHTML =
                        '<div style="text-align: center; color: #dc2626; padding: 16px;">' +
                        '    加载失败，请检查 API Key' +
                        '</div>';
                }
            } catch (error) {
                modelsList.innerHTML =
                    '<div style="text-align: center; color: #dc2626; padding: 16px;">' +
                    '    网络错误: ' + error.message +
                    '</div>';
            }
        }

        function displayModels(models) {
            const modelsList = document.getElementById('modelsList');
            if (!models || models.length === 0) {
                modelsList.innerHTML =
                    '<div style="text-align: center; color: #6e6e73; padding: 16px;">' +
                    '    未找到可用模型' +
                    '</div>';
                return;
            }

            const modelsByProvider = models.reduce((acc, model) => {
                const provider = model.owned_by || 'Unknown';
                if (!acc[provider]) acc[provider] = [];
                acc[provider].push(model);
                return acc;
            }, {});

            let html = '';
            for (const provider in modelsByProvider) {
                const providerModels = modelsByProvider[provider];
                html +=
                    '<div style="margin-bottom: 16px;">' +
                    '    <div style="font-weight: 600; color: #1d1d1f; margin-bottom: 8px; font-size: 14px;">' +
                         provider + ' (' + providerModels.length + ' 个模型)' +
                    '    </div>' +
                    '    <div class="models-grid">';

                providerModels.forEach(model => {
                    html +=
                        '<div class="model-item">' +
                        '    <div>' +
                        '        <div class="model-name">' + model.id + '</div>' +
                        '        <div class="model-provider">' + provider + '</div>' +
                        '    </div>' +
                        "    <button onclick=\"copyModelName('" + model.id + "')\" class=\"btn btn-small copy-btn\">" +
                        '        复制' +
                        '    </button>' +
                        '</div>';
                });

                html += '</div></div>';
            }
            modelsList.innerHTML = html;
        }

        function copyModelName(modelName) {
            navigator.clipboard.writeText(modelName).then(() => {
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = '已复制';
                btn.style.background = '#bbf7d0';
                btn.style.color = '#166534';
                setTimeout(() => {
                    btn.textContent = originalText;
                    btn.style.background = '#007aff';
                    btn.style.color = 'white';
                }, 1500);
            }).catch(err => {
                console.error('复制失败:', err);
            });
        }

        document.addEventListener('DOMContentLoaded', function() {
            const apiKeyInput = document.getElementById('apiKeyInput');
            apiKeyInput.addEventListener('input', function() {
                const apiKey = this.value.trim();
                if (apiKey) {
                    loadModels(apiKey);
                } else {
                    const modelsList = document.getElementById('modelsList');
                    modelsList.innerHTML =
                        '<div style="text-align: center; color: #6e6e73; padding: 20px;">' +
                        '    请先获取 API Key 以查看可用模型' +
                        '</div>';
                }
            });

            document.getElementById('codeInput').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') login();
            });
            document.getElementById('apiKeyInput').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') testApiKey();
            });
        });
    </script>
</body>
</html>
`
