package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/alibaba/higress/plugins/wasm-go/extensions/ai-proxy/util"
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	proxy_wasm "github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
)

var _ providerInitializer = (*cozeProviderInitializer)(nil)
var _ Provider = (*cozeProvider)(nil)

const (
	cozeChatCompletionPath = "/v3/chat"
)

// ========================================
// Coze API 结构体定义开始
// ========================================

type CozeEnterMessageType string

const (
	CozeEnterMessageTypeQuestion        CozeEnterMessageType = "question"      // 用户输入内容。
	CozeEnterMessageTypeAnswer          CozeEnterMessageType = "answer"        // Bot 返回给用户的消息内容，支持增量返回。如果工作流绑定了 message 节点，可能会存在多 answer 场景，此时可以用流式返回的结束标志来判断所有 answer 完成。
	CozeEnterMessageTypeFunctionCall    CozeEnterMessageType = "function_call" // Bot 对话过程中调用函数（function call）的中间结果。
	CozeEnterMessageTypeToolOutput      CozeEnterMessageType = "tool_output"   // 调用工具 （function call）后返回的结果。
	CozeEnterMessageTypeToolResponse    CozeEnterMessageType = "tool_response" // 调用工具 （function call）后返回的结果。
	CozeEnterMessageTypeFollowUp        CozeEnterMessageType = "follow_up"     // 如果在 Bot 上配置打开了用户问题建议开关，则会返回推荐问题相关的回复内容。不支持在请求中作为入参。
	CozeEnterMessageTypeGenerateVerbose CozeEnterMessageType = "verbose"       // 多 answer 场景下，服务端会返回一个 verbose 包，对应的 content 为 JSON 格式，content.msg_type =generate_answer_finish 代表全部 answer 回复完成。不支持在请求中作为入参。
)

type CozeRole string

const (
	CozeRoleUser      CozeRole = "user"
	CozeRoleAssistant CozeRole = "assistant"
)

type CozeContentType string

const (
	CozeContentTypeText         CozeContentType = "text"          // 文本。
	CozeContentTypeObjectString CozeContentType = "object_string" // 即文本和文件的组合、文本和图片的组合。
	CozeContentTypeCard         CozeContentType = "card"          // 卡片。此枚举值仅在接口响应中出现，不支持作为入参。
)

type CozeChatRequest struct {
	// 要进行会话聊天的 Bot ID。
	// 进入 Bot 的 开发页面，开发页面 URL 中 bot 参数后的数字就是 Bot ID。
	// 例如https://www.coze.cn/space/341****/bot/73428668*****，bot ID 为73428668*****。
	BotId string `json:"bot_id"`
	// 标识当前与 Bot 交互的用户，由使用方自行定义、生成与维护。
	// user_id 用于标识对话中的不同用户，不同的 user_id，其对话的上下文消息、数据库等对话记忆数据互相隔离。
	// 如果不需要用户数据隔离，可将此参数固定为一个任意字符串，例如 123，abc 等。
	UserId string `json:"user_id,omitempty"`
	// 对话的附加信息。你可以通过此字段传入历史消息和本次对话中用户的问题。数组长度限制为 100，即最多传入 100 条消息。
	// 若未设置 additional_messages，Bot 收到的消息只有会话中已有的消息内容，其中最后一条作为本次对话的用户输入，其他内容均为本次对话的上下文。
	// 若设置了 additional_messages，Bot 收到的消息包括会话中已有的消息和 additional_messages 中添加的消息
	// 其中 additional_messages 最后一条消息会作为本次对话的用户输入，其他内容均为本次对话的上下文。
	// 消息结构可参考EnterMessage Object，具体示例可参考 https://www.coze.cn/docs/developer_guides/chat_v3#2bb94adb。
	AdditionMessages []*CozeEnterMessage `json:"additional_messages,omitempty"`
	Steam            bool                `json:"stream"`
	// Bot 中定义的变量。在 Bot prompt 中设置变量 {{key}} 后，可以通过该参数传入变量值，同时支持 Jinja2 语法。
	CustomVariables map[string]string `json:"custom_variables,omitempty"`
	// 是否保存本次对话记录。
	//  * true：（默认）会话中保存本次对话记录，包括 additional_messages 中指定的所有消息、本次对话的模型回复结果、模型执行中间结果。
	//  * false：会话中不保存本次对话记录，后续也无法通过任何方式查看本次对话信息、消息详情。在同一个会话中再次发起对话时，本次会话也不会作为上下文传递给模型。
	// 非流式响应下（stream=false），此参数必须设置为 true，即保存本次对话记录，否则无法查看对话状态和模型回复。
	AutoSaveHistory bool `json:"auto_save_history,omitempty"`
	//	创建消息时的附加消息，获取消息时也会返回此附加消息。
	// 自定义键值对，应指定为 Map 对象格式。长度为 16 对键值对，其中键（key）的长度范围为 1～64 个字符，值（value）的长度范围为 1～512 个字符。
	MetaData map[string]string `json:"meta_data,omitempty"`
}

type CozeEnterMessage struct {
	// 发送这条消息的实体。取值：
	//  * user：代表该条消息内容是用户发送的。
	//  * assistant：代表该条消息内容是 Bot 发送的。
	Role CozeRole `json:"role"`
	// 仅发起会话（v3）接口支持将此参数作为入参，且：
	//  * 如果 autoSaveHistory=true，type 支持设置为 question 或 answer。
	//  * 如果 autoSaveHistory=false，type 支持设置为 question、answer、function_call、tool_output/tool_response。
	//
	// 其中，type=question 只能和 role=user 对应，即仅用户角色可以且只能发起 question 类型的消息。详细说明可参考消息 type 说明。
	Type CozeEnterMessageType `json:"type,omitempty"`
	// 消息的内容，支持纯文本、多模态（文本、图片、文件混合输入）、卡片等多种类型的内容。
	//
	// content_type 为 object_string 时，content 为 object_string object 数组序列化之后的 JSON String，详细说明可参考 object_string object。
	//
	// 当 content_type = text 时，content 为普通文本，例如 "content" :"Hello!"。
	Content string `json:"content,omitempty"`
	// 消息内容的类型，支持设置为：
	//  * text：文本。
	//  * object_string：多模态内容，即文本和文件的组合、文本和图片的组合。
	//  * card：卡片。此枚举值仅在接口响应中出现，不支持作为入参。
	//  * content 不为空时，此参数为必选。
	ContentType CozeContentType `json:"content_type,omitempty"`
	// 创建消息时的附加消息，获取消息时也会返回此附加消息。
	//
	// 自定义键值对，应指定为 Map 对象格式。长度为 16 对键值对，其中键（key）的长度范围为 1～64 个字符，值（value）的长度范围为 1～512 个字符。
	MetaData map[string]string `json:"meta_data,omitempty"`
}

type CozeObjectString struct {
	// 多模态消息内容类型，支持设置为：
	//  * text：文本类型。
	//  * file：文件类型。
	//  * image：图片类型。
	Type string `json:"type"`
	// 文本内容。
	Text string `json:"text"`
	// 文件或图片内容的 ID。
	//  * 必须是当前账号上传的文件 ID，上传方式可参考 https://www.coze.cn/docs/developer_guides/upload_files 。
	//  * 在 type 为 file 或 image 时，file_id 和 file_url 应至少指定一个。
	FileId string `json:"file_id"`
	// 文件或图片内容的在线地址。必须是可公共访问的有效地址。
	//
	// 在 type 为 file 或 image 时，file_id 和 file_url 应至少指定一个。
	FileUrl string `json:"file_url"`
}

type CozeConversationObject struct {
	Id        string `json:"id"`
	CreatedAt string `json:"created_at"` // 会话创建的时间。格式为 10 位的 UnixTime 时间戳，单位为秒。
	MetaData  string `json:"meta_data"`
}

type CozeChatResponse[T any] struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data T      `json:"data"`
}

type CozeRetrieveChatData struct {
	BotID          string `json:"bot_id"`
	CompletedAt    int64  `json:"completed_at"`
	ConversationID string `json:"conversation_id"`
	CreatedAt      int64  `json:"created_at"`
	ID             string `json:"id"`
	RequiredAction struct {
		SubmitToolOutputs struct {
			ToolCalls []struct {
				Function struct {
					Arguments string `json:"arguments"`
					Name      string `json:"name"`
				} `json:"function"`
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"tool_calls"`
		} `json:"submit_tool_outputs"`
		Type string `json:"type"`
	} `json:"required_action"`
	Status string `json:"status"`
}

type CozeChatMessagesData struct {
	BotID          string               `json:"bot_id"`
	Content        string               `json:"content"`
	ContentType    string               `json:"content_type"`
	ConversationID string               `json:"conversation_id"`
	ID             string               `json:"id"`
	Role           CozeRole             `json:"role"`
	Type           CozeEnterMessageType `json:"type"`
}

type CozeChatReqData struct {
	BotID          string            `json:"bot_id"`
	CompletedAt    int64             `json:"completed_at"`
	ConversationID string            `json:"conversation_id"`
	CreatedAt      int64             `json:"created_at"`
	ID             string            `json:"id"`
	MetaData       map[string]string `json:"meta_data"`
	Status         string            `json:"status"`
	Usage          struct {
		InputCount  int64 `json:"input_count"`
		OutputCount int64 `json:"output_count"`
		TokenCount  int64 `json:"token_count"`
	} `json:"usage"`
}

type cbData struct {
	statusCode      int
	responseHeaders http.Header
	responseBody    []byte
}

// ========================================
// Coze API 结构体定义结束
// ========================================

// ========================================
// Coze API 工具函数定义开始
// ========================================

func (c *cozeProvider) SendHttpRequest(method, path string, headers, params [][2]string, body []byte) ([]byte, error) {
	resp := make(chan cbData, 1)
	defer close(resp)

	// 编译params
	q := make(url.Values)
	for _, p := range params {
		q.Add(p[0], p[1])
	}
	path += "?" + q.Encode()

	err := c.client.Call(method, path, headers, body, func(statusCode int, responseHeaders http.Header, responseBody []byte) {
		// 复制一份原始数据防止被修改
		rh := make(http.Header)
		for k, v := range responseHeaders {
			rh[k] = v
		}
		rb := make([]byte, len(responseBody))
		copy(rb, responseBody)

		resp <- cbData{
			statusCode:      statusCode,
			responseHeaders: rh,
			responseBody:    rb,
		}
	})
	if err != nil {
		return nil, err
	}

	r := <-resp
	if r.statusCode != http.StatusOK {
		return nil, fmt.Errorf("http request failed, status code: %d", r.statusCode)
	}
	return r.responseBody, nil
}

func (c *cozeProvider) CozeGetChatRetrieve(host, accessToken, conversationId, chatId string) (*CozeChatResponse[CozeRetrieveChatData], error) {
	url := fmt.Sprintf("https://%s/v3/chat/retrieve", host)
	headers := [][2]string{
		{"Authorization", "Bearer " + accessToken},
		{"Content-Type", "application/json"},
	}
	params := [][2]string{
		{"conversation_id", conversationId},
		{"chat_id", chatId},
	}
	resp, err := c.SendHttpRequest(http.MethodGet, url, headers, params, nil)
	if err != nil {
		return nil, err
	}

	var response CozeChatResponse[CozeRetrieveChatData]
	if err := json.Unmarshal(resp, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// list_chat_messages
func (c *cozeProvider) CozeListChatMessages(host, accessToken, chatId, conversationId string) (*CozeChatResponse[[]CozeChatMessagesData], error) {
	url := fmt.Sprintf("https://%s/v3/chat/message/list", host)
	headers := [][2]string{
		{"Authorization", "Bearer " + accessToken},
		{"Content-Type", "application/json"},
	}
	params := [][2]string{
		{"conversation_id", conversationId},
		{"chat_id", chatId},
	}

	resp, err := c.SendHttpRequest(http.MethodPost, url, headers, params, nil)
	if err != nil {
		return nil, err
	}

	var response CozeChatResponse[[]CozeChatMessagesData]
	if err := json.Unmarshal(resp, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// ========================================
// Coze API 工具函数定义结束
// ========================================

// ========================================
// Coze 插件实现开始
// ========================================

type cozeProviderInitializer struct {
}

func (c *cozeProviderInitializer) ValidateConfig(config ProviderConfig) error {
	if config.apiTokens == nil || len(config.apiTokens) == 0 {
		return errors.New("no apiToken found in provider config")
	}

	if config.cozeBotId == "" {
		return errors.New("no cozeBotId found in provider config")
	}

	return nil
}

func (c *cozeProviderInitializer) CreateProvider(config ProviderConfig) (Provider, error) {
	return &cozeProvider{
		config: config,
		client: wrapper.NewClusterClient(wrapper.RouteCluster{
			Host: config.cozeApiDomain,
		}),
		contextCache: createContextCache(&config),
	}, nil
}

type cozeProvider struct {
	config       ProviderConfig
	client       wrapper.HttpClient
	contextCache *contextCache
}

func (c *cozeProvider) GetProviderType() string {
	return providerTypeCoze
}

func (c *cozeProvider) OnRequestHeaders(ctx wrapper.HttpContext, apiName ApiName, log wrapper.Log) (types.Action, error) {
	if apiName != ApiNameChatCompletion {
		return types.ActionContinue, errUnsupportedApiName
	}

	accessToken := c.config.GetRandomToken()
	if accessToken == "" {
		return types.ActionContinue, errors.New("no available access token")
	}
	log.Debugf("accessToken: %s", accessToken)
	ctx.SetContext("cozeRequestAccessToken", accessToken)

	_ = util.OverwriteRequestPath(cozeChatCompletionPath)
	_ = util.OverwriteRequestHost(c.config.cozeApiDomain)
	_ = util.OverwriteRequestAuthorization("Bearer " + accessToken)

	_ = proxy_wasm.RemoveHttpRequestHeader("Accept-Encoding")
	_ = proxy_wasm.RemoveHttpRequestHeader("Content-Length")
	return types.HeaderStopIteration, nil
}

func (c *cozeProvider) buildCozeTextGenerationRequest(rawReq *chatCompletionRequest, cozeReq *CozeChatRequest) error {
	cozeMessage := make([]*CozeEnterMessage, 0, len(rawReq.Messages))
	for _, message := range rawReq.Messages {
		var role CozeRole
		msgType := CozeEnterMessageTypeQuestion
		switch message.Role {
		case "user":
			role = CozeRoleUser
		case "assistant":
			msgType = CozeEnterMessageTypeAnswer
			role = CozeRoleAssistant
		default:
			return fmt.Errorf("unsupported role: %s", message.Role)
		}

		if !message.IsStringContent() {
			return fmt.Errorf("unsupported msg type")
		}

		cozeMessage = append(cozeMessage, &CozeEnterMessage{
			Role:        role,
			Type:        msgType,
			Content:     message.StringContent(),
			ContentType: CozeContentTypeText,
		})
	}

	cozeReq.AdditionMessages = cozeMessage

	return nil
}

func (c *cozeProvider) OnRequestBody(ctx wrapper.HttpContext, apiName ApiName, body []byte, log wrapper.Log) (types.Action, error) {
	if apiName != ApiNameChatCompletion {
		return types.ActionContinue, errUnsupportedApiName
	}

	request := &chatCompletionRequest{}
	if err := decodeChatCompletionRequest(body, request); err != nil {
		return types.ActionContinue, err
	}

	userId := sha256.New()
	userId.Write([]byte(request.User))
	cozeRequest := &CozeChatRequest{
		BotId:  c.config.cozeBotId,
		UserId: hex.EncodeToString(userId.Sum(nil)),
	}

	// stream check
	streaming := request.Stream
	if streaming {
		cozeRequest.Steam = true
	}

	// send request
	if err := c.buildCozeTextGenerationRequest(request, cozeRequest); err != nil {
		log.Errorf("failed to build coze request: %v", err)
		_ = util.SendResponse(500, "ai-proxy.coze.build_req_failed", util.MimeTypeTextPlain, fmt.Sprintf("failed to build coze request: %v", err))
		return types.ActionPause, nil
	}
	log.Infof("req %s", fmt.Sprintf("%s %s://%s%s", ctx.Method(), ctx.Scheme(), ctx.Host(), ctx.Path()))
	if err := replaceJsonRequestBody(cozeRequest, log); err != nil {
		_ = util.SendResponse(500, "ai-proxy.coze.insert_ctx_failed", util.MimeTypeTextPlain, fmt.Sprintf("failed to replace request body: %v", err))
		return types.ActionPause, err
	}

	return types.ActionContinue, nil
}

func (c *cozeProvider) OnResponseHeaders(ctx wrapper.HttpContext, apiName ApiName, log wrapper.Log) (types.Action, error) {
	log.Infof("OnResponseHeaders req %s", fmt.Sprintf("%s %s://%s%s", ctx.Method(), ctx.Scheme(), ctx.Host(), ctx.Path()))
	log.Infof("protocol: %s", c.config.protocol)
	log.Infof("apiName: %s", apiName)
	if c.config.protocol == protocolOriginal {
		ctx.DontReadResponseBody()
		return types.ActionContinue, nil
	}
	// _ = proxy_wasm.RemoveHttpResponseHeader("Content-Length")
	return types.ActionContinue, nil
}

func (c *cozeProvider) OnResponseBody(ctx wrapper.HttpContext, apiName ApiName, body []byte, log wrapper.Log) (types.Action, error) {
	if apiName != ApiNameChatCompletion {
		return types.ActionContinue, nil
	}

	accessToken := ctx.GetContext("cozeRequestAccessToken")
	if v, ok := accessToken.(string); !ok || v == "" {
		return types.ActionContinue, errors.New("no available access token")
	}

	log.Infof("resp %s", fmt.Sprintf("%s %s://%s%s", ctx.Method(), ctx.Scheme(), ctx.Host(), ctx.Path()))
	log.Infof("protocol: %s", c.config.protocol)
	log.Infof("apiName: %s", apiName)
	log.Infof("body: %s", string(body))
	log.Infof("accessToken: %s", accessToken)

	chatResp := &CozeChatResponse[CozeChatReqData]{}
	if err := json.Unmarshal(body, &chatResp); err != nil {
		log.Errorf("failed to unmarshal response: %v", err)
		_ = util.SendResponse(500, "ai-proxy.coze.unmarshal_resp_failed", util.MimeTypeTextPlain, fmt.Sprintf("failed to unmarshal response: %v", err))
		return types.ActionPause, fmt.Errorf("unable to unmarshal response: %v", err)
	}

	if chatResp.Code != 0 {
		log.Errorf("coze chat failed: %s", chatResp.Msg)
		_ = util.SendResponse(500, "ai-proxy.coze.chat_failed", util.MimeTypeTextPlain, fmt.Sprintf("coze chat failed: %s", chatResp.Msg))
		return types.ActionPause, nil
	}

	// wait for generating response
	for {
		chatRetrieveResp, err := c.CozeGetChatRetrieve(c.config.cozeApiDomain, accessToken.(string), chatResp.Data.ConversationID, chatResp.Data.ID)
		if err != nil {
			log.Errorf("failed to get chat retrieve: %v", err)
			_ = util.SendResponse(500, "ai-proxy.coze.retrieve_failed", util.MimeTypeTextPlain, fmt.Sprintf("failed to get chat retrieve: %v", err))
			return types.ActionPause, nil
		}
		if chatRetrieveResp.Code != 0 {
			log.Errorf("coze chat retrieve failed: %s", chatRetrieveResp.Msg)
			_ = util.SendResponse(500, "ai-proxy.coze.retrieve_failed", util.MimeTypeTextPlain, fmt.Sprintf("coze chat retrieve failed: %s", chatRetrieveResp.Msg))
			return types.ActionPause, nil
		}

		if chatRetrieveResp.Data.Status == "completed" {
			break
		}

		if chatRetrieveResp.Data.Status == "failed" || chatRetrieveResp.Data.Status == "canceled" {
			log.Errorf("failed")
			_ = util.SendResponse(500, "ai-proxy.coze.failed", util.MimeTypeTextPlain, "failed")
			return types.ActionPause, nil
		}
		// time.Sleep(1 * time.Second)
	}

	chatMsgResp, err := c.CozeListChatMessages(c.config.cozeApiDomain, accessToken.(string), chatResp.Data.ID, chatResp.Data.ConversationID)
	if err != nil {
		log.Errorf("failed to list chat messages: %v", err)
		_ = util.SendResponse(500, "ai-proxy.coze.list_failed", util.MimeTypeTextPlain, fmt.Sprintf("failed to list chat messages: %v", err))
		return types.ActionPause, nil
	}

	if chatMsgResp.Code != 0 {
		log.Errorf("coze list chat messages failed: %s", chatMsgResp.Msg)
		_ = util.SendResponse(500, "ai-proxy.coze.list_failed", util.MimeTypeTextPlain, fmt.Sprintf("coze list chat messages failed: %s", chatMsgResp.Msg))
		return types.ActionPause, nil
	}

	choices := make([]chatCompletionChoice, 0, len(chatMsgResp.Data))
	for idx, message := range chatMsgResp.Data {
		finishReason := string(message.Type)
		switch message.Type {
		case CozeEnterMessageTypeToolOutput, CozeEnterMessageTypeToolResponse:
			finishReason = "tool_calls"
		case CozeEnterMessageTypeAnswer:
			finishReason = "stop"
		}

		choices = append(choices, chatCompletionChoice{
			FinishReason: finishReason,
			Index:        idx,
			Message: &chatMessage{
				Role:    string(message.Role),
				Content: message.Content,
			},
		})

	}
	result := &chatCompletionResponse{
		Id:                chatResp.Data.ConversationID,
		Created:           time.Now().UnixMilli() / 1000,
		Model:             "",
		SystemFingerprint: "",
		Object:            objectChatCompletion,
		Choices:           choices,
		Usage: usage{
			PromptTokens:     int(chatResp.Data.Usage.InputCount),
			CompletionTokens: int(chatResp.Data.Usage.OutputCount),
			TotalTokens:      int(chatResp.Data.Usage.TokenCount),
		},
	}

	return types.ActionContinue, replaceJsonResponseBody(result, log)
}

// ========================================
// Coze 插件实现结束
// ========================================
