//go:build darwin

package sai

import (
	"crypto/md5"
	"encoding/binary"
	"math"
	"strconv"
	"strings"
	"sync"
)

var aiProviderPatterns = []string{
	"openai.com",
	"api.openai.com",
	"anthropic.com",
	"api.anthropic.com",
	"claude.ai",
	"cohere.ai",
	"cohere.com",
	"ai21.com",
	"mistral.ai",
	"groq.com",
	"perplexity.ai",
	"deepseek.com",
	"x.ai",
	"grok.x.ai",
	"aiplatform.googleapis.com",
	"generativelanguage.googleapis.com",
	"aistudio.google.com",
	"bedrock.amazonaws.com",
	"bedrock-runtime.amazonaws.com",
	"sagemaker.amazonaws.com",
	"inference.azure.com",
	"openai.azure.com",
	"cognitiveservices.azure.com",
	"huggingface.co",
	"api-inference.huggingface.co",
	"replicate.com",
	"api.replicate.com",
	"together.ai",
	"api.together.xyz",
	"fireworks.ai",
	"api.fireworks.ai",
	"deepinfra.com",
	"api.deepinfra.com",
	"anyscale.com",
	"cerebras.ai",
	"api.cerebras.ai",
	"sambanova.ai",
	"cloud.sambanova.ai",
	"octoai.cloud",
	"baseten.co",
	"modal.com",
	"lepton.ai",
	"hyperbolic.xyz",
	"novita.ai",
	"featherless.ai",
	"nscale.com",
	"nebius.com",
	"lambdalabs.com",
	"api.lambdalabs.com",
	"ollama.ai",
	"ollama.com",
	"lmstudio.ai",
	"llamafile.ai",
	"openrouter.ai",
	"poe.com",
	"chatgpt.com",
	"chat.openai.com",
	"copilot.github.com",
	"api.githubcopilot.com",
	"cursor.sh",
	"cursor.com",
	"windsurf.ai",
	"codeium.com",
	"tabnine.com",
	"sourcegraph.com",
	"elevenlabs.io",
	"api.elevenlabs.io",
	"deepgram.com",
	"stability.ai",
	"api.stability.ai",
	"runwayml.com",
	"midjourney.com",
	"fal.ai",
	"dashscope.aliyuncs.com",
	"volcengine.com",
	"minimax.chat",
	"moonshot.cn",
	"api.moonshot.cn",
	"zhipuai.cn",
	"bigmodel.cn",
	"baichuan-ai.com",
	"ernie.baidu.com",
	"watsonx.ai",
	"nlpcloud.io",
	"aleph-alpha.com",
	"clarifai.com",
	"datarobot.com",
	"databricks.com",
	"snowflake.com",
	"voyageai.com",
	"jina.ai",
	"aimlapi.com",
	"galadriel.com",
	"recraft.ai",
}

type bloomFilter struct {
	m      int
	k      int
	bitset []byte
}

func newBloomFilter(expectedItems int, falsePositiveRate float64) *bloomFilter {
	m := int(math.Ceil(-float64(expectedItems) * math.Log(falsePositiveRate) / math.Pow(math.Ln2, 2)))
	k := int(math.Round(float64(m) / float64(expectedItems) * math.Ln2))
	return &bloomFilter{
		m:      m,
		k:      k,
		bitset: make([]byte, (m+7)/8),
	}
}

func (bf *bloomFilter) hash(item string, seed int) int {
	h := md5.Sum([]byte(strconv.Itoa(seed) + ":" + item))
	return int(binary.LittleEndian.Uint32(h[:4])) % bf.m
}

func (bf *bloomFilter) Add(item string) {
	for i := 0; i < bf.k; i++ {
		pos := bf.hash(item, i)
		bf.bitset[pos/8] |= 1 << (pos % 8)
	}
}

func (bf *bloomFilter) Test(item string) bool {
	for i := 0; i < bf.k; i++ {
		pos := bf.hash(item, i)
		if bf.bitset[pos/8]&(1<<(pos%8)) == 0 {
			return false
		}
	}
	return true
}

type Classifier struct {
	aiFilter *bloomFilter
	mu       sync.RWMutex
}

func NewClassifier() *Classifier {
	c := &Classifier{
		aiFilter: newBloomFilter(10000, 0.01),
	}
	for _, domain := range aiProviderPatterns {
		c.aiFilter.Add(normalizeDomain(domain))
	}
	return c
}

func (c *Classifier) IsAI(domain string) bool {
	domain = normalizeDomain(domain)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.aiFilter.Test(domain) {
		return true
	}

	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if c.aiFilter.Test(parent) {
			return true
		}
	}

	return false
}

func normalizeDomain(domain string) string {
	domain = strings.ToLower(domain)
	domain = strings.TrimPrefix(domain, "www.")
	return domain
}

func MatchAIProvider(hostname string) string {
	hostname = strings.ToLower(hostname)
	for _, domain := range aiProviderPatterns {
		if hostname == domain || strings.HasSuffix(hostname, "."+domain) {
			return domain
		}
	}
	return ""
}
