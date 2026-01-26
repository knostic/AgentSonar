package sai

import (
	"crypto/md5"
	"encoding/binary"
	"math"
	"strconv"
	"strings"
)

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

func normalizeDomain(domain string) string {
	domain = strings.ToLower(domain)
	domain = strings.TrimPrefix(domain, "www.")
	return domain
}
