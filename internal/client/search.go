package client

import (
	"sort"
	"strings"
)

type SearchMode uint8

const SearchModeMetadata SearchMode = iota

type SearchResult struct {
	ItemID string
}

type SearchIndex struct {
	entries []searchEntry
}

type searchEntry struct {
	itemID string
	title  string
}

func NewSearchIndex(items []NativeItem, _ []FolderItem) SearchIndex {
	index := SearchIndex{
		entries: make([]searchEntry, 0, len(items)),
	}
	for _, item := range items {
		switch item.Type {
		case NativeItemTypeLogin:
			if item.Login != nil {
				index.entries = append(index.entries, searchEntry{
					itemID: item.Login.ItemID,
					title:  item.Login.Name,
				})
			}
		case NativeItemTypeSecureNote:
			if item.SecureNote != nil {
				index.entries = append(index.entries, searchEntry{
					itemID: item.SecureNote.ItemID,
					title:  item.SecureNote.Title,
				})
			}
		}
	}
	return index
}

func (index SearchIndex) Search(
	query string,
	_ SearchMode,
) []SearchResult {
	query = strings.TrimSpace(strings.ToLower(query))
	if query == "" {
		return nil
	}
	type scoredResult struct {
		SearchResult
		score int
		title string
	}
	scored := make([]scoredResult, 0)
	for _, entry := range index.entries {
		score, matched := fuzzyScore(query, entry.title)
		if !matched {
			continue
		}
		scored = append(scored, scoredResult{
			SearchResult: SearchResult{ItemID: entry.itemID},
			score:        score,
			title:        strings.ToLower(entry.title),
		})
	}
	sort.Slice(scored, func(left, right int) bool {
		if scored[left].score != scored[right].score {
			return scored[left].score > scored[right].score
		}
		if scored[left].title != scored[right].title {
			return scored[left].title < scored[right].title
		}
		return scored[left].ItemID < scored[right].ItemID
	})
	results := make([]SearchResult, len(scored))
	for resultIndex, result := range scored {
		results[resultIndex] = result.SearchResult
	}
	return results
}

func fuzzyScore(query, candidate string) (int, bool) {
	queryRunes := []rune(strings.ToLower(query))
	candidateRunes := []rune(strings.ToLower(candidate))
	if len(queryRunes) == 0 || len(queryRunes) > len(candidateRunes) {
		return 0, false
	}
	if start := runeSliceIndex(candidateRunes, queryRunes); start >= 0 {
		return 8000 -
			start*16 -
			(len(candidateRunes) - len(queryRunes)), true
	}

	start := -1
	last := -1
	queryIndex := 0
	for candidateIndex, candidateRune := range candidateRunes {
		if candidateRune != queryRunes[queryIndex] {
			continue
		}
		if start < 0 {
			start = candidateIndex
		}
		last = candidateIndex
		queryIndex++
		if queryIndex == len(queryRunes) {
			gaps := last - start + 1 - len(queryRunes)
			return 4000 -
				start*16 -
				gaps*32 -
				(len(candidateRunes) - len(queryRunes)), true
		}
	}
	return 0, false
}

func runeSliceIndex(candidate, query []rune) int {
	for start := 0; start <= len(candidate)-len(query); start++ {
		matched := true
		for queryIndex := range query {
			if candidate[start+queryIndex] != query[queryIndex] {
				matched = false
				break
			}
		}
		if matched {
			return start
		}
	}
	return -1
}
