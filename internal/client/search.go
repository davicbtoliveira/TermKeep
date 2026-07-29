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
	fields []searchField
}

type searchField struct {
	value  string
	weight int
}

func NewSearchIndex(items []NativeItem, folders []FolderItem) SearchIndex {
	index := SearchIndex{
		entries: make([]searchEntry, 0, len(items)),
	}
	folderNames := make(map[string]string, len(folders))
	for _, folder := range folders {
		folderNames[folder.ItemID] = folder.Name
	}
	for _, item := range items {
		switch item.Type {
		case NativeItemTypeLogin:
			if item.Login != nil {
				entry := searchEntry{
					itemID: item.Login.ItemID,
					title:  item.Login.Name,
				}
				entry.addField(item.Login.Name, 5000)
				entry.addField(item.Login.Username, 4000)
				for _, itemURL := range item.Login.URLs {
					entry.addField(itemURL, 3000)
				}
				entry.addField(folderNames[item.Login.FolderID], 2000)
				for _, field := range item.Login.CustomFields {
					entry.addField(field.Name, 1000)
				}
				index.entries = append(index.entries, entry)
			}
		case NativeItemTypeSecureNote:
			if item.SecureNote != nil {
				entry := searchEntry{
					itemID: item.SecureNote.ItemID,
					title:  item.SecureNote.Title,
				}
				entry.addField(item.SecureNote.Title, 5000)
				entry.addField(
					folderNames[item.SecureNote.FolderID], 2000)
				index.entries = append(index.entries, entry)
			}
		}
	}
	return index
}

func (entry *searchEntry) addField(value string, weight int) {
	if value == "" {
		return
	}
	entry.fields = append(entry.fields, searchField{
		value:  value,
		weight: weight,
	})
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
		var (
			score   int
			matched bool
		)
		for _, field := range entry.fields {
			fieldScore, fieldMatched := fuzzyScore(query, field.value)
			if fieldMatched &&
				(!matched || fieldScore+field.weight > score) {
				score = fieldScore + field.weight
				matched = true
			}
		}
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
