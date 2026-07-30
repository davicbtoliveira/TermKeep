package client

type ImportCounts struct {
	Logins      int
	SecureNotes int
	Folders     int
	Generic     int
}

type ImportIssue struct {
	Item    int
	Field   string
	Message string
}

type ImportPreview struct {
	Items          []NativeItem
	Counts         ImportCounts
	UnmappedFields []ImportIssue
	Errors         []ImportIssue
}
