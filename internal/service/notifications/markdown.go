package notifications

import (
	"bytes"
	"html"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	extast "github.com/yuin/goldmark/extension/ast"
	mdhtml "github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"golang.org/x/text/width"
)

// markdown 是通知内容共用的 goldmark 实例；未启用 WithUnsafe，正文 HTML 与危险链接会被转义。
// goldmark.Markdown 可被多个 goroutine 并发使用。
var markdown = goldmark.New(goldmark.WithExtensions(extension.GFM))

func renderMarkdownHTML(source string) string {
	var buffer bytes.Buffer
	if err := markdown.Convert([]byte(source), &buffer); err != nil {
		return "<p>" + html.EscapeString(source) + "</p>"
	}
	return buffer.String()
}

// ---------------------------------------------------------------------------
// QQ 纯文本渲染
// ---------------------------------------------------------------------------

func renderMarkdownText(source string) string {
	sourceBytes := []byte(source)
	doc := markdown.Parser().Parse(text.NewReader(sourceBytes))

	out := &plainTextWriter{}
	renderer := &plainTextRenderer{source: sourceBytes, out: out}
	renderer.renderBlocks(doc)
	return normalizePlainText(out.String())
}

type plainTextWriter struct {
	builder  strings.Builder
	lastByte byte
}

func (w *plainTextWriter) write(value string) {
	if value == "" {
		return
	}
	w.builder.WriteString(value)
	w.lastByte = value[len(value)-1]
}

func (w *plainTextWriter) newline() {
	if w.lastByte != '\n' {
		w.builder.WriteByte('\n')
		w.lastByte = '\n'
	}
}

func (w *plainTextWriter) blankLine() {
	if w.lastByte == 0 {
		return
	}
	w.newline()
	w.builder.WriteByte('\n')
	w.lastByte = '\n'
}

func (w *plainTextWriter) String() string {
	return w.builder.String()
}

type plainTextRenderer struct {
	source []byte
	out    *plainTextWriter
}

func (r *plainTextRenderer) renderBlocks(node ast.Node) {
	for child := node.FirstChild(); child != nil; child = child.NextSibling() {
		r.renderBlock(child)
	}
}

func (r *plainTextRenderer) renderBlock(node ast.Node) {
	switch current := node.(type) {
	case *ast.Document:
		r.renderBlocks(current)
	case *ast.Paragraph:
		r.renderInlines(current)
		r.out.blankLine()
	case *ast.TextBlock:
		r.renderInlines(current)
		r.out.newline()
	case *ast.Heading:
		r.renderHeading(current)
	case *ast.List:
		r.renderList(current, 0)
		r.out.blankLine()
	case *ast.ListItem:
		r.renderListItem(current, 0)
	case *ast.Blockquote:
		r.renderBlocks(current)
	case *ast.FencedCodeBlock:
		r.renderCodeBlock(current.Lines())
		r.out.blankLine()
	case *ast.CodeBlock:
		r.renderCodeBlock(current.Lines())
		r.out.blankLine()
	case *ast.ThematicBreak:
		r.out.write("----------")
		r.out.blankLine()
	case *ast.HTMLBlock:
	case *extast.Table:
		r.renderTable(current)
		r.out.blankLine()
	default:
		r.renderBlocks(current)
	}
}

func (r *plainTextRenderer) renderHeading(heading *ast.Heading) {
	open, close := "- - - ", " - - -" // 六级及以下
	switch heading.Level {
	case 1:
		open, close = "=====〖", "〗====="
	case 2:
		open, close = "=====〔", "〕====="
	case 3:
		open, close = "===== ", " ====="
	case 4:
		open, close = "-----〔", "〕-----"
	case 5:
		open, close = "----- ", " -----"
	}

	r.out.write(open)
	r.renderInlines(heading)
	r.out.write(close)
	r.out.blankLine()
}

func (r *plainTextRenderer) renderList(list *ast.List, depth int) {
	for item := list.FirstChild(); item != nil; item = item.NextSibling() {
		r.renderListItem(item, depth)
	}
}

func (r *plainTextRenderer) renderListItem(item ast.Node, depth int) {
	indent := strings.Repeat("  ", depth)
	r.out.write(indent + " - ")

	first := true
	for child := item.FirstChild(); child != nil; child = child.NextSibling() {
		switch current := child.(type) {
		case *ast.List:
			r.out.newline()
			r.renderList(current, depth+1)
		case *ast.TextBlock, *ast.Paragraph:
			if !first {
				r.out.newline()
				r.out.write(indent + "  ")
			}
			r.renderInlines(child)
			first = false
		default:
			if !first {
				r.out.newline()
				r.out.write(indent + "  ")
			}
			r.renderBlock(child)
			first = false
		}
	}
	r.out.newline()
}

func (r *plainTextRenderer) renderCodeBlock(lines *text.Segments) {
	for i := 0; i < lines.Len(); i++ {
		segment := lines.At(i)
		r.out.write(string(segment.Value(r.source)))
	}
}

func (r *plainTextRenderer) renderInlines(node ast.Node) {
	for child := node.FirstChild(); child != nil; child = child.NextSibling() {
		r.renderInline(child)
	}
}

func (r *plainTextRenderer) renderInline(node ast.Node) {
	switch current := node.(type) {
	case *ast.Text:
		if current.IsRaw() {
			// 代码片段内的反斜杠是字面量，不做反转义
			r.out.write(string(current.Segment.Value(r.source)))
		} else {
			r.out.write(unescapeMarkdownText(string(current.Segment.Value(r.source))))
		}
		if current.SoftLineBreak() || current.HardLineBreak() {
			r.out.write("\n")
		}
	case *ast.String:
		r.out.write(string(current.Value))
	case *ast.AutoLink:
		r.out.write(string(current.URL(r.source)))
	case *ast.RawHTML:
	case *ast.Link:
		r.renderInlines(current)
		// 与 HTML 渲染保持一致：跳过 javascript: 等危险链接
		if destination := current.Destination; len(destination) > 0 && !mdhtml.IsDangerousURL(destination) {
			r.out.write(" (")
			r.out.write(string(destination))
			r.out.write(")")
		}
	case *ast.Image:
		r.renderInlines(current)
	case *ast.Emphasis:
		open, close := "「", "」"
		if current.Level >= 2 {
			open, close = "『", "』"
		}
		r.out.write(open)
		r.renderInlines(current)
		r.out.write(close)
	case *extast.Strikethrough:
		r.renderInlines(current)
	case *ast.CodeSpan:
		r.renderInlines(current)
	default:
		r.renderInlines(current)
	}
}

// renderTable 把 GFM 表格渲染为制表符分列的纯文本表格。
// 空格补齐保证制表符被折叠成空格时列间仍有分隔。
func (r *plainTextRenderer) renderTable(table *extast.Table) {
	var rows [][]string
	var alignments []extast.Alignment

	for child := table.FirstChild(); child != nil; child = child.NextSibling() {
		switch current := child.(type) {
		case *extast.TableHeader:
			alignments = current.Alignments
			rows = append(rows, r.tableCells(current))
		case *extast.TableRow:
			if alignments == nil {
				alignments = current.Alignments
			}
			rows = append(rows, r.tableCells(current))
		}
	}
	if len(rows) == 0 {
		return
	}

	columnCount := 0
	for _, row := range rows {
		if len(row) > columnCount {
			columnCount = len(row)
		}
	}
	if columnCount == 0 {
		return
	}
	for len(alignments) < columnCount {
		alignments = append(alignments, extast.AlignNone)
	}

	widths := make([]int, columnCount)
	for _, row := range rows {
		for index := 0; index < columnCount && index < len(row); index++ {
			if cellWidth := displayWidth(row[index]); cellWidth > widths[index] {
				widths[index] = cellWidth
			}
		}
	}

	var tableBuilder strings.Builder
	for _, row := range rows {
		for index := 0; index < columnCount; index++ {
			cell := ""
			if index < len(row) {
				cell = row[index]
			}
			if index == columnCount-1 {
				tableBuilder.WriteString(cell)
				break
			}
			tableBuilder.WriteString(padDisplay(cell, widths[index], alignments[index]))
			tableBuilder.WriteString(" ")
			tableBuilder.WriteByte('\t')
		}
		tableBuilder.WriteByte('\n')
	}

	r.out.write(tableBuilder.String())
}

func (r *plainTextRenderer) tableCells(node ast.Node) []string {
	cells := make([]string, 0)
	for cell := node.FirstChild(); cell != nil; cell = cell.NextSibling() {
		cellOut := &plainTextWriter{}
		cellRenderer := &plainTextRenderer{source: r.source, out: cellOut}
		cellRenderer.renderInlines(cell)
		cells = append(cells, strings.Join(strings.Fields(cellOut.String()), " "))
	}
	return cells
}

func displayWidth(value string) int {
	total := 0
	for _, char := range value {
		switch {
		case char == '\t':
			total += 4
		case char >= 0x1F300 && char <= 0x1FAFF:
			// Emoji 与符号补充区通常按两格显示
			total += 2
		default:
			switch width.LookupRune(char).Kind() {
			case width.EastAsianWide, width.EastAsianFullwidth:
				total += 2
			default:
				total++
			}
		}
	}
	return total
}

func padDisplay(value string, target int, alignment extast.Alignment) string {
	padding := target - displayWidth(value)
	if padding < 0 {
		padding = 0
	}

	switch alignment {
	case extast.AlignRight:
		return strings.Repeat(" ", padding) + value
	case extast.AlignCenter:
		left := padding / 2
		return strings.Repeat(" ", left) + value + strings.Repeat(" ", padding-left)
	default:
		return value + strings.Repeat(" ", padding)
	}
}

func unescapeMarkdownText(value string) string {
	if !strings.ContainsAny(value, "\\&") {
		return value
	}

	var builder strings.Builder
	builder.Grow(len(value))
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char == '\\' && index+1 < len(value) && isASCIIPunctuation(value[index+1]) {
			builder.WriteByte(value[index+1])
			index++
			continue
		}
		builder.WriteByte(char)
	}
	return builder.String()
}

func isASCIIPunctuation(char byte) bool {
	switch char {
	case '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
		':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~':
		return true
	default:
		return false
	}
}

func normalizePlainText(content string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}

	normalized := strings.Join(lines, "\n")
	for strings.Contains(normalized, "\n\n\n") {
		normalized = strings.ReplaceAll(normalized, "\n\n\n", "\n\n")
	}
	return strings.TrimSpace(normalized)
}
