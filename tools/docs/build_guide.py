#!/usr/bin/env python3
"""ztgate 안내서 PDF 를 docs/guide 의 Markdown 에서 만든다. 표준 라이브러리만 쓴다.

    python3 tools/docs/build_guide.py            PDF 와 원본 목록(sha256)을 다시 만든다
    python3 tools/docs/build_guide.py --check    원본이 바뀌었는데 PDF 를 다시 만들지 않았으면 실패한다 (브라우저 없이)
    python3 tools/docs/build_guide.py --out F    PDF 만 F 에 만든다. 목록은 건드리지 않는다 (CI)
    python3 tools/docs/build_guide.py --html F   인쇄하기 전의 HTML 을 F 에 쓴다

원본은 BOOK 의 Markdown 과 그 안의 그림, 이 스크립트, guide.css, VERSION 이다. 목록
(docs/guide/ztgate-guide.sources.sha256)에는 원본마다의 sha256 과 그때 만든 PDF 의 sha256 이 있다.
글 파일은 줄 끝을 LF 로 맞춘 뒤 재므로 Windows 와 Linux 의 체크아웃이 같은 값을 낸다.

PDF 는 헤드리스 Chromium 계열(Edge, Chrome, Chromium)로 인쇄한다. ZTGATE_BROWSER 로 실행 파일을 정할 수 있다.
Markdown 은 안내서가 쓰는 만큼만 읽는다: 제목, 문단, 목록(겹침 포함), 표, 코드 블록, 인라인 코드, 굵게, 링크, 그림.
"""

import argparse
import base64
import hashlib
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GUIDE = ROOT / "docs" / "guide"
CSS = Path(__file__).with_name("guide.css")
LOGO = ROOT / "docs" / "assets" / "logo.svg"
VERSION = ROOT / "VERSION"
PDF = GUIDE / "ztgate-guide.pdf"
MANIFEST = GUIDE / "ztgate-guide.sources.sha256"
REPO_URL = "https://github.com/k1msatgat/ztgate/blob/main/"
REBUILD = "python3 tools/docs/build_guide.py"

# 책의 차례. (머리에 붙는 부의 이름, 원본)
BOOK = [
	("들어가며", GUIDE / "intro.md"),
	("사용자편", GUIDE / "user.md"),
	("운영자편", GUIDE / "admin.md"),
	("운영자편", GUIDE / "admin-reference.md"),
	("부록", GUIDE / "glossary.md"),
]

TEXT_SUFFIXES = {".md", ".py", ".css", ".svg", ""}
MIME = {".png": "image/png", ".svg": "image/svg+xml", ".jpg": "image/jpeg"}


def rel(path):
	return path.resolve().relative_to(ROOT).as_posix()


def file_bytes(path):
	data = path.read_bytes()
	if path.suffix in TEXT_SUFFIXES:
		data = data.replace(b"\r\n", b"\n")
	return data


def sha256(path):
	return hashlib.sha256(file_bytes(path)).hexdigest()


def slug(text):
	"""GitHub 이 제목에 붙이는 id. 안내서의 #링크가 이 모양이다."""
	text = re.sub(r"[^\w\- ]", "", text.lower())
	return text.replace(" ", "-")


# ---- Markdown ----------------------------------------------------------------

CODE_SPAN = re.compile(r"`([^`]+)`")
IMAGE = re.compile(r"!\[([^\]]*)\]\(([^)\s]+)\)")
LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
BOLD = re.compile(r"\*\*(.+?)\*\*")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
ITEM = re.compile(r"^(\d+\.|[-*])(\s+)(.*)$")
TABLE_SEP = re.compile(r"^\|?(\s*:?-{3,}:?\s*\|)+\s*(:?-{3,}:?\s*)?$")
HOLE = re.compile(r"\x00(\d+)\x00")


def indent_of(line):
	return len(line) - len(line.lstrip(" "))


def starts_block(line):
	return line.startswith("```") or HEADING.match(line) or line.startswith("|") or ITEM.match(line)


class Chapter:
	"""Markdown 한 파일을 책의 한 장으로 바꾼다. 링크와 그림의 경로는 그 파일을 기준으로 푼다."""

	def __init__(self, part, path, book):
		self.part = part
		self.path = path
		self.id = path.stem
		self.book = book			# 원본 경로 -> 장 id
		self.title = ""
		self.sections = []			# (id, 제목) 의 h2 목록. 목차가 쓴다
		self.images = []

	def html(self):
		lines = self.path.read_text(encoding="utf-8").splitlines()
		body = "\n".join(self.blocks(lines))
		return ('<section class="chapter" id="%s" style="page: %s">\n<span class="part">%s</span>\n%s\n</section>'
			% (self.id, self.id, html.escape(self.part), body))

	# 블록 ---------------------------------------------------------------

	def blocks(self, lines):
		out, i = [], 0
		while i < len(lines):
			line = lines[i]
			if not line.strip():
				i += 1
			elif line.startswith("```"):
				j = i + 1
				while j < len(lines) and not lines[j].startswith("```"):
					j += 1
				out.append("<pre><code>%s</code></pre>" % html.escape("\n".join(lines[i + 1:j])))
				i = j + 1
			elif HEADING.match(line):
				m = HEADING.match(line)
				out.append(self.heading(len(m[1]), m[2]))
				i += 1
			elif line.startswith("|") and i + 1 < len(lines) and TABLE_SEP.match(lines[i + 1].strip()):
				j = i + 2
				while j < len(lines) and lines[j].startswith("|"):
					j += 1
				out.append(self.table(lines[i], lines[i + 2:j]))
				i = j
			elif ITEM.match(line):
				text, i = self.list_block(lines, i)
				out.append(text)
			else:
				j = i
				while j < len(lines) and lines[j].strip() and (j == i or not starts_block(lines[j])):
					j += 1
				text = " ".join(l.strip() for l in lines[i:j])
				m = IMAGE.fullmatch(text)
				if m:
					out.append('<figure>%s<figcaption>%s</figcaption></figure>'
						% (self.image(m[2], m[1]), html.escape(m[1])))
				else:
					out.append("<p>%s</p>" % self.inline(text))
				i = j
		return out

	def heading(self, level, text):
		plain = LINK.sub(r"\1", text).replace("`", "")
		if level == 1:
			self.title = plain
			return '<h1>%s</h1>' % self.inline(text)
		hid = "%s-%s" % (self.id, slug(plain))
		if level == 2:
			self.sections.append((hid, plain))
		return '<h%d id="%s">%s</h%d>' % (level, hid, self.inline(text), level)

	def table(self, head, rows):
		def cells(row):
			row = row.strip().replace("\\|", "\x01")
			return [c.strip().replace("\x01", "|") for c in row.strip("|").split("|")]
		th = "".join("<th>%s</th>" % self.inline(c) for c in cells(head))
		trs = "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % self.inline(c) for c in cells(r)) for r in rows)
		return "<table><thead><tr>%s</tr></thead><tbody>%s</tbody></table>" % (th, trs)

	def list_block(self, lines, i):
		ordered = ITEM.match(lines[i])[1][0].isdigit()
		start = int(ITEM.match(lines[i])[1][:-1]) if ordered else 1
		items = []
		while i < len(lines):
			m = ITEM.match(lines[i])
			if not m or m[1][0].isdigit() != ordered:
				break
			width = len(m[1]) + len(m[2])
			body, i = [m[3]], i + 1
			while i < len(lines):
				line = lines[i]
				if not line.strip():
					k = i
					while k < len(lines) and not lines[k].strip():
						k += 1
					if k < len(lines) and indent_of(lines[k]) >= width:
						body += [""] * (k - i)
						i = k
						continue
					break
				if indent_of(line) >= width:
					body.append(line[width:])
				elif starts_block(line):
					break
				else:
					body.append(line.strip())
				i += 1
			items.append(self.blocks(body))
			k = i
			while k < len(lines) and not lines[k].strip():
				k += 1
			if k < len(lines) and ITEM.match(lines[k]):
				i = k
			else:
				break
		lis = []
		for parts in items:
			if parts and parts[0].startswith("<p>") and not any(p.startswith("<p>") for p in parts[1:]):
				parts = [parts[0][3:-4]] + parts[1:]
			lis.append("<li>%s</li>" % "\n".join(parts))
		tag = "ol" if ordered else "ul"
		attr = ' start="%d"' % start if ordered and start != 1 else ""
		return "<%s%s>%s</%s>" % (tag, attr, "".join(lis), tag), i

	# 인라인 -------------------------------------------------------------

	def inline(self, text):
		holes = []

		def keep(fragment):
			holes.append(fragment)
			return "\x00%d\x00" % (len(holes) - 1)

		def plain(t):
			return BOLD.sub(r"<strong>\1</strong>", html.escape(t, quote=False))

		text = CODE_SPAN.sub(lambda m: keep("<code>%s</code>" % html.escape(m[1], quote=False)), text)
		text = IMAGE.sub(lambda m: keep(self.image(m[2], m[1])), text)
		text = LINK.sub(lambda m: keep('<a href="%s">%s</a>' % (html.escape(self.href(m[2])), plain(m[1]))), text)
		text = plain(text)
		while HOLE.search(text):
			text = HOLE.sub(lambda m: holes[int(m[1])], text)
		return text

	def href(self, target):
		if re.match(r"^[a-z]+:", target):
			return target
		path, _, frag = target.partition("#")
		frag = urllib.parse.unquote(frag)
		if not path:
			return "#%s-%s" % (self.id, frag)
		dest = (self.path.parent / path).resolve()
		if dest in self.book:
			chap = self.book[dest]
			return "#%s-%s" % (chap, frag) if frag else "#" + chap
		return REPO_URL + rel(dest) + ("#" + urllib.parse.quote(frag) if frag else "")

	def image(self, src, alt):
		path = (self.path.parent / src).resolve()
		self.images.append(path)
		return '<img src="%s" alt="%s">' % (data_uri(path), html.escape(alt))


def data_uri(path):
	return "data:%s;base64,%s" % (MIME[path.suffix], base64.b64encode(path.read_bytes()).decode())


# ---- 책 ----------------------------------------------------------------------

def book_html(pages=None):
	"""pages: 장과 절의 id -> 쪽 번호. 첫 인쇄에서 읽어 목차에 적는다."""
	index = {path.resolve(): path.stem for _, path in BOOK}
	chapters = [Chapter(part, path, index) for part, path in BOOK]
	bodies = [c.html() for c in chapters]
	version = VERSION.read_text(encoding="utf-8").strip()
	pages = pages or {}

	def entry(hid, title, cls=""):
		num = '<span class="page">%s</span>' % pages[hid] if hid in pages else ""
		return '<a href="#%s"%s><span class="title">%s</span>%s</a>' % (hid, cls, html.escape(title), num)

	toc = []
	for c in chapters:
		subs = "".join("<li>%s</li>" % entry(hid, title) for hid, title in c.sections)
		toc.append('<li><span class="part">%s</span>%s<ol>%s</ol></li>'
			% (html.escape(c.part), entry(c.id, c.title, ' class="toc-chapter"'), subs))
	running = "\n".join(
		'@page %s { @top-right { content: "%s"; font: 8.5pt "Malgun Gothic", "Noto Sans CJK KR", "Noto Sans KR", sans-serif; color: #5B6678; } }'
		% (c.id, c.title.replace('"', "")) for c in chapters)
	parts = "<br>".join(html.escape(c.title) for c in chapters)
	doc = """<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<title>ztgate 안내서</title>
<style>
{css}
{running}
</style>
</head>
<body>
<section class="cover">
<img class="logo" src="{logo}" alt="">
<h1>ztgate 안내서</h1>
<div class="subtitle">서버 운영과 Windows 접속</div>
<div class="rule"></div>
<div class="parts">{parts}</div>
<div class="meta">ztgate {version}<br>{repo}</div>
</section>
<nav class="toc">
<h1>목차</h1>
<ol>{toc}</ol>
</nav>
{bodies}
</body>
</html>
""".format(css=CSS.read_text(encoding="utf-8"), running=running, logo=data_uri(LOGO), parts=parts,
		version=html.escape(version), repo=REPO_URL.split("/blob/")[0].replace("https://", ""),
		toc="".join(toc), bodies="\n".join(bodies))
	broken = set(re.findall(r'href="#([^"]+)"', doc)) - set(re.findall(r' id="([^"]+)"', doc))
	if broken:
		sys.exit("오류: 안내서 안의 링크가 가리키는 제목이 없습니다: " + ", ".join(sorted(broken)))
	sources = [p for _, p in BOOK] + [img for c in chapters for img in c.images] + [Path(__file__), CSS, LOGO, VERSION]
	return doc, sorted({rel(p) for p in sources})


# ---- 인쇄 --------------------------------------------------------------------

def find_browser():
	named = os.environ.get("ZTGATE_BROWSER")
	if named:
		return named
	for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "msedge"):
		found = shutil.which(name)
		if found:
			return found
	for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles"), os.environ.get("LOCALAPPDATA")):
		if not base:
			continue
		for sub in (r"Microsoft\Edge\Application\msedge.exe", r"Google\Chrome\Application\chrome.exe"):
			if os.path.isfile(os.path.join(base, sub)):
				return os.path.join(base, sub)
	return None


def print_pdf(browser, page, out, work):
	src = work / "guide.html"
	src.write_text(page, encoding="utf-8")
	pdf = work / "guide.pdf"
	cmd = [browser, "--headless", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
		"--user-data-dir=" + str(work / "profile"), "--no-pdf-header-footer",
		"--generate-pdf-document-outline", "--print-to-pdf=" + str(pdf), src.as_uri()]
	# Ubuntu 24.04 는 AppArmor 가 Chrome 샌드박스의 사용자 네임스페이스를 막는다. 인쇄하는 것은 이
	# 스크립트가 만든 HTML 하나라 샌드박스 없이 돌린다.
	if sys.platform.startswith("linux"):
		cmd.insert(1, "--no-sandbox")
	r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
	if not pdf.exists() or pdf.stat().st_size == 0:
		sys.exit("오류: %s 가 PDF 를 만들지 못했습니다.\n%s" % (browser, r.stdout.decode(errors="replace")[-2000:]))
	data = pdf.read_bytes()
	# 인쇄한 시각만 다른 PDF 가 커밋마다 새 파일이 되지 않게, 같은 길이의 고정 시각으로 바꾼다.
	data = re.sub(rb"\(D:\d{14}", b"(D:20000101000000", data)
	out.parent.mkdir(parents=True, exist_ok=True)
	out.write_bytes(data)
	return data


def pdf_objects(data):
	"""PDF 의 객체 번호 -> 본문. Chromium 의 PDF 는 객체 스트림을 쓰지 않아 객체가 그대로 보인다."""
	return {int(m[1]): m[2] for m in re.finditer(rb"(\d+) 0 obj\s*(.*?)\s*endobj", data, re.S)}


def anchor_pages(data):
	"""Chromium 이 이름 붙인 목적지(id 마다 하나)를 쪽 번호로 바꾼다."""
	objs = pdf_objects(data)
	pages = []

	def walk(num):
		body = objs[num]
		if re.search(rb"/Type\s*/Pages", body):
			for kid in re.findall(rb"(\d+) 0 R", re.search(rb"/Kids\s*\[(.*?)\]", body, re.S)[1]):
				walk(int(kid))
		else:
			pages.append(num)

	root = re.search(rb"/Root (\d+) 0 R", data)
	catalog = objs.get(int(root[1]), b"") if root else b""
	dests = re.search(rb"/Dests (\d+) 0 R", catalog)
	if not dests:
		return {}
	walk(int(re.search(rb"/Pages (\d+) 0 R", catalog)[1]))
	page_no = {num: i + 1 for i, num in enumerate(pages)}
	found = {}
	# 이름은 PDF 이름의 #xx 안에 다시 URL 의 %xx 로 적혀 있다 (/intro-#25EA#25B5...).
	for name, ref in re.findall(rb"/([^\s/\[]+)\s*\[\s*(\d+) 0 R\s*/XYZ", objs[int(dests[1])]):
		raw = re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m[1], 16)]), name)
		if int(ref) in page_no:
			found[urllib.parse.unquote(raw.decode("latin-1"))] = page_no[int(ref)]
	return found


def build(out, html_out=None):
	page, sources = book_html()
	browser = find_browser()
	if not browser:
		sys.exit("오류: PDF 를 인쇄할 Chromium 계열 브라우저(Edge, Chrome, Chromium)를 찾지 못했습니다. ZTGATE_BROWSER 로 정합니다.")
	with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
		work = Path(tmp)
		# 목차에 쪽 번호를 적으면 목차가 길어져 쪽이 밀릴 수 있다. 번호가 그대로일 때까지 다시 인쇄한다.
		pages = anchor_pages(print_pdf(browser, page, out, work))
		if not pages:
			print("주의: PDF 에서 쪽 번호를 읽지 못해 목차에 쪽 번호를 넣지 않았습니다.", file=sys.stderr)
		for attempt in range(3):
			if not pages:
				break
			page, _ = book_html(pages)
			again = anchor_pages(print_pdf(browser, page, out, work))
			if again == pages:
				break
			pages = again
		else:
			print("주의: 목차의 쪽 번호가 세 번 인쇄해도 맞춰지지 않았습니다.", file=sys.stderr)
	if html_out:
		Path(html_out).write_text(page, encoding="utf-8")
	return sources


# ---- 원본 목록 ---------------------------------------------------------------

HEADER = ("# docs/guide/ztgate-guide.pdf 를 만든 원본의 sha256. %s 가 쓴다. 손으로 고치지 않는다.\n"
	"# 글 파일은 줄 끝을 LF 로 맞춘 뒤 잰다. 마지막 줄은 그때 만든 PDF 다.\n" % REBUILD)


def write_manifest(sources):
	lines = ["%s  %s" % (sha256(ROOT / p), p) for p in sources]
	lines.append("%s  %s" % (sha256(PDF), rel(PDF)))
	MANIFEST.write_bytes((HEADER + "\n".join(lines) + "\n").encode("utf-8"))


def read_manifest():
	entries = {}
	for line in MANIFEST.read_text(encoding="utf-8").splitlines():
		if line.strip() and not line.startswith("#"):
			digest, path = line.split(None, 1)
			entries[path.strip()] = digest
	return entries


def check():
	if not MANIFEST.exists() or not PDF.exists():
		missing = ", ".join(rel(p) for p in (PDF, MANIFEST) if not p.exists())
		print("오류: 없는 파일: %s\n만들기: %s" % (missing, REBUILD), file=sys.stderr)
		return 1
	_, sources = book_html()
	want = {p: sha256(ROOT / p) for p in sources}
	want[rel(PDF)] = sha256(PDF)
	have = read_manifest()
	changed = sorted(p for p in want if p in have and have[p] != want[p])
	added = sorted(p for p in want if p not in have)
	removed = sorted(p for p in have if p not in want)
	if not (changed or added or removed):
		print("안내서 PDF 가 원본과 맞습니다 (원본 %d개)." % len(sources))
		return 0
	print("오류: 안내서 PDF 가 원본과 맞지 않습니다.", file=sys.stderr)
	for label, paths in (("바뀐 파일", changed), ("새 원본", added), ("빠진 원본", removed)):
		for p in paths:
			print("  %s: %s" % (label, p), file=sys.stderr)
	print("다시 만들기: %s\n그다음 두 파일을 함께 커밋합니다: %s, %s" % (REBUILD, rel(PDF), rel(MANIFEST)), file=sys.stderr)
	return 1


def main():
	ap = argparse.ArgumentParser(description="ztgate 안내서 PDF 만들기")
	ap.add_argument("--check", action="store_true", help="원본이 바뀌었는데 PDF 를 다시 만들지 않았으면 실패한다")
	ap.add_argument("--out", help="PDF 만 이 경로에 만든다 (목록은 그대로)")
	ap.add_argument("--html", help="인쇄하기 전의 HTML 도 이 경로에 쓴다")
	a = ap.parse_args()
	if a.check:
		return check()
	if a.out:
		build(Path(a.out).resolve(), a.html)
		print("만듦: %s" % a.out)
		return 0
	sources = build(PDF, a.html)
	write_manifest(sources)
	print("만듦: %s (%d KB), %s (원본 %d개)" % (rel(PDF), PDF.stat().st_size // 1024, rel(MANIFEST), len(sources)))
	return 0


if __name__ == "__main__":
	sys.exit(main())
