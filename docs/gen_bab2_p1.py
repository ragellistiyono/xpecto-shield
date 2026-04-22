"""BAB 2 content generator - Part 1: Deskripsi Sistem, Permasalahan, Solusi."""
from gen_helpers import *


def write_bab2_part1(doc):
    """Write BAB 2 opening, 2.1, and 2.2."""

    add_chapter_title(doc, 'BAB 2\nDESKRIPSI SISTEM')

    # ── BAB 2 Intro ─────────────────────────────────────────────
    add_para(doc,
        'Sistem ini merepresentasikan sebuah paradigma pertahanan proaktif dalam '
        'keamanan siber, yang terwujud sebagai Web-based Intrusion Detection and '
        'Prevention System (IDPS). Xpecto Shield diimplementasikan sebagai library '
        'TypeScript yang terintegrasi dengan framework Next.js, dirancang untuk '
        'membangun pertahanan website yang tidak hanya mampu mendeteksi, tetapi juga '
        'secara aktif mencegah dan memitigasi serangan siber terhadap aplikasi web '
        'secara real-time. Sistem beroperasi melalui middleware interceptor yang '
        'menganalisis setiap HTTP request masuk, serta menyediakan dashboard admin '
        'yang intuitif untuk monitoring dan pengambilan keputusan.', first_indent=True
    )

    add_para(doc,
        'Fungsionalitas inti sistem ini bertumpu pada tiga pilar utama yang saling '
        'terintegrasi untuk menciptakan sebuah lapisan keamanan yang komprehensif:'
    )

    add_bold_para(doc, 'Deteksi Real-time')
    add_para(doc,
        'Sistem secara berkelanjutan memonitor dan menganalisis seluruh permintaan '
        'HTTP yang masuk, termasuk URL path, query parameters, header HTTP, cookie, '
        'dan request body. Kemampuan ini memastikan tidak ada lalu lintas yang luput '
        'dari pengawasan, memungkinkan identifikasi ancaman pada titik masuk paling '
        'awal menggunakan algoritma Aho-Corasick multi-pattern matching.',
        indent=True
    )

    add_bold_para(doc, 'Pencegahan Otomatis')
    add_para(doc,
        'Ketika sebuah permintaan teridentifikasi sebagai ancaman dengan skor '
        'kepercayaan di atas threshold yang dikonfigurasi, sistem tidak hanya '
        'mencatatnya, tetapi juga mengambil tindakan pencegahan secara instan. '
        'Ini mencakup pemblokiran permintaan berbahaya sebelum mencapai logika '
        'inti aplikasi dan secara otomatis memasukkan alamat IP penyerang ke dalam '
        'daftar blokir berdasarkan mekanisme strike count. Mekanisme ini secara '
        'signifikan mempersempit peluang bagi penyerang untuk melakukan eksploitasi '
        'lebih lanjut.',
        indent=True
    )

    add_bold_para(doc, 'Analitik Cerdas Berbasis AI')
    add_para(doc,
        'Sistem ini mengintegrasikan analitik berbasis Kecerdasan Buatan (AI) '
        'melalui OpenAI-compatible chat completions API yang bersifat provider-agnostic. '
        'Dengan meneruskan data insiden serangan ke Large Language Model (LLM) '
        'eksternal, sistem memperoleh analisis mendalam mengenai pola serangan, '
        'penilaian tingkat ancaman, dan rekomendasi mitigasi yang adaptif. Pendekatan '
        'ini mengubah data mentah serangan menjadi intelijen keamanan yang dapat '
        'ditindaklanjuti.',
        indent=True
    )

    # ═════════════════════════════════════════════════════════════
    # 2.1 DESKRIPSI PERMASALAHAN
    # ═════════════════════════════════════════════════════════════
    add_heading_numbered(doc, '2.1 DESKRIPSI PERMASALAHAN')

    add_para(doc,
        'Aplikasi web modern merupakan aset digital vital bagi organisasi, namun '
        'sekaligus menjadi target utama serangan siber. Ancaman terus berevolusi, '
        'dengan penyerang mengembangkan teknik yang semakin canggih untuk '
        'mengeksploitasi kerentanan. Kegagalan dalam melindungi aplikasi web dapat '
        'mengakibatkan konsekuensi yang merusak, termasuk pencurian data sensitif, '
        'kerugian finansial yang signifikan, kerusakan reputasi, dan gangguan '
        'operasional.', first_indent=True
    )

    add_para(doc,
        'Selain itu, penyerang semakin mahir menggunakan teknik evasion untuk '
        'melewati sistem deteksi tradisional. Teknik seperti double URL encoding, '
        'HTML entity encoding, Unicode fullwidth substitution, null byte injection, '
        'dan Base64 encoding digunakan untuk menyamarkan payload serangan agar tidak '
        'terdeteksi oleh Web Application Firewall (WAF) konvensional. Hal ini '
        'menuntut sistem deteksi yang tidak hanya mencocokkan pattern, tetapi juga '
        'mampu menormalisasi input melalui proses dekoding berlapis sebelum '
        'melakukan analisis.', first_indent=True
    )

    add_para(doc,
        'Sistem Xpecto Shield IDPS dirancang secara spesifik untuk mengatasi '
        'serangkaian vektor serangan yang paling umum dan merusak yang menargetkan '
        'logika aplikasi dan penanganan input pengguna. Sistem ini memfokuskan '
        'pertahanannya pada lima jenis teknik eksploitasi utama yang secara konsisten '
        'menjadi ancaman serius menurut OWASP Top 10:', first_indent=True
    )

    attacks = [
        ('SQL Injection (SQLi)', 'merupakan teknik serangan yang memanfaatkan celah keamanan pada aplikasi web dengan menyisipkan kode SQL berbahaya melalui input pengguna. Serangan ini dapat memberikan akses tidak sah ke database, memungkinkan penyerang untuk mengambil, memodifikasi, atau menghapus data sensitif.'),
        ('Cross-Site Scripting (XSS)', 'adalah serangan yang menyisipkan skrip berbahaya ke dalam halaman web yang dilihat oleh pengguna lain. Serangan ini dapat mencuri informasi sesi, melakukan tindakan atas nama pengguna, atau mengalihkan pengguna ke situs berbahaya.'),
        ('Path Traversal', 'memungkinkan penyerang mengakses file dan direktori yang berada di luar direktori root aplikasi web. Serangan ini dapat mengekspos file konfigurasi sensitif, kode sumber, atau data sistem yang seharusnya tidak dapat diakses.'),
        ('Server-Side Request Forgery (SSRF)', 'adalah serangan yang memaksa server untuk melakukan permintaan HTTP ke sistem internal atau eksternal yang tidak diinginkan. Serangan ini dapat digunakan untuk menjelajahi jaringan internal atau mengakses layanan yang seharusnya tidak dapat dijangkau dari luar.'),
        ('Local File Inclusion (LFI)', 'memungkinkan penyerang untuk menyertakan file lokal yang tidak dimaksudkan untuk diakses, yang dapat mengakibatkan eksekusi kode berbahaya atau pengungkapan informasi sensitif.'),
    ]

    for title, desc in attacks:
        add_para_mixed(doc, [
            (title + ' ', True),
            (desc, False),
        ])

    # ═════════════════════════════════════════════════════════════
    # 2.2 DESKRIPSI SOLUSI
    # ═════════════════════════════════════════════════════════════
    add_heading_numbered(doc, '2.2 DESKRIPSI SOLUSI')

    add_para(doc,
        'Untuk mengatasi permasalahan keamanan siber yang kompleks, dikembangkan '
        'Xpecto Shield — AI-Driven Web Intrusion Detection & Prevention System. '
        'Sistem ini merupakan solusi komprehensif yang menggabungkan '
        'deteksi berbasis signature menggunakan algoritma Aho-Corasick, multi-layer '
        'input decoding, confidence scoring, pencegahan otomatis berbasis strike count, '
        'dan analitik AI untuk memberikan perlindungan berlapis terhadap ancaman '
        'modern.', first_indent=True
    )

    # Tabel Klasifikasi
    add_para(doc,
        'Berikut adalah klasifikasi mengenai teknik ancaman OWASP Top 10 yang '
        'ditangani oleh sistem:'
    )

    add_table_simple(doc,
        ['No', 'Kategori Serangan', 'Contoh Payload', 'Jumlah Pola'],
        [
            ['1', 'SQL Injection (SQLi)', "' OR 1=1 --\nUNION SELECT * FROM users\n' AND SLEEP(5)--", '~600'],
            ['2', 'Cross-Site Scripting (XSS)', '<script>alert(1)</script>\n<img onerror=alert(1)>\njavascript:void(0)', '~5.500'],
            ['3', 'Path Traversal', '../../etc/passwd\n..\\windows\\system32\n....//....//etc/shadow', '~2.500'],
            ['4', 'Server-Side Request Forgery (SSRF)', 'http://169.254.169.254\nhttp://localhost:8080\nhttp://[::1]', '~150'],
            ['5', 'Local File Inclusion (LFI)', '/etc/passwd%00\nphp://filter/convert.base64\ndata://text/plain;base64,...', '~2.300'],
        ],
        caption='Tabel 2.1: Klasifikasi Teknik Serangan dan Payload'
    )

    # ── 2.2.1 Mekanisme Deteksi ─────────────────────────────────
    add_sub_heading(doc, '2.2.1 Mekanisme Deteksi Presisi Tinggi Berbasis Aho-Corasick')

    add_para(doc,
        'Inti dari kemampuan pertahanan sistem ini terletak pada mekanisme deteksi '
        'berbasis signature (Signature-based Intrusion Detection System atau SIDS) '
        'yang menggunakan algoritma Aho-Corasick. Pendekatan ini dipilih karena '
        'kemampuannya yang terbukti dalam mendeteksi serangan yang telah diketahui '
        'dengan tingkat akurasi yang sangat tinggi dan false positive yang rendah, '
        'serta efisiensi dalam mencocokkan ribuan pola secara simultan.', first_indent=True
    )

    add_bold_para(doc, 'Payload Database')
    add_para(doc,
        'Sistem menggunakan database berisi ~11.050 payload serangan yang '
        'dikategorikan ke dalam lima file terpisah berdasarkan jenis ancaman: '
        'sqli.txt, xss.txt, lfi.txt, ssrf.txt, dan path-traversal.txt. Setiap file '
        'berisi satu pola serangan per baris yang dimuat ke dalam Aho-Corasick '
        'automaton saat inisialisasi sistem.',
        indent=True
    )

    add_bold_para(doc, 'Algoritma Aho-Corasick Multi-Pattern String Matching')
    add_para(doc,
        'Berbeda dengan pendekatan Regular Expression (Regex) tradisional yang '
        'memproses setiap pola secara individual, algoritma Aho-Corasick membangun '
        'sebuah finite automaton dari seluruh pola serangan sekaligus. Proses '
        'pembangunan automaton terdiri dari dua tahap:', indent=True
    )

    add_numbered(doc, [
        'Pembangunan Trie: Seluruh pola serangan dimasukkan ke dalam struktur data trie, dimana setiap node merepresentasikan satu karakter dan setiap jalur dari root ke leaf merepresentasikan satu pola lengkap.',
        'Inisialisasi Failure Links: Menggunakan algoritma Breadth-First Search (BFS), failure links dibuat untuk setiap node dalam trie. Failure links memungkinkan automaton untuk melompat ke posisi yang tepat ketika terjadi ketidakcocokan, tanpa perlu memulai pencarian dari awal.',
    ])

    add_para(doc,
        'Setelah automaton terbangun, pencarian dilakukan dalam single pass melalui '
        'seluruh input dengan kompleksitas waktu O(n + m + z), dimana n adalah '
        'panjang input, m adalah total panjang semua pola, dan z adalah jumlah '
        'kecocokan yang ditemukan. Ini jauh lebih efisien dibandingkan pencocokan '
        'regex per pola yang memiliki kompleksitas O(n × k) dimana k adalah jumlah '
        'pola.', first_indent=True
    )

    add_bold_para(doc, 'Multi-Layer Input Decoder')
    add_para(doc,
        'Sebelum input dianalisis oleh detection engine, seluruh input melewati '
        'pipeline dekoding berlapis yang dirancang untuk mengalahkan teknik evasion. '
        'Pipeline ini terdiri dari enam lapisan dekoding yang dieksekusi secara berurutan:', indent=True
    )

    add_numbered(doc, [
        'Double URL Decoding: Mengonversi encoding persen ganda (%25XX → %XX → karakter asli) untuk menangani teknik double encoding.',
        'URL Decoding: Mengonversi encoding persen standar (%XX) menjadi karakter asli.',
        'HTML Entity Decoding: Mengonversi entitas HTML bernama (&lt;, &amp;), desimal (&#60;), dan heksadesimal (&#x3c;) menjadi karakter asli.',
        'Unicode Normalization: Mengonversi karakter fullwidth Unicode (U+FF01–U+FF5E) menjadi ekuivalen ASCII, menangani teknik substitusi Unicode.',
        'Null Byte Removal: Menghapus null bytes dan representasinya (%00, \\0, \\\\0, \\\\x00) yang digunakan untuk memotong validasi input.',
        'Base64 Detection & Decoding: Mendeteksi dan mendekode segmen yang di-encode menggunakan Base64 (minimal 16 karakter dan valid Base64 charset).',
    ])

    add_bold_para(doc, 'Precision Validation dan Confidence Scoring')
    add_para(doc,
        'Setelah kandidat kecocokan ditemukan oleh Aho-Corasick automaton, '
        'sistem melakukan validasi presisi untuk menghitung skor kepercayaan '
        '(confidence score) yang menentukan apakah kecocokan tersebut merupakan '
        'ancaman nyata atau false positive. Perhitungan skor terdiri dari tiga '
        'komponen:', indent=True
    )

    add_numbered(doc, [
        'Base Score (0.6): Skor dasar yang diberikan untuk setiap kecocokan yang ditemukan.',
        'Length Ratio Bonus (0–0.2): Bonus berdasarkan rasio panjang pola terhadap panjang input. Pola yang panjang dalam input yang pendek mengindikasikan ancaman dengan tingkat kepercayaan lebih tinggi.',
        'Context Keyword Bonus (0–0.2): Bonus berdasarkan keberadaan kata kunci kontekstual yang relevan dengan kategori serangan (misalnya, kata "SELECT", "UNION", "DROP" untuk SQL Injection, atau "script", "onerror", "alert" untuk XSS).',
    ])

    add_para(doc,
        'Total skor maksimum adalah 1.0. Ancaman hanya dilaporkan jika skor '
        'kepercayaan melebihi threshold yang dikonfigurasi (default: 0.7). '
        'Mekanisme ini secara signifikan mengurangi false positive, karena '
        'kecocokan yang bersifat kebetulan (misalnya, kata "select" dalam konteks '
        'non-SQL) tidak akan melewati threshold karena kurangnya konteks pendukung.',
        first_indent=True
    )

    # ── 2.2.2 Alur Kerja Pencegahan dan Mitigasi ────────────────
    add_sub_heading(doc, '2.2.2 Alur Kerja Pencegahan dan Mitigasi Otomatis')

    add_para(doc,
        'Sistem beroperasi melalui alur kerja yang terotomatisasi, dirancang untuk '
        'merespons ancaman dari deteksi awal hingga mitigasi penuh.', first_indent=True
    )

    add_bold_para(doc, 'Deteksi Real-time')
    add_numbered(doc, [
        'Input Monitoring: Middleware mengintercept setiap HTTP request yang masuk ke aplikasi web dan mengekstrak seluruh input yang dapat dipindai, meliputi URL path, query parameters, header HTTP, cookie, dan request body (JSON maupun form-encoded).',
        'Multi-Layer Decoding: Seluruh input yang diekstrak melewati pipeline dekoding berlapis (6 lapisan) untuk menormalisasi dan mengungkap payload yang disembunyikan menggunakan teknik evasion.',
        'Pattern Matching: Mesin deteksi menggunakan Aho-Corasick automaton untuk mencocokkan seluruh input terhadap ~11.050 pola serangan secara simultan dalam satu kali pemindaian.',
        'Precision Validation: Kandidat kecocokan divalidasi menggunakan confidence scoring yang mempertimbangkan rasio panjang dan konteks kata kunci.',
        'Kategorisasi: Jika ancaman tervalidasi dengan skor di atas threshold, sistem mengklasifikasikan jenis serangan berdasarkan kategori payload yang tercocok.',
    ])

    add_bold_para(doc, 'Pencegahan dan Mitigasi')
    add_numbered(doc, [
        'Request Blocking: Permintaan berbahaya segera diblokir sebelum mencapai logika aplikasi. Sistem mengembalikan halaman blokir bertemakan cyberpunk untuk request HTML atau respons JSON error untuk API request.',
        'Strike Counting: Setiap IP yang mengirimkan request berbahaya mendapat satu strike yang disimpan di in-memory cache.',
        'Auto IP Blocking: Ketika jumlah strike dari suatu IP mencapai batas maksimum (default: 3 strike), IP tersebut secara otomatis dimasukkan ke dalam block cache dengan durasi pemblokiran yang dapat dikonfigurasi.',
        'Access Restriction: Seluruh request berikutnya dari IP yang diblokir langsung ditolak tanpa perlu melalui proses deteksi, menggunakan fast-path cache lookup.',
    ])

    add_bold_para(doc, 'Logging dan Dokumentasi')

    add_para(doc,
        'Setelah ancaman berhasil terdeteksi dan dicegah, sistem beralih ke fase '
        'dokumentasi yang menjadi fondasi untuk analisis lebih lanjut.', indent=True
    )

    add_bold_para(doc, 'Sistem Pencatatan Komprehensif')
    add_para(doc,
        'Setiap insiden keamanan yang terdeteksi dicatat secara komprehensif ke '
        'database Appwrite. Log insiden mencakup data yang kaya konteks:', indent=True
    )

    add_bullet(doc, [
        'Timestamp: Waktu pasti terjadinya serangan.',
        'Attacker IP: Alamat IP sumber penyerang.',
        'URL Path: Path yang diserang.',
        'HTTP Method: Metode HTTP yang digunakan (GET, POST, PUT, dll.).',
        'Attack Category: Kategori serangan yang terdeteksi (sqli, xss, lfi, ssrf, path-traversal).',
        'Matched Payload: Payload spesifik yang tercocok dengan database.',
        'Confidence Score: Skor kepercayaan dari hasil analisis.',
        'Raw Input: Input mentah sebelum dekoding.',
        'Action Taken: Tindakan yang diambil (blocked, logged, atau monitored).',
        'User Agent: Informasi peramban atau klien yang digunakan penyerang.',
    ], indent_cm=1.27)

    add_bold_para(doc, 'Analitik AI untuk Intelijen Ancaman')
    add_para(doc,
        'Komponen AI berfungsi untuk mengekstrak wawasan tingkat tinggi dari data '
        'serangan yang berhasil dideteksi, mengubahnya menjadi intelijen ancaman '
        'proaktif. Sistem menggunakan OpenAI-compatible chat completions API yang '
        'bersifat provider-agnostic, sehingga dapat bekerja dengan berbagai provider '
        'AI seperti OpenAI, OpenRouter, Anthropic (Claude), dan lainnya.',
        indent=True
    )

    add_para(doc,
        'Pipeline AI analytics bekerja sebagai berikut:', indent=True
    )

    add_numbered(doc, [
        'Data Preparation: Sistem menyiapkan ringkasan data insiden dan statistik keamanan yang terstruktur.',
        'Prompt Construction: System prompt dan user prompt dikonstruksi secara dinamis berdasarkan data yang tersedia, memberikan konteks spesifik kepada AI sebagai cybersecurity analyst.',
        'AI Processing: Data dan prompt dikirimkan ke LLM eksternal melalui API untuk dianalisis.',
        'Response Parsing: Respons AI di-parse menjadi laporan terstruktur yang mencakup lima komponen utama.',
    ])

    add_para(doc,
        'Laporan AI yang dihasilkan mencakup:', indent=True
    )

    add_bullet(doc, [
        'Executive Summary: Ringkasan eksekutif status keamanan untuk manajemen.',
        'Pattern Analysis: Identifikasi pola serangan yang berulang dan vektor serangan dominan.',
        'Trend Analysis: Analisis tren perubahan dalam landscape ancaman.',
        'Risk Assessment: Penilaian tingkat risiko keamanan secara keseluruhan dengan severity scoring.',
        'Recommendations: Rekomendasi tindakan pencegahan lanjutan yang spesifik dan dapat ditindaklanjuti.',
    ], indent_cm=1.27)
