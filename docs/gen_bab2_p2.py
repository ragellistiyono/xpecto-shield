"""BAB 2 content generator - Part 2: Penelitian Terkait, Desain Sistem, Mockup."""
from gen_helpers import *


def write_bab2_part2(doc):
    """Write sections 2.3 through 2.5 and Daftar Pustaka."""

    # ═════════════════════════════════════════════════════════════
    # 2.3 PENELITIAN TERKAIT
    # ═════════════════════════════════════════════════════════════
    add_heading_numbered(doc, '2.3 PENELITIAN TERKAIT')

    add_para(doc,
        'Penelitian terkait berfungsi sebagai referensi dan perbandingan terhadap '
        'penelitian yang dilakukan. Beberapa penelitian yang relevan dengan '
        'pengembangan Xpecto Shield IDPS diuraikan sebagai berikut.'
    )

    add_sub_heading(doc, '2.3.1 Deep Learning Algorithms Used in Intrusion Detection Systems [4]')
    add_para(doc,
        'Penelitian ini dilakukan oleh Richard Kimanzi, Peter Kimanga, Dedan Cherori, '
        'dan Patrick K. Gikunda dari Department of Computer Science, Dedan Kimathi '
        'University of Technology, pada tahun 2024. Penelitian ini menganalisis '
        'berbagai arsitektur Deep Learning (CNN, RNN, LSTM, GAN, GRU, dan Transformer) '
        'yang digunakan dalam Intrusion Detection System (IDS). Temuan utama mencakup '
        'keunggulan dan kelemahan masing-masing arsitektur serta tantangan umum seperti '
        'ketidakseimbangan dataset, high false positive rate, dan kebutuhan sumber daya '
        'komputasi yang besar.', first_indent=True
    )

    add_sub_heading(doc, '2.3.2 A Systematic Review on the Integration of Explainable Artificial Intelligence in Intrusion Detection Systems [5]')
    add_para(doc,
        'Penelitian ini dilakukan oleh Vincent Zibi Mohale dan Ibidun Christiana '
        'Obagbuwa dari Sol Plaatje University, South Africa, tahun 2025. Penelitian '
        'ini menekankan pentingnya Explainable AI (XAI) dalam IDS untuk meningkatkan '
        'transparansi, kepercayaan analis keamanan, dan interpretabilitas keputusan '
        'sistem. Temuan ini secara langsung mendukung desain fitur AI analytics pada '
        'Xpecto Shield, dimana laporan AI bersifat eksplisit dan memberikan penjelasan '
        'yang dapat dipahami oleh administrator.', first_indent=True
    )

    add_sub_heading(doc, '2.3.3 SSRF vs. Developers: A Study of SSRF Defenses in PHP Applications [6]')
    add_para(doc,
        'Penelitian oleh Wessels et al. yang menganalisis kerentanan SSRF dan '
        'mekanisme pertahanan dalam 27.078 aplikasi PHP open-source pada tahun 2024. '
        'Temuan menunjukkan bahwa lebih dari separuh aplikasi tidak memiliki '
        'pertahanan SSRF yang memadai. Penelitian ini menegaskan urgensi penargetan '
        'spesifik terhadap serangan SSRF dalam Xpecto Shield sebagai salah satu dari '
        'lima kategori serangan yang dideteksi.', first_indent=True
    )

    add_sub_heading(doc, '2.3.4 A Survey on Intrusion Detection System Based on Deep Learning [2]')
    add_para(doc,
        'Penelitian ini dilakukan oleh Saddam Hussain, Professor Santosh Nagar, '
        'dan Professor Anurag Shrivastava dari CSE, NIIST, pada tahun 2025. '
        'Penelitian ini mengidentifikasi tantangan utama dalam DL-IDS seperti '
        'dataset yang tidak seimbang, kurangnya real-time processing, dan '
        'kebutuhan resources tinggi. Temuan ini menginformasikan keputusan desain '
        'Xpecto Shield untuk memanfaatkan API AI eksternal (LLM) untuk analitik, '
        'sehingga menghindari overhead melatih dan menjalankan model sendiri.', first_indent=True
    )

    # Tabel perbandingan
    add_table_simple(doc,
        ['Peneliti/Sumber', 'Tahun', 'Fokus Penelitian', 'Temuan Utama', 'Relevansi'],
        [
            ['Richard Kimanzi et al.', '2024',
             'Tinjauan Deep Learning untuk IDS',
             'Kelemahan DL: dataset imbalance, false positive tinggi, resource intensive',
             'Memvalidasi pendekatan signature-based yang lebih efisien untuk deteksi known attacks'],
            ['Mohale & Obagbuwa', '2025',
             'Explainable AI dalam IDS',
             'Pentingnya transparansi AI untuk kepercayaan analis',
             'Mendukung desain AI analytics yang memberikan penjelasan eksplisit'],
            ['Wessels et al.', '2024',
             'Analisis SSRF defenses',
             '50%+ aplikasi tanpa pertahanan SSRF memadai',
             'Menegaskan urgensi deteksi SSRF sebagai salah satu kategori'],
            ['Hussain et al.', '2025',
             'Survey IDS berbasis Deep Learning',
             'Tantangan: real-time processing, resources tinggi',
             'Mendukung keputusan menggunakan AI eksternal via API'],
        ],
        caption='Tabel 2.2: Perbandingan Penelitian Terkait'
    )

    # ═════════════════════════════════════════════════════════════
    # 2.4 DESAIN SISTEM
    # ═════════════════════════════════════════════════════════════
    add_heading_numbered(doc, '2.4 DESAIN SISTEM')

    add_para(doc,
        'Desain sistem merupakan sebuah tahap dalam pengembangan sistem yang '
        'terdiri dari proses pendefinisian arsitektur, komponen, modul, antarmuka, '
        'dan data untuk memenuhi persyaratan yang telah didefinisikan. Tahap ini '
        'memfasilitasi identifikasi potensi masalah sejak dini sehingga solusi '
        'dapat diimplementasikan secara tepat.', first_indent=True
    )

    # ── 2.4.1 Desain Alur Sistem ────────────────────────────────
    add_sub_heading(doc, '2.4.1 Desain Alur Sistem')

    add_bold_para(doc, 'Alur Deteksi dan Pencegahan Serangan')

    add_para(doc,
        'Alur utama sistem Xpecto Shield dalam mendeteksi dan mencegah serangan '
        'web diilustrasikan sebagai berikut:', indent=True
    )

    add_numbered(doc, [
        'HTTP Request masuk ke aplikasi Next.js dan diintercept oleh Shield Middleware.',
        'Middleware memeriksa apakah path termasuk dalam protectedPaths dan bukan excludePaths.',
        'IP klien diperiksa terhadap whitelist dan block cache. Jika IP diblokir, request langsung ditolak.',
        'Request Analyzer mengekstrak seluruh input yang dapat dipindai (URL path, query params, headers, cookies, body).',
        'Multi-Layer Input Decoder menormalisasi seluruh input melalui 6 lapisan dekoding.',
        'Detection Engine (Aho-Corasick) melakukan multi-pattern matching terhadap seluruh input.',
        'Precision Validator menghitung confidence score untuk setiap kandidat kecocokan.',
        'Jika ancaman terdeteksi (score > threshold), sistem mencatat strike untuk IP tersebut.',
        'Jika jumlah strike mencapai maxStrikes, IP otomatis diblokir.',
        'Incident log dibuat dan dikirim ke backend (Appwrite) secara asinkron.',
        'Block response dikembalikan ke klien (HTML page atau JSON error).',
        'Jika tidak ada ancaman, request diteruskan ke aplikasi.',
    ])

    add_bold_para(doc, 'Alur Admin dengan Analitik AI')

    add_para(doc,
        'Administrator sistem berinteraksi dengan dashboard untuk memonitor, '
        'menganalisis, dan mengelola data serangan:', indent=True
    )

    add_numbered(doc, [
        'Admin mengakses dashboard dan melihat statistik keamanan real-time (total serangan, IP diblokir, distribusi kategori).',
        'Admin melihat daftar insiden serangan dengan detail lengkap dan dapat melakukan filter serta pencarian.',
        'Admin mengelola daftar IP yang diblokir (unblock manual, lihat detail strike).',
        'Admin memilih data insiden untuk dianalisis dan men-trigger AI Analytics.',
        'Sistem mengirimkan data insiden terstruktur ke LLM eksternal melalui OpenAI-compatible API.',
        'AI memproses data dan menghasilkan laporan komprehensif (executive summary, pattern analysis, trend analysis, risk assessment, recommendations).',
        'Laporan AI ditampilkan di dashboard dan disimpan ke database Appwrite untuk referensi.',
        'Admin dapat mengonfigurasi parameter sistem seperti confidence threshold, maximum strikes, dan durasi pemblokiran.',
    ])

    # ── 2.4.2 Desain Sistem Arsitektur ──────────────────────────
    add_sub_heading(doc, '2.4.2 Desain Sistem Arsitektur')

    add_para(doc,
        'Xpecto Shield dikembangkan sebagai library TypeScript yang terintegrasi '
        'dengan framework Next.js. Arsitektur sistem terdiri dari empat lapisan '
        'utama yang saling terintegrasi:', first_indent=True
    )

    # Architecture components
    add_bold_para(doc, 'TypeScript + Next.js (Framework)')
    add_para(doc,
        'TypeScript digunakan sebagai bahasa pemrograman utama karena menyediakan '
        'static typing yang memastikan keamanan tipe data di seluruh codebase. '
        'Next.js 15.5+ dengan App Router digunakan sebagai full-stack framework '
        'yang mendukung dua mode runtime:', indent=True
    )
    add_bullet(doc, [
        'Node.js Runtime: Mendukung filesystem access untuk memuat payload dari file secara dinamis.',
        'Edge Runtime: Mode ringan yang menggunakan compiled payloads yang sudah di-bundle untuk performa optimal di environment serverless seperti Vercel Edge Functions.',
    ], indent_cm=1.27)

    add_para(doc,
        'Pemilihan Next.js didasarkan pada popularitasnya sebagai framework React '
        'full-stack terdepan dan dukungannya terhadap middleware native yang '
        'memungkinkan intercept request di level framework, sebelum request '
        'mencapai logika aplikasi.',
        indent=True
    )

    add_bold_para(doc, 'Core Layer — Detection Engine')
    add_para(doc,
        'Core layer mencakup seluruh komponen inti yang bertanggung jawab untuk '
        'deteksi ancaman:', indent=True
    )
    add_bullet(doc, [
        'AhoCorasickAutomaton: Implementasi algoritma Aho-Corasick untuk multi-pattern matching. Membangun trie dan failure links saat inisialisasi, kemudian melakukan pencarian dalam O(n) per request.',
        'InputDecoder: Pipeline dekoding berlapis 6 tahap untuk normalisasi input dan mengalahkan teknik evasion.',
        'DetectionEngine: Modul koordinasi yang menggabungkan input decoding, Aho-Corasick matching, dan precision validation menjadi satu pipeline analisis.',
        'PayloadLoader: Modul untuk memuat payload dari filesystem (Node.js) atau compiled data (Edge).',
    ], indent_cm=1.27)

    add_bold_para(doc, 'Middleware Layer — Request Interception')
    add_para(doc,
        'Middleware layer bertanggung jawab untuk mengintercept dan memproses '
        'setiap HTTP request:', indent=True
    )
    add_bullet(doc, [
        'ShieldMiddleware: Fungsi middleware utama yang mengorkestrasi seluruh proses dari intercept, analisis, hingga respons.',
        'RequestAnalyzer: Mengekstrak dan memflatkan seluruh input yang dapat dipindai dari HTTP request.',
        'StrikeManager: Mengelola strike count per IP menggunakan in-memory cache dengan pembersihan periodik.',
        'BlockResponseBuilder: Membuat respons blokir bertemakan cyberpunk (HTML untuk browser, JSON untuk API).',
    ], indent_cm=1.27)

    add_bold_para(doc, 'API Layer — Dashboard Backend')
    add_para(doc,
        'API layer menyediakan endpoint RESTful untuk dashboard admin:', indent=True
    )
    add_bullet(doc, [
        'DashboardAPI (createShieldAPI): Route handler untuk operasi CRUD terhadap insiden, IP yang diblokir, laporan AI, dan pengaturan sistem.',
        'AppwriteIntegration: Modul integrasi dengan Appwrite Cloud sebagai Backend-as-a-Service, menangani penyimpanan insiden, manajemen blocked IPs, dan penyimpanan laporan AI.',
        'AIAnalytics (createAIAnalytics): Pipeline analisis AI yang menggunakan OpenAI-compatible API untuk menghasilkan laporan keamanan dari data insiden.',
    ], indent_cm=1.27)

    add_bold_para(doc, 'Dashboard Layer — Admin Interface')
    add_para(doc,
        'Dashboard layer menyediakan antarmuka admin untuk monitoring:', indent=True
    )
    add_bullet(doc, [
        'ShieldDashboard: Komponen React utama yang menampilkan statistik, daftar insiden, IP yang diblokir, laporan AI, dan pengaturan sistem.',
        'DashboardStyles: File CSS dengan desain cyberpunk-themed untuk tampilan yang modern dan fungsional.',
    ], indent_cm=1.27)

    add_bold_para(doc, 'Appwrite (Backend-as-a-Service)')
    add_para(doc,
        'Appwrite Cloud digunakan sebagai Backend-as-a-Service untuk menggantikan '
        'database relasional tradisional. Appwrite menyediakan document-based database '
        'yang digunakan untuk menyimpan empat jenis data utama:', indent=True
    )
    add_bullet(doc, [
        'Collection incidents: Menyimpan log insiden serangan dengan seluruh detail.',
        'Collection blocked_ips: Menyimpan daftar IP yang diblokir beserta metadata.',
        'Collection ai_reports: Menyimpan laporan analisis AI yang dihasilkan.',
        'Collection settings: Menyimpan konfigurasi sistem yang dapat disesuaikan.',
    ], indent_cm=1.27)
    add_para(doc,
        'Pemilihan Appwrite didasarkan pada kemudahan integrasi melalui SDK '
        '(node-appwrite), skema fleksibel yang cocok untuk data insiden yang '
        'bervariasi, dan kemampuan query filtering yang memadai untuk kebutuhan '
        'dashboard.', indent=True
    )

    # ── 2.4.3 Use Case Diagram ──────────────────────────────────
    add_sub_heading(doc, '2.4.3 Use Case Diagram')

    add_para(doc,
        'Use Case Diagram menggambarkan interaksi antara aktor dengan sistem '
        'Xpecto Shield IDPS, serta menampilkan hubungan dan keterkaitan antar '
        'use case yang tersedia.', first_indent=True
    )

    add_bold_para(doc, 'Web Administrator')
    add_para(doc,
        'Pengguna yang memiliki peran penting dalam menjaga keamanan sistem. '
        'Tugas utamanya meliputi pemantauan aktivitas sistem dan log keamanan, '
        'konfigurasi mekanisme deteksi serangan, serta pengelolaan respons '
        'terhadap ancaman melalui dashboard admin. Administrator dapat melihat '
        'statistik real-time, mengelola IP yang diblokir, men-trigger analisis AI, '
        'dan mengonfigurasi parameter sistem.',
        indent=True
    )

    add_bold_para(doc, 'External User / Attacker')
    add_para(doc,
        'Aktor eksternal yang mengirimkan HTTP request ke aplikasi web. Request '
        'dari aktor ini diintercept oleh Shield Middleware. Jika request '
        'mengandung payload serangan yang terdeteksi, sistem secara otomatis '
        'memblokir request dan mencatat insiden. Aktor ini tidak berinteraksi '
        'langsung dengan sistem — seluruh interaksi terjadi melalui HTTP request '
        'yang diproses oleh middleware.',
        indent=True
    )

    # ── 2.4.4 Data Flow Diagram ─────────────────────────────────
    add_sub_heading(doc, '2.4.4 Data Flow Diagram')

    add_para(doc,
        'Data Flow Diagram (DFD) menggambarkan aliran data antara entitas '
        'luar dengan sistem, serta memperlihatkan bagaimana data diproses, '
        'disimpan, dan diteruskan antar komponen dalam Xpecto Shield.',
        first_indent=True
    )

    add_bold_para(doc, 'DFD Level 0')
    add_para(doc,
        'Xpecto Shield menerima input dari External User berupa HTTP Request '
        '(yang mungkin mengandung payload serangan). Sistem memproses request '
        'tersebut dan menghasilkan dua output utama: (1) Response ke External '
        'User berupa halaman yang diminta (jika aman) atau halaman blokir (jika '
        'terdeteksi ancaman), dan (2) Data insiden dan laporan keamanan ke Admin '
        'melalui dashboard.', indent=True
    )

    add_bold_para(doc, 'DFD Level 1')
    add_para(doc,
        'Pada level ini, sistem dirinci menjadi empat proses utama:', indent=True
    )
    add_numbered(doc, [
        'Request Interception: Middleware mengintercept HTTP request dan mengekstrak input yang dapat dipindai.',
        'Threat Detection: Detection engine menganalisis input menggunakan multi-layer decoder dan Aho-Corasick automaton.',
        'Response & Prevention: Sistem memblokir request berbahaya, mencatat strike, dan melakukan auto-blocking IP.',
        'Analytics & Reporting: Data insiden dikirim ke Appwrite dan dapat dianalisis menggunakan AI analytics.',
    ])

    add_bold_para(doc, 'DFD Level 2 — Threat Detection')
    add_para(doc,
        'Proses Threat Detection dirinci menjadi sub-proses:', indent=True
    )
    add_numbered(doc, [
        'Input Extraction: RequestAnalyzer mengekstrak URL path, query params, headers, cookies, dan body.',
        'Multi-Layer Decoding: InputDecoder menjalankan 6 lapisan dekoding secara berurutan.',
        'Aho-Corasick Matching: Automaton melakukan multi-pattern search terhadap input yang telah didekode.',
        'Precision Validation: Confidence scoring menghitung skor berdasarkan length ratio dan context keywords.',
        'Whitelist Check: Input dicocokkan dengan daftar whitelist untuk menghindari false positive.',
    ])

    add_bold_para(doc, 'DFD Level 2 — Response & Prevention')
    add_para(doc,
        'Proses Response & Prevention dirinci menjadi sub-proses:', indent=True
    )
    add_numbered(doc, [
        'Strike Recording: StrikeManager mencatat strike untuk IP penyerang di in-memory cache.',
        'Auto-Block Decision: Jika strike >= maxStrikes, IP ditambahkan ke block cache.',
        'Incident Logging: Log insiden dikirim ke Appwrite secara asinkron melalui callback.',
        'Block Response: BlockResponseBuilder membuat respons blokir (HTML atau JSON) dan mengirimkannya ke klien.',
    ])

    add_bold_para(doc, 'DFD Level 2 — AI Analytics')
    add_para(doc,
        'Proses AI Analytics dirinci menjadi sub-proses:', indent=True
    )
    add_numbered(doc, [
        'Data Aggregation: Mengumpulkan dan merangkum data insiden dari Appwrite.',
        'Prompt Construction: Membuat system prompt dan user prompt dengan data insiden terstruktur.',
        'LLM API Call: Mengirimkan prompt ke OpenAI-compatible API.',
        'Response Parsing: Parse respons AI menjadi laporan terstruktur (AIReport).',
        'Report Storage: Menyimpan laporan ke collection ai_reports di Appwrite.',
    ])

    # ── 2.4.5 Entity Relationship Diagram ───────────────────────
    add_sub_heading(doc, '2.4.5 Entity Relationship Diagram')

    add_para(doc,
        'ERD sistem Xpecto Shield dirancang berdasarkan collections '
        'yang digunakan pada Appwrite. Struktur data utama meliputi empat '
        'entitas yang saling berelasi:', first_indent=True
    )

    add_bold_para(doc, '1. Incidents (Log Insiden Serangan)')
    add_para(doc,
        'Menyimpan setiap insiden serangan yang terdeteksi. Atribut meliputi: '
        'incident_id (auto-generated), timestamp, attacker_ip, url_path, '
        'http_method, attack_category, matched_payload, confidence_score, '
        'raw_input, decoded_input, action_taken, user_agent, dan request_id.',
        indent=True
    )

    add_bold_para(doc, '2. Blocked IPs (Daftar IP Diblokir)')
    add_para(doc,
        'Menyimpan daftar IP yang diblokir secara otomatis maupun manual. '
        'Atribut meliputi: block_id, ip_address, reason, strike_count, '
        'blocked_at, expires_at, last_attack_category, is_permanent, dan '
        'is_active.',
        indent=True
    )

    add_bold_para(doc, '3. AI Reports (Laporan Analisis AI)')
    add_para(doc,
        'Menyimpan laporan yang dihasilkan oleh AI analytics. Atribut meliputi: '
        'report_id, generated_at, period_start, period_end, executive_summary, '
        'pattern_analysis, trend_analysis, risk_assessment, recommendations, '
        'threat_level, total_incidents_analyzed, dan model_used.',
        indent=True
    )

    add_bold_para(doc, '4. Settings (Konfigurasi Sistem)')
    add_para(doc,
        'Menyimpan konfigurasi sistem yang dapat disesuaikan oleh administrator. '
        'Atribut meliputi: setting_key, setting_value, dan updated_at. Contoh '
        'pengaturan: confidence_threshold, max_strikes, block_duration, dan '
        'protected_paths.',
        indent=True
    )

    # ═════════════════════════════════════════════════════════════
    # 2.5 MOCKUP WEBSITE
    # ═════════════════════════════════════════════════════════════
    add_heading_numbered(doc, '2.5 MOCKUP WEBSITE')

    add_para(doc,
        'Mockup merupakan representasi visual dari sebuah produk untuk '
        'memberikan gambaran sebelum produk tersebut diimplementasikan. User '
        'interface terdiri dari tata letak halaman, warna, ikon, dan tipografi. '
        'Berikut merupakan mockup dari dashboard admin Xpecto Shield IDPS.',
        first_indent=True
    )

    mockups = [
        ('Login Page',
         'Halaman ini berfungsi sebagai gerbang utama untuk mengakses dashboard '
         'dan fitur-fitur manajemen. Administrator harus memasukkan username dan '
         'password yang valid untuk dapat masuk ke dalam sistem. Ini adalah lapisan '
         'keamanan pertama untuk memastikan hanya pihak yang berwenang yang dapat '
         'mengelola dan memonitor sistem.'),
        ('Dashboard Sidebar Admin',
         'Menu navigasi utama yang menjadi pusat kendali sistem. Menu ini '
         'memberikan akses cepat ke semua modul fungsional: Beranda (ringkasan '
         'status keamanan), Deteksi Serangan (log dan detail serangan yang '
         'terdeteksi), Daftar IP Diblokir (pengelolaan IP yang diblokir), '
         'Laporan AI (laporan analisis keamanan), dan Pengaturan (konfigurasi '
         'parameter sistem).'),
        ('Dashboard Admin (Beranda)',
         'Halaman Beranda menyajikan pandangan at-a-glance dari status keamanan '
         'sistem. Menampilkan metrik kunci: Total Attacks Detected, IPs Blocked, '
         'Active Threats, dan System Health. Tabel "Recent Attack Detections" '
         'menampilkan daftar serangan terbaru dengan jenis serangan, waktu, IP '
         'pelaku, dan payload yang digunakan.'),
        ('Dashboard Admin — Deteksi Serangan',
         'Halaman Deteksi Serangan menyediakan analisis mendalam tentang semua '
         'ancaman yang terdeteksi. Administrator dapat melakukan pencarian dan '
         'filtering berdasarkan IP, payload, jenis serangan, confidence score, '
         'dan rentang waktu.'),
        ('Dashboard Admin — Daftar IP Diblokir',
         'Halaman Blocked IPs merupakan inti dari fungsi pencegahan. Menampilkan '
         'semua IP yang telah diblokir dengan informasi alasan pemblokiran, '
         'jumlah strike, status (permanen atau temporer), dan waktu kedaluwarsa. '
         'Administrator dapat membuka blokir atau memblokir IP permanen dari '
         'halaman ini.'),
        ('Dashboard Admin — Laporan AI',
         'Halaman AI Reports menampilkan laporan analisis keamanan yang '
         'dihasilkan oleh AI analytics. Administrator dapat men-trigger '
         'pembuatan laporan baru dan melihat laporan historis yang mencakup '
         'executive summary, pattern analysis, risk assessment, dan '
         'recommendations.'),
        ('Dashboard Admin — Pengaturan',
         'Halaman Pengaturan memungkinkan administrator mengonfigurasi parameter '
         'sistem, meliputi: Confidence Threshold (batas skor deteksi), Maximum '
         'Strikes (jumlah strike sebelum auto-block), Block Duration (durasi '
         'pemblokiran otomatis), Protected Paths (jalur yang dilindungi), dan '
         'Whitelist IPs (IP yang dikecualikan dari deteksi).'),
    ]

    for title, desc in mockups:
        add_bold_para(doc, title)
        add_para(doc, desc, indent=True)

    # ═════════════════════════════════════════════════════════════
    # DAFTAR PUSTAKA
    # ═════════════════════════════════════════════════════════════
    doc.add_page_break()
    add_heading_numbered(doc, 'Daftar Pustaka')

    refs = [
        '[1] Hoang Xuan Dau, N. T. T. T. N. T. H. (2022). A Survey of Tools and Techniques for Web Application Security.',
        '[2] Hussain, S., Nagar, S., & Shrivastava, A. (2025). A Survey on Intrusion Detection System Based on Deep Learning. 13, 1.',
        '[3] Kannan, M., & Pajasri, P. (2025). AUTOMATIC IP BLOCKING CYBERSECURITY SYSTEM. International Research Journal of Modernization in Engineering, 291. www.irjmets.com',
        '[4] Kimanzi, R., Kimanga, P., Cherori, D., & Gikunda, P. K. (2024). Deep Learning Algorithms Used in Intrusion Detection Systems -- A Review. http://arxiv.org/abs/2402.17020',
        '[5] Mohale, V. Z., & Obagbuwa, I. C. (2025). A systematic review on the integration of explainable artificial intelligence in intrusion detection systems. Frontiers in Artificial Intelligence (Vol. 8). https://doi.org/10.3389/frai.2025.1526221',
        '[6] Wessels, M., Koch, S., Pellegrino, G., & Johns, M. (2024). SSRF vs. Developers: A Study of SSRF-Defenses in PHP Applications. 33rd USENIX Security Symposium. https://www.usenix.org/conference/usenixsecurity24/presentation/wessels',
        '[7] Aho, A. V., & Corasick, M. J. (1975). Efficient String Matching: An Aid to Bibliographic Search. Communications of the ACM, 18(6), 333–340.',
    ]

    for ref in refs:
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        run = p.add_run(ref)
        run.font.name = 'Times New Roman'
        run.font.size = Pt(12)
        p.paragraph_format.line_spacing_rule = WD_LINE_SPACING.ONE_POINT_FIVE
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.left_indent = Cm(1.27)
        p.paragraph_format.first_line_indent = Cm(-1.27)
