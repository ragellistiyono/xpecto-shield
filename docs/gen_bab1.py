"""BAB 1 content generator."""
from gen_helpers import *


def write_bab1(doc):
    add_chapter_title(doc, 'BAB 1 PENDAHULUAN')

    # ── 1.1 LATAR BELAKANG ──────────────────────────────────────
    add_heading_numbered(doc, '1.1 LATAR BELAKANG')

    add_para(doc,
        'Perkembangan teknologi informasi yang pesat telah menjadikan aplikasi web '
        'sebagai tulang punggung operasional berbagai organisasi, mulai dari layanan '
        'perbankan, e-commerce, hingga sistem pemerintahan. Namun, seiring dengan '
        'meningkatnya ketergantungan terhadap aplikasi web, ancaman keamanan siber juga '
        'mengalami eskalasi yang signifikan. Berdasarkan laporan OWASP (Open Worldwide '
        'Application Security Project), serangan terhadap aplikasi web terus mendominasi '
        'lanskap ancaman siber global, dengan teknik eksploitasi seperti SQL Injection, '
        'Cross-Site Scripting (XSS), dan Server-Side Request Forgery (SSRF) yang tetap '
        'menjadi vektor serangan utama.', first_indent=True
    )

    add_para(doc,
        'Keamanan aplikasi web menjadi isu kritis karena sifatnya yang terekspos '
        'secara publik melalui internet. Setiap parameter input yang diterima oleh '
        'aplikasi — baik melalui URL, formulir, header HTTP, maupun cookie — berpotensi '
        'menjadi titik masuk bagi penyerang untuk melakukan eksploitasi. Ketidakmampuan '
        'sistem dalam mendeteksi dan mencegah serangan secara real-time dapat '
        'mengakibatkan konsekuensi yang merusak, termasuk pencurian data sensitif, '
        'kerugian finansial yang signifikan, kerusakan reputasi, dan gangguan operasional '
        'yang berkepanjangan.', first_indent=True
    )

    add_para(doc,
        'Intrusion Detection and Prevention System (IDPS) hadir sebagai salah satu '
        'solusi pertahanan yang paling efektif untuk menanggulangi ancaman tersebut. '
        'IDPS bekerja dengan memonitor lalu lintas jaringan atau aktivitas sistem untuk '
        'mendeteksi aktivitas berbahaya dan mengambil tindakan pencegahan secara otomatis. '
        'Pendekatan signature-based detection, dimana sistem mencocokkan input terhadap '
        'database pola serangan yang diketahui, terbukti sangat efektif dengan tingkat '
        'akurasi tinggi dan false positive yang rendah untuk mendeteksi serangan yang '
        'telah terdokumentasi.', first_indent=True
    )

    add_para(doc,
        'Dalam konteks ini, algoritma multi-pattern string matching memainkan peran '
        'krusial. Algoritma Aho-Corasick, yang dikembangkan oleh Alfred V. Aho dan '
        'Margaret J. Corasick pada tahun 1975, memungkinkan pencocokan ribuan pola '
        'serangan secara simultan dalam satu kali pemindaian input dengan kompleksitas '
        'waktu linier O(n + m + z), dimana n adalah panjang input, m adalah total '
        'panjang semua pola, dan z adalah jumlah kecocokan. Efisiensi ini menjadikan '
        'Aho-Corasick sangat cocok untuk diterapkan pada IDPS yang membutuhkan kecepatan '
        'deteksi real-time.', first_indent=True
    )

    add_para(doc,
        'Selain mekanisme deteksi, integrasi kecerdasan buatan (Artificial Intelligence) '
        'memberikan dimensi tambahan yang signifikan pada kemampuan IDPS. Dengan '
        'memanfaatkan Large Language Model (LLM) sebagai AI analytics, sistem tidak hanya '
        'mampu mendeteksi dan mencegah serangan, tetapi juga menganalisis pola serangan '
        'secara mendalam, memberikan penilaian tingkat ancaman, dan menghasilkan '
        'rekomendasi mitigasi yang kontekstual dan dapat ditindaklanjuti. Pendekatan ini '
        'mengubah data mentah serangan menjadi intelijen keamanan yang bernilai tinggi.', first_indent=True
    )

    add_para(doc,
        'Berdasarkan latar belakang tersebut, penelitian ini mengembangkan '
        'Xpecto Shield — sebuah AI-Driven Web Intrusion Detection & Prevention System '
        '(IDPS) yang diimplementasikan sebagai library TypeScript terintegrasi dengan '
        'framework Next.js. Sistem ini menggabungkan algoritma Aho-Corasick untuk '
        'pencocokan multi-pattern presisi tinggi, multi-layer input decoder untuk '
        'mengalahkan teknik evasion, confidence scoring untuk mengurangi false positive, '
        'dan AI analytics berbasis LLM untuk menghasilkan laporan keamanan komprehensif. '
        'Xpecto Shield dirancang sebagai solusi end-to-end yang mampu mendeteksi, '
        'mencegah, dan mendokumentasikan serangan siber terhadap aplikasi web secara '
        'real-time.', first_indent=True
    )

    # ── 1.2 RUMUSAN MASALAH ─────────────────────────────────────
    add_heading_numbered(doc, '1.2 RUMUSAN MASALAH')

    add_para(doc,
        'Berdasarkan latar belakang yang telah diuraikan, berikut rumusan masalah '
        'dalam penelitian ini:'
    )

    add_numbered(doc, [
        'Bagaimana merancang dan mengimplementasikan sistem deteksi serangan web berbasis algoritma Aho-Corasick yang mampu mencocokkan ribuan pola serangan secara simultan dengan performa real-time?',
        'Bagaimana mengimplementasikan mekanisme multi-layer input decoding yang efektif dalam mengalahkan berbagai teknik evasion (URL encoding, HTML entities, Unicode normalization, Base64 encoding) yang digunakan penyerang untuk melewati sistem deteksi?',
        'Bagaimana membangun sistem pencegahan otomatis (IP blocking) berbasis strike count yang mampu merespons ancaman yang terdeteksi secara real-time?',
        'Bagaimana mengintegrasikan AI analytics berbasis Large Language Model (LLM) untuk menghasilkan laporan analisis keamanan yang komprehensif dari data insiden serangan?',
        'Bagaimana mengimplementasikan seluruh sistem sebagai library TypeScript yang terintegrasi dengan framework Next.js dan kompatibel dengan Node.js Runtime maupun Edge Runtime?',
    ])

    # ── 1.3 BATASAN MASALAH ─────────────────────────────────────
    add_heading_numbered(doc, '1.3 BATASAN MASALAH')

    add_para(doc,
        'Batasan masalah dalam pengembangan sistem ini adalah sebagai berikut:'
    )

    add_numbered(doc, [
        'Sistem dikembangkan sebagai library TypeScript bernama Xpecto Shield yang terintegrasi dengan framework Next.js versi 15.5 ke atas menggunakan App Router.',
        'Teknologi yang digunakan meliputi TypeScript sebagai bahasa pemrograman utama, Next.js sebagai full-stack framework, Appwrite sebagai Backend-as-a-Service (database dan autentikasi), React untuk komponen dashboard, dan OpenAI-compatible API sebagai AI analytics provider.',
        'Deteksi serangan dibatasi pada lima kategori teknik eksploitasi utama: SQL Injection (SQLi), Cross-Site Scripting (XSS), Path Traversal, Server-Side Request Forgery (SSRF), dan Local File Inclusion (LFI).',
        'Algoritma deteksi menggunakan Aho-Corasick multi-pattern string matching dengan precision validation dan confidence scoring, bukan machine learning classifier.',
        'Fitur mitigasi otomatis terbatas pada IP blocking berbasis strike count dan request blocking; tidak menggunakan honeypot atau deception technology.',
        'Sistem beroperasi sebagai middleware interceptor dengan fokus deteksi real-time; tidak mencakup analisis forensik mendalam atau threat hunting capabilities kompleks.',
        'AI analytics menggunakan Large Language Model (LLM) eksternal melalui OpenAI-compatible chat completions API; sistem bersifat provider-agnostic dan tidak melatih model sendiri.',
    ])

    # ── 1.4 TUJUAN ──────────────────────────────────────────────
    add_heading_numbered(doc, '1.4 TUJUAN')

    add_para(doc,
        'Penelitian proyek akhir ini bertujuan untuk mengembangkan Xpecto Shield, '
        'sebuah AI-Driven Web Intrusion Detection & Prevention System (IDPS) yang '
        'diimplementasikan sebagai library TypeScript terintegrasi dengan framework '
        'Next.js. Sistem ini mengimplementasikan algoritma Aho-Corasick untuk '
        'mencocokkan ribuan pola serangan web secara simultan dengan performa real-time, '
        'dilengkapi multi-layer input decoder untuk mengalahkan teknik evasion, serta '
        'confidence scoring untuk mengurangi false positive.', first_indent=True
    )

    add_para(doc,
        'Sistem dirancang untuk mendeteksi lima kategori teknik eksploitasi utama — '
        'SQL Injection, XSS, Path Traversal, SSRF, dan LFI — kemudian '
        'mengklasifikasikan dan merespons ancaman secara otomatis melalui mekanisme '
        'IP blocking berbasis strike count. Setiap insiden serangan yang terdeteksi '
        'dicatat secara komprehensif ke database Appwrite dan dapat dianalisis '
        'menggunakan AI analytics berbasis LLM untuk menghasilkan laporan keamanan '
        'yang mencakup ringkasan eksekutif, analisis pola, penilaian risiko, dan '
        'rekomendasi mitigasi kontekstual.', first_indent=True
    )

    add_para(doc,
        'Seluruh hasil deteksi dan analisis ditampilkan melalui dashboard admin '
        'berbasis React yang menyediakan monitoring real-time, sehingga administrator '
        'dapat mengambil keputusan keamanan berdasarkan data yang akurat dan terkini. '
        'Sistem ini bertujuan untuk memberikan solusi keamanan yang komprehensif, '
        'mudah diintegrasikan, dan berdaya guna tinggi bagi developer dan administrator '
        'aplikasi web.', first_indent=True
    )

    # ── 1.5 MANFAAT ─────────────────────────────────────────────
    add_heading_numbered(doc, '1.5 MANFAAT')

    add_para(doc,
        'Xpecto Shield sebagai AI-Driven Web IDPS dengan pendekatan Aho-Corasick '
        'multi-pattern matching merupakan solusi dalam upaya peningkatan keamanan '
        'aplikasi web terhadap ancaman eksploitasi kerentanan. Pendekatan ini '
        'menyajikan deteksi real-time yang memudahkan identifikasi dan pencegahan '
        'serangan berdasarkan lima kategori teknik eksploitasi utama. Manfaat dari '
        'penelitian ini adalah sebagai berikut:'
    )

    add_bold_para(doc, 'Bagi Organisasi dan Perusahaan')
    add_para(doc,
        'Penelitian ini menyediakan sistem perlindungan proaktif yang memberikan '
        'keamanan berlapis terhadap serangan siber dengan cakupan deteksi SQL Injection, '
        'XSS, Path Traversal, SSRF, dan LFI. Hal ini memberikan dukungan perlindungan '
        'aset digital berbasis data dalam pencegahan kerugian finansial dan reputasi, '
        'serta memudahkan monitoring ancaman keamanan secara kontinu. Sistem ini '
        'mengurangi downtime website dan memastikan kontinuitas bisnis dengan biaya '
        'yang optimal dibandingkan potensi kerugian dari serangan siber yang berhasil.',
        indent=True
    )

    add_bold_para(doc, 'Bagi Developer dan Administrator Website')
    add_para(doc,
        'Developer memperoleh manfaat berupa library yang mudah diintegrasikan ke '
        'dalam proyek Next.js dengan konfigurasi minimal. Administrator website '
        'mendapatkan dashboard intuitif yang memungkinkan monitoring real-time tanpa '
        'memerlukan keahlian mendalam dalam keamanan siber. Integrasi AI analytics '
        'memberikan wawasan mendalam mengenai landscape ancaman melalui laporan '
        'keamanan yang komprehensif, sehingga mendorong waktu respons yang lebih cepat '
        'dan pengambilan keputusan yang berbasis data.',
        indent=True
    )

    add_bold_para(doc, 'Bagi Akademis dan Komunitas Open-Source')
    add_para(doc,
        'Penelitian ini berkontribusi pada pengembangan pengetahuan tentang '
        'penerapan algoritma Aho-Corasick dalam domain keamanan siber, '
        'khususnya sebagai mesin deteksi pada IDPS berbasis web. Selain itu, '
        'implementasi sebagai library open-source memungkinkan komunitas developer '
        'untuk mengadopsi, mengembangkan, dan berkontribusi pada peningkatan '
        'keamanan aplikasi web secara kolaboratif.',
        indent=True
    )
