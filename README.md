# Implementasi Sistem Keamanan Server Linux Menggunakan Firewall dan Fail2Ban Berbasis Log Analysis

## Deskripsi Proyek

Proyek ini merupakan implementasi sistem keamanan server Linux yang bertujuan untuk mendeteksi dan memitigasi serangan **Brute Force Attack** dan **Dictionary Attack** pada layanan Secure Shell (SSH). Sistem dirancang dengan mengintegrasikan Firewall, Fail2Ban, dan Log Analysis untuk memantau aktivitas autentikasi serta melakukan pemblokiran alamat IP yang terindikasi melakukan percobaan login berulang secara mencurigakan.

Fail2Ban bekerja dengan menganalisis log autentikasi server, khususnya pada file `/var/log/auth.log`, untuk mengidentifikasi kegagalan login berdasarkan pola yang telah ditentukan. Ketika jumlah percobaan gagal mencapai batas konfigurasi, Fail2Ban akan menjalankan mekanisme pemblokiran melalui Firewall. Mekanisme ini diharapkan dapat mengurangi risiko akses tidak sah terhadap server melalui layanan SSH.

Sistem juga dilengkapi dengan **website monitoring berbasis Python dan Flask** yang berfungsi sebagai antarmuka untuk memantau kondisi keamanan server. Dashboard menampilkan informasi terkait status server, aktivitas login SSH, kejadian keamanan, serta alamat IP yang diblokir. Selain itu, **Auditd** digunakan untuk mencatat aktivitas akses terhadap berkas sensitif, sedangkan Telegram Bot dimanfaatkan untuk mengirimkan notifikasi keamanan kepada administrator.

Pengujian dilakukan menggunakan lingkungan virtual machine dengan Ubuntu Server sebagai server yang diamankan dan Kali Linux sebagai mesin penguji. Simulasi serangan dilakukan menggunakan Hydra untuk menguji mekanisme deteksi dan pemblokiran pada layanan SSH. Pengujian tambahan mencakup reconnaissance, SQL Injection, credential stuffing, MITM/ARP spoofing, Denial of Service (DoS), low-and-slow brute force, distributed brute force, serta serangan brute force terhadap halaman login website monitoring.

Evaluasi sistem dilakukan berdasarkan waktu respons pemblokiran, keberhasilan pemblokiran, akurasi deteksi, dan waktu pengiriman notifikasi. Hasil pengujian digunakan untuk mengetahui kemampuan sistem dalam menangani berbagai skenario serangan serta mengidentifikasi keterbatasan mekanisme pertahanan yang diterapkan.

Proyek ini dikembangkan sebagai bagian dari Tugas Akhir Program Studi Teknik Komputer, Institut Teknologi Batam, tahun 2026.

## Teknologi yang Digunakan

- Ubuntu Server
- Firewall (iptables/UFW)
- Fail2Ban
- Log Analysis
- Auditd
- Python dan Flask
- Telegram Bot API
- Kali Linux dan Hydra
- Virtual Machine
