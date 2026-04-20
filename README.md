# Rayon Ntapi Crawler
Bu proje, standart Windows API katmanını atlayarak doğrudan çekirdek (kernel) fonksiyonlarını çalışma anında çözümleyen ve paralel bir iş akışı ile dosya sistemini tarayan gelişmiş bir mimari prototiptir. Projenin ana odağı, statik analiz araçlarından kaçınmak için sembol gizleme (dynamic resolution) ve XOR obfuskasyonu gibi teknikleri, Rayon'un yüksek performanslı paralellik mimarisiyle entegre etmektir.

## Amaç ve Hedef

Projenin temel amacı, düşük seviyeli sistem çağrılarını (NTAPI) kullanarak dosya sistemine en az iz bırakacak şekilde erişmek ve bu süreci çok çekirdekli sistemlerde optimize etmektir. Yazılım, hedef dosya uzantılarını XOR ile şifreleyerek statik imza taramalarından kaçınmayı ve her bir iş parçacığı için özel bellek alanları (Thread-Local Storage) kullanarak I/O operasyonlarındaki darboğazları minimize etmeyi hedefler.

## Teknik Mimari Özellikleri

### 1. Dinamik Fonksiyon Çözümleme (Runtime Resolution)
`ntdll.dll` içerisindeki fonksiyonlar (`NtOpenFile`, `NtQueryDirectoryFile`, `NtClose`) içe aktarma tablosunda (Import Address Table) görünmez. Bunun yerine `GetModuleHandleA` ve `GetProcAddress` kullanılarak bellekten çalışma anında çözümlenir. Bu teknik, programın hangi sistem çağrılarını yapacağının statik olarak analiz edilmesini zorlaştırır.

### 2. XOR Tabanlı Obfuskasyon
Hedeflenen dosya uzantıları (`.txt`, `.pdf`, `.wallet` vb.) ham metin olarak kod içerisinde yer almaz. XOR anahtarıyla şifrelenmiş bayt dizileri olarak tutulur ve sadece karşılaştırma anında bellekte çözülür. Bu, string tabanlı heuristik taramalara karşı bir savunma mekanizmasıdır.

### 3. Thread-Local Storage (TLS) Optimizasyonu
Her bir iş parçacığı için `thread_local!` makrosu ile 64 KB'lık yeniden kullanılabilir (reusable) buffer alanları atanmıştır. Bu mimari, her bir dizin sorgusunda sürekli bellek ayırma (allocation) ve serbest bırakma (deallocation) maliyetini ortadan kaldırarak tarama hızını maksimize eder.

### 4. Asenkron Raporlama ve Paralellik
Rayon'un work-stealing algoritması, dizin ağacındaki yükü tüm çekirdeklere dengeli dağıtır. Bulunan sonuçlar, `mpsc` (Multi-Producer, Single-Consumer) kanalı üzerinden ana iş parçacığına asenkron olarak iletilir, böylece tarama işlemi raporlama hızıyla kısıtlanmaz.

## İşlem Akışı

1. Çözümleme: Çalışma anında ntdll fonksiyon adresleri tespit edilir.
2. Hazırlık: XOR'lu uzantılar bellekte çözülür ve Thread-Local bufferlar hazır hale getirilir.
3. Keşif: Belirtilen kök dizinden itibaren NTAPI fonksiyonlarıyla düşük seviyeli tarama başlatılır.
4. Filtreleme: Beyaz liste (whitelist) kontrolü ile kritik sistem dizinleri (Windows, Program Files vb.) taranmaz.
5. Raporlama: Kriterlere uyan dosyalar, thread kimliği ile birlikte merkezi kanala fırlatılır.

##

```bash
cargo run --release
