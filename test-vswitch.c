/*

 * =============================================================================
 * Test-Suite für vswitch
 * =============================================================================
 * 
 * Diese Test-Suite prüft ob der vswitch korrekt funktioniert.
 * 
 * TESTPRINZIP:
 * Wir "simulieren" den network-driver! Statt dass der vswitch mit
 * echter Hardware kommuniziert, kommuniziert er mit unserem Test-Programm.
 * 
 * AUFBAU EINES TESTS:
 * 1. vswitch als Child-Prozess starten
 * 2. Pipes für stdin/stdout des vswitchs einrichten
 * 3. MAC-Adressen senden (wie der echte Driver beim Start)
 * 4. Test-Frames senden
 * 5. Empfangene Frames prüfen
 * 6. vswitch beenden
 * 
 * WICHTIG FÜR DIE BEWERTUNG:
 * - Tests müssen gegen reference-vswitch BESTEHEN (return 0)
 * - Tests müssen bug1/2/3-vswitch ERKENNEN (return != 0)
 * 
 * Das Grading-Skript kopiert buggy-Binaries zu ./vswitch und führt
 * dann "make check-vswitch" aus. Unsere Tests müssen die Bugs finden!
 */
#include "glab.h"
#include <sys/wait.h>  /* waitpid() */
#include <assert.h>    /* assert() */

/* 
 * Timeout in Sekunden für select().
 * Nicht zu kurz, sonst gibt es false negatives auf langsamen Systemen!
 */
#define TIMEOUT_SEC 2

/* ============================================================================
 * TEST-HELPER STRUKTUREN
 * 
 * Diese Strukturen müssen EXAKT mit denen im vswitch übereinstimmen!
 * ============================================================================ */

/* pack(1) = keine Padding-Bytes, exaktes Speicher-Layout */
_Pragma("pack(push)") _Pragma("pack(1)")

/**
 * Standard Ethernet Header (ohne VLAN-Tag)
 * 
 * Grösse: 14 Bytes
 */
struct EthernetHeader {
    struct MacAddress dst;   /* 6 Bytes: Ziel-MAC */
    struct MacAddress src;   /* 6 Bytes: Quell-MAC */
    uint16_t tag;            /* 2 Bytes: EtherType */
};

/**
 * 802.1Q Tagged Ethernet Header
 * 
 * Grösse: 18 Bytes
 */
struct QHeader {
    struct MacAddress dst;   /* 6 Bytes: Ziel-MAC */
    struct MacAddress src;   /* 6 Bytes: Quell-MAC */
    uint16_t tpid;           /* 2 Bytes: Tag Protocol ID (0x8100) */
    uint16_t tci;            /* 2 Bytes: Tag Control Info (enthält VLAN-ID) */
    uint16_t tag;            /* 2 Bytes: Eigentlicher EtherType */
};

_Pragma("pack(pop)")

/* 802.1Q Tag Protocol Identifier */
#define ETH_802_1Q_TAG 0x8100

/* ============================================================================
 * GLOBALE VARIABLEN FÜR DIE KOMMUNIKATION MIT DEM VSWITCH
 * ============================================================================ */

/* 
 * Pipes für Inter-Process Communication (IPC)
 * 
 * to_vswitch:   Wir schreiben -> vswitch liest (sein stdin)
 * from_vswitch: vswitch schreibt -> Wir lesen (sein stdout)
 * 
 * Jede Pipe hat zwei File-Deskriptoren:
 * [0] = Lese-Ende
 * [1] = Schreib-Ende
 */
static int to_vswitch[2];
static int from_vswitch[2];

/* Process ID des vswitch Child-Prozesses */
static pid_t vswitch_pid;

/* 
 * Test-MAC-Adressen
 * 
 * Diese repräsentieren "virtuelle Hosts" in unserem Test-Netzwerk.
 * 
 * WICHTIG: Das erste Byte muss GERADE sein für Unicast-Adressen!
 * Ungerade = Multicast-Bit gesetzt.
 */
static struct MacAddress mac1 = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x01}};
static struct MacAddress mac2 = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x02}};
static struct MacAddress mac3 = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x03}};

/* Broadcast-Adresse: Alle Bits auf 1 */
static struct MacAddress broadcast = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};

/* 
 * Interface-MAC-Adressen
 * 
 * Diese werden dem vswitch beim Start mitgeteilt (simuliert Hardware-MACs).
 * In der Realität würde der network-driver diese vom Betriebssystem holen.
 */
static struct MacAddress ifc_mac1 = {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}};
static struct MacAddress ifc_mac2 = {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02}};
static struct MacAddress ifc_mac3 = {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x03}};

/* Wird nicht genutzt, aber für Vollständigkeit da */
static int test_failed = 0;

/* ============================================================================
 * KOMMUNIKATIONSFUNKTIONEN
 * 
 * Diese Funktionen implementieren das Protokoll des network-drivers.
 * ============================================================================ */

/**
 * Sendet die initialen MAC-Adressen an den vswitch.
 * 
 * HINTERGRUND:
 * Der echte network-driver sendet beim Start eine Nachricht mit type=0,
 * die alle Interface-MAC-Adressen enthält. Der vswitch braucht diese,
 * um zu wissen welche MAC-Adressen seine eigenen Ports haben.
 * 
 * FORMAT der Nachricht:
 * [GLAB_MessageHeader]
 *   .size = 4 + (num_ifc * 6)
 *   .type = 0 (Kontrollnachricht)
 * [MAC 1 (6 Bytes)]
 * [MAC 2 (6 Bytes)]
 * ...
 * [MAC n (6 Bytes)]
 * 
 * @param num_ifc Anzahl der Interfaces
 * @param macs Array der MAC-Adressen (in Interface-Reihenfolge!)
 */
static void
send_macs(int num_ifc, struct MacAddress *macs)
{
    /* Berechne Grösse des Payloads: num_ifc MACs à 6 Bytes */
    size_t payload_size = num_ifc * sizeof(struct MacAddress);
    
    /* Header erstellen */
    struct GLAB_MessageHeader hdr = {
        .size = htons(sizeof(hdr) + payload_size),  /* Gesamtgrösse */
        .type = htons(0)  /* type=0 bedeutet Kontrollnachricht */
    };
    
    /* Header schreiben */
    write(to_vswitch[1], &hdr, sizeof(hdr));
    
    /* MAC-Adressen schreiben */
    write(to_vswitch[1], macs, payload_size);
}

/**
 * Sendet einen Frame an den vswitch auf einem bestimmten Interface.
 * 
 * HINTERGRUND:
 * In der Realität würde der network-driver einen Frame von der
 * Netzwerkkarte lesen und ihn an den vswitch weiterleiten.
 * Wir simulieren das, indem wir Frames direkt senden.
 * 
 * FORMAT der Nachricht:
 * [GLAB_MessageHeader]
 *   .size = 4 + frame_size
 *   .type = interface_nummer (1-basiert!)
 * [Ethernet Frame (variable Länge)]
 * 
 * @param ifc Interface-Nummer (1, 2, 3, ...) auf dem der Frame "ankommt"
 * @param frame Die Frame-Daten (Ethernet-Header + Payload)
 * @param frame_size Grösse des Frames in Bytes
 */
static void
send_frame(uint16_t ifc, const void *frame, size_t frame_size)
{
    struct GLAB_MessageHeader hdr = {
        .size = htons(sizeof(hdr) + frame_size),
        .type = htons(ifc)  /* Interface-Nummer als Type */
    };
    
    write(to_vswitch[1], &hdr, sizeof(hdr));
    write(to_vswitch[1], frame, frame_size);
}

/**
 * Versucht einen Frame vom vswitch zu empfangen (mit Timeout).
 * 
 * HINTERGRUND:
 * Der vswitch schreibt Frames, die er weiterleiten will, auf stdout.
 * Wir lesen diese und prüfen ob sie korrekt sind.
 * 
 * TIMEOUT:
 * Wir wollen nicht ewig warten, wenn der vswitch nichts sendet.
 * select() erlaubt uns zu warten mit einer maximalen Zeit.
 * 
 * @param buf Buffer für den empfangenen Frame
 * @param buf_size Grösse des Buffers
 * @param out_size [OUTPUT] Tatsächliche Grösse des empfangenen Frames
 * @param timeout_ms Maximale Wartezeit in Millisekunden
 * @return Interface-Nummer (>0), 0 bei Timeout, -1 bei Fehler
 */
static int
receive_frame(void *buf, size_t buf_size, size_t *out_size, int timeout_ms)
{
    fd_set fds;               /* Menge von File-Deskriptoren für select() */
    struct timeval tv;        /* Timeout-Struktur */
    struct GLAB_MessageHeader hdr;
    
    /*
     * select() vorbereiten
     * 
     * FD_ZERO: Menge leeren
     * FD_SET: Unseren Lese-Deskriptor hinzufügen
     */
    FD_ZERO(&fds);
    FD_SET(from_vswitch[0], &fds);
    
    /* Timeout konvertieren: Millisekunden -> Sekunden + Mikrosekunden */
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    /*
     * select() wartet bis:
     * - Daten verfügbar sind (return > 0)
     * - Timeout abläuft (return 0)
     * - Fehler auftritt (return < 0)
     * 
     * Parameter: max_fd+1, read_fds, write_fds, except_fds, timeout
     */
    if (select(from_vswitch[0] + 1, &fds, NULL, NULL, &tv) <= 0)
        return 0;  /* Timeout oder Fehler -> kein Frame empfangen */
    
    /* Header lesen */
    if (read(from_vswitch[0], &hdr, sizeof(hdr)) != sizeof(hdr))
        return -1;  /* Konnte Header nicht lesen -> Fehler */
    
    /* Werte aus Network Byte Order konvertieren */
    uint16_t size = ntohs(hdr.size) - sizeof(hdr);  /* Payload-Grösse */
    uint16_t type = ntohs(hdr.type);                /* Interface-Nummer */
    
    /* Passt der Frame in unseren Buffer? */
    if (size > buf_size)
        return -1;  /* Buffer zu klein */
    
    /* Frame-Daten lesen */
    if (read(from_vswitch[0], buf, size) != size)
        return -1;  /* Konnte Frame nicht vollständig lesen */
    
    /* Erfolg! */
    *out_size = size;
    return type;  /* Interface-Nummer zurückgeben */
}

/**
 * Startet den vswitch als Child-Prozess.
 * 
 * PROZESS-HIERARCHIE:
 * 
 * test-vswitch (Parent)
 *       |
 *       +---> vswitch (Child)
 * 
 * KOMMUNIKATION über Pipes:
 * 
 * test-vswitch                    vswitch
 *     |                              |
 *     |-- to_vswitch[1] -----> stdin (to_vswitch[0])
 *     |                              |
 *     +-- from_vswitch[0] <--- stdout (from_vswitch[1])
 * 
 * @param args NULL-terminiertes Array von Argumenten (wie für execv)
 *             args[0] = Programmname ("./vswitch")
 *             args[1], args[2], ... = Interface-Spezifikationen
 * @return 0 bei Erfolg, -1 bei Fehler
 */
static int
start_vswitch(char **args)
{
    /*
     * SCHRITT 1: Pipes erstellen
     * 
     * pipe() erstellt eine unidirektionale Verbindung:
     * - Was in [1] geschrieben wird, kann aus [0] gelesen werden
     */
    if (pipe(to_vswitch) < 0 || pipe(from_vswitch) < 0) {
        perror("pipe");
        return -1;
    }
    
    /*
     * SCHRITT 2: Prozess forken
     * 
     * fork() erstellt eine Kopie des aktuellen Prozesses.
     * - Im Parent: fork() gibt Child-PID zurück (> 0)
     * - Im Child: fork() gibt 0 zurück
     * - Bei Fehler: fork() gibt -1 zurück
     */
    vswitch_pid = fork();
    if (vswitch_pid < 0) {
        perror("fork");
        return -1;
    }
    
    if (vswitch_pid == 0) {
        /*
         * CHILD-PROZESS (wird zum vswitch)
         * 
         * Wir müssen stdin/stdout auf unsere Pipes umleiten.
         */
        
        /*
         * dup2(oldfd, newfd) macht newfd zu einer Kopie von oldfd.
         * Nach dup2(to_vswitch[0], STDIN_FILENO) liest stdin aus der Pipe.
         */
        dup2(to_vswitch[0], STDIN_FILENO);
        dup2(from_vswitch[1], STDOUT_FILENO);
        
        /* Nicht mehr benötigte Pipe-Enden schliessen */
        close(to_vswitch[0]);
        close(to_vswitch[1]);
        close(from_vswitch[0]);
        close(from_vswitch[1]);
        
        /*
         * execv() ersetzt den aktuellen Prozess durch ein neues Programm.
         * args[0] = Programm-Pfad
         * args = Argument-Array (muss mit NULL enden)
         * 
         * WICHTIG: execv kehrt nur bei Fehler zurück!
         */
        execv(args[0], args);
        
        /* Nur erreicht wenn execv fehlschlägt */
        perror("execv");
        exit(1);
    }
    
    /*
     * PARENT-PROZESS (Test-Programm)
     * 
     * Wir brauchen nur:
     * - to_vswitch[1] zum Schreiben
     * - from_vswitch[0] zum Lesen
     * 
     * Die anderen Enden schliessen wir.
     */
    close(to_vswitch[0]);
    close(from_vswitch[1]);
    
    return 0;
}

/**
 * Beendet den vswitch-Prozess.
 * 
 * AUFRÄUMEN:
 * 1. Pipes schliessen (signalisiert EOF an den vswitch)
 * 2. SIGTERM senden (höfliche Aufforderung zum Beenden)
 * 3. Warten bis der Prozess beendet ist (Zombie vermeiden!)
 */
static void
stop_vswitch(void)
{
    /* Pipes schliessen */
    close(to_vswitch[1]);
    close(from_vswitch[0]);
    
    /* Signal zum Beenden senden */
    kill(vswitch_pid, SIGTERM);
    
    /*
     * Auf Prozessende warten.
     * 
     * WICHTIG: Ohne waitpid() würde ein "Zombie-Prozess" entstehen!
     * Der Kernel behält Informationen über beendete Child-Prozesse,
     * bis der Parent sie mit wait() abholt.
     */
    waitpid(vswitch_pid, NULL, 0);
}

/* ============================================================================
 * FRAME-BUILDER FUNKTIONEN
 * 
 * Diese Funktionen erstellen Ethernet-Frames für unsere Tests.
 * ============================================================================ */

/**
 * Erstellt einen UNTAGGED Ethernet-Frame.
 * 
 * FRAME-AUFBAU:
 * [Destination MAC (6 Bytes)]
 * [Source MAC (6 Bytes)]
 * [EtherType (2 Bytes)]
 * [Payload (variable)]
 * 
 * @param buf Buffer für den Frame (muss gross genug sein!)
 * @param dst Ziel-MAC-Adresse
 * @param src Quell-MAC-Adresse
 * @param ethertype EtherType (z.B. 0x0800 für IPv4)
 * @param payload Payload-Daten (kann NULL sein)
 * @param payload_len Länge des Payloads
 * @return Gesamtlänge des erstellten Frames
 */
static size_t
build_frame(void *buf, struct MacAddress *dst, struct MacAddress *src, 
            uint16_t ethertype, const void *payload, size_t payload_len)
{
    struct EthernetHeader *eh = buf;
    
    /* Header befüllen */
    eh->dst = *dst;
    eh->src = *src;
    eh->tag = htons(ethertype);  /* Network Byte Order! */
    
    /* Payload kopieren (falls vorhanden) */
    if (payload && payload_len > 0)
        memcpy((char*)buf + sizeof(*eh), payload, payload_len);
    
    return sizeof(*eh) + payload_len;
}

/**
 * Erstellt einen 802.1Q TAGGED Ethernet-Frame.
 * 
 * FRAME-AUFBAU:
 * [Destination MAC (6 Bytes)]
 * [Source MAC (6 Bytes)]
 * [TPID = 0x8100 (2 Bytes)]
 * [TCI = VLAN-ID (2 Bytes)]
 * [EtherType (2 Bytes)]
 * [Payload (variable)]
 * 
 * @param buf Buffer für den Frame
 * @param dst Ziel-MAC-Adresse
 * @param src Quell-MAC-Adresse
 * @param vlan_id VLAN-ID (0-4095)
 * @param ethertype EtherType
 * @param payload Payload-Daten
 * @param payload_len Länge des Payloads
 * @return Gesamtlänge des erstellten Frames
 */
static size_t
build_tagged_frame(void *buf, struct MacAddress *dst, struct MacAddress *src,
                   uint16_t vlan_id, uint16_t ethertype, 
                   const void *payload, size_t payload_len)
{
    struct QHeader *qh = buf;
    
    /* Header befüllen */
    qh->dst = *dst;
    qh->src = *src;
    qh->tpid = htons(ETH_802_1Q_TAG);    /* 0x8100 kennzeichnet VLAN-Tag */
    qh->tci = htons(vlan_id & 0x0FFF);   /* Nur untere 12 Bits = VLAN-ID */
    qh->tag = htons(ethertype);
    
    /* Payload kopieren */
    if (payload && payload_len > 0)
        memcpy((char*)buf + sizeof(*qh), payload, payload_len);
    
    return sizeof(*qh) + payload_len;
}

/* ============================================================================
 * TESTFÄLLE
 * 
 * Jeder Test prüft einen Aspekt der vswitch-Funktionalität.
 * Return: 0 = Test bestanden, 1 = Test fehlgeschlagen
 * ============================================================================ */

/**
 * TEST 1: Broadcast Flooding
 * 
 * ERWARTETES VERHALTEN:
 * Ein Broadcast-Frame (Ziel = FF:FF:FF:FF:FF:FF) auf Port 1 soll
 * an ALLE anderen Ports im gleichen VLAN gesendet werden, aber
 * NICHT zurück an Port 1.
 * 
 * SETUP:
 * - 3 Interfaces: eth0, eth1, eth2 (alle im Default-VLAN 0)
 * - Broadcast von Port 1
 * 
 * ERWARTUNG:
 * - Port 2: empfängt Frame ✓
 * - Port 3: empfängt Frame ✓
 * - Port 1: empfängt NICHT (wäre Rücksendung an Quelle)
 */
static int
test_broadcast_flooding(void)
{
    /* Argumente für vswitch: 3 einfache Interfaces */
    char *args[] = {"./vswitch", "eth0", "eth1", "eth2", NULL};
    char frame[64], recv_buf[128];
    size_t frame_len, recv_len;
    
    /* Tracking: Auf welchen Interfaces haben wir Frames empfangen? */
    int received_on[4] = {0};  /* Index 0 ungenutzt, 1-3 für Interfaces */
    
    fprintf(stderr, "Test: Broadcast flooding... ");
    
    /* vswitch starten */
    if (start_vswitch(args) < 0) return 1;
    
    /* MAC-Adressen senden (simuliert Driver-Startup) */
    struct MacAddress macs[3] = {ifc_mac1, ifc_mac2, ifc_mac3};
    send_macs(3, macs);
    
    /* Kurz warten damit vswitch bereit ist */
    usleep(50000);  /* 50ms */
    
    /* Broadcast-Frame erstellen und auf Interface 1 senden */
    frame_len = build_frame(frame, &broadcast, &mac1, 0x0800, "test", 4);
    send_frame(1, frame, frame_len);
    
    /* 
     * Frames empfangen und tracken
     * 
     * Wir versuchen 3x zu empfangen (mit Timeout), weil wir maximal
     * 2 Frames erwarten (Port 2 und 3).
     */
    for (int i = 0; i < 3; i++) {
        int ifc = receive_frame(recv_buf, sizeof(recv_buf), &recv_len, 500);
        if (ifc > 0 && ifc <= 3)
            received_on[ifc] = 1;
    }
    
    /* vswitch beenden */
    stop_vswitch();
    
    /* PRÜFUNG: Frame muss auf Port 2 und 3 angekommen sein */
    if (!received_on[2] || !received_on[3]) {
        fprintf(stderr, "FAILED (broadcast not flooded to all interfaces)\n");
        return 1;
    }
    
    /* PRÜFUNG: Frame darf NICHT auf Port 1 angekommen sein */
    if (received_on[1]) {
        fprintf(stderr, "FAILED (broadcast sent back to source interface)\n");
        return 1;
    }
    
    fprintf(stderr, "OK\n");
    return 0;
}

/**
 * TEST 2: MAC Learning
 * 
 * ERWARTETES VERHALTEN:
 * Wenn ein Frame von MAC-Adresse X auf Port 1 ankommt, soll der vswitch
 * lernen: "X ist auf Port 1 erreichbar". Spätere Frames AN X sollen
 * nur an Port 1 gehen, nicht geflutet werden.
 * 
 * SETUP:
 * 1. mac1 sendet Broadcast auf Port 1 (vswitch lernt: mac1 -> Port 1)
 * 2. mac2 sendet Unicast AN mac1 auf Port 2
 * 
 * ERWARTUNG:
 * Der Unicast geht NUR an Port 1 (nicht geflutet an Port 3!)
 */
static int
test_mac_learning(void)
{
    char *args[] = {"./vswitch", "eth0", "eth1", "eth2", NULL};
    char frame[64], recv_buf[128];
    size_t frame_len, recv_len;
    
    fprintf(stderr, "Test: MAC learning... ");
    
    if (start_vswitch(args) < 0) return 1;
    
    struct MacAddress macs[3] = {ifc_mac1, ifc_mac2, ifc_mac3};
    send_macs(3, macs);
    usleep(50000);
    
    /* 
     * SCHRITT 1: mac1 "lernen" lassen
     * 
     * Wir senden einen Broadcast VON mac1 auf Port 1.
     * Der vswitch sieht die Quell-MAC und lernt: mac1 -> Port 1
     */
    frame_len = build_frame(frame, &broadcast, &mac1, 0x0800, "learn", 5);
    send_frame(1, frame_len);
    
    /* Broadcast-Antworten "leeren" (wir interessieren uns nicht dafür) */
    while (receive_frame(recv_buf, sizeof(recv_buf), &recv_len, 200) > 0);
    
    /* 
     * SCHRITT 2: Unicast AN mac1 von Port 2 senden
     * 
     * Da der vswitch mac1 gelernt hat, sollte dieser Frame
     * NUR an Port 1 gehen!
     */
    frame_len = build_frame(frame, &mac1, &mac2, 0x0800, "reply", 5);
    send_frame(2, frame_len);
    
    /* Empfangen: Sollte nur auf Port 1 ankommen */
    int ifc = receive_frame(recv_buf, sizeof(recv_buf), &recv_len, 500);
    
    stop_vswitch();
    
    /* PRÜFUNG: Frame muss auf Port 1 ankommen */
    if (ifc != 1) {
        fprintf(stderr, "FAILED (frame not forwarded to learned port, got ifc %d)\n", ifc);
        return 1;
    }
    
    fprintf(stderr, "OK\n");
    return 0;
}

/**
 * TEST 3: VLAN Separation
 * 
 * ERWARTETES VERHALTEN:
 * Frames in VLAN 1 dürfen NICHT an Ports in VLAN 2 weitergeleitet werden!
 * VLANs sind logisch getrennte Netzwerke.
 * 
 * SETUP:
 * - eth0[U:1] = Port 1, untagged VLAN 1
 * - eth1[U:1] = Port 2, untagged VLAN 1
 * - eth2[U:2] = Port 3, untagged VLAN 2 (ANDERES VLAN!)
 * 
 * ERWARTUNG:
 * Broadcast auf Port 1 (VLAN 1) -> Port 2 (ja), Port 3 (NEIN!)
 */
static int
test_vlan_separation(void)
{
    /* Interface-Konfiguration mit VLANs */
    char *args[] = {"./vswitch", "eth0[U:1]", "eth1[U:1]", "eth2[U:2]", NULL};
    char frame[64], recv_buf[128];
    size_t frame_len, recv_len;
    int received_on[4] = {0};
    
    fprintf(stderr, "Test: VLAN separation... ");
    
    if (start_vswitch(args) < 0) return 1;
    
    struct MacAddress macs[3] = {ifc_mac1, ifc_mac2, ifc_mac3};
    send_macs(3, macs);
    usleep(50000);
    
    /* Broadcast auf Port 1 (VLAN 1) */
    frame_len = build_frame(frame, &broadcast, &mac1, 0x0800, "vlan1", 5);
    send_frame(1, frame_len);
    
    /* Frames empfangen und tracken */
    for (int i = 0; i < 3; i++) {
        int ifc = receive_frame(recv_buf, sizeof(recv_buf), &recv_len, 300);
        if (ifc > 0 && ifc <= 3)
            received_on[ifc] = 1;
    }
    
    stop_vswitch();
    
    /* PRÜFUNG: Port 2 (VLAN 1) muss Frame bekommen */
    if (!received_on[2]) {
        fprintf(stderr, "FAILED (not forwarded within same VLAN)\n");
        return 1;
    }
    
    /* PRÜFUNG: Port 3 (VLAN 2) darf Frame NICHT bekommen */
    if (received_on[3]) {
        fprintf(stderr, "FAILED (leaked to different VLAN)\n");
        return 1;
    }
    
    fprintf(stderr, "OK\n");
    return 0;
}

/**
 * TEST 4: VLAN Tagging (Untagged -> Tagged)
 * 
 * ERWARTETES VERHALTEN:
 * Wenn ein ungetaggter Frame von einem Untagged-Port kommt und an
 * einen Tagged-Port weitergeleitet wird, muss der VLAN-Tag
 * HINZUGEFÜGT werden!
 * 
 * SETUP:
 * - eth0[U:1] = Port 1, untagged VLAN 1
 * - eth1[T:1] = Port 2, tagged VLAN 1
 * 
 * ERWARTUNG:
 * Untagged Frame auf Port 1 -> Tagged Frame auf Port 2 (mit VLAN-ID 1)
 */
static int
test_vlan_tagging(void)
{
    char *args[] = {"./vswitch", "eth0[U:1]", "eth1[T:1]", NULL};
    char frame[64], recv_buf[128];
    size_t frame_len, recv_len;
    
    fprintf(stderr, "Test: VLAN tagging... ");
    
    if (start_vswitch(args) < 0) return 1;
    
    struct MacAddress macs[2] = {ifc_mac1, ifc_mac2};
    send_macs(2, macs);
    usleep(50000);
    
    /* Untagged Frame auf Port 1 senden */
    frame_len = build_frame(frame, &broadcast, &mac1, 0x0800, "data", 4);
    send_frame(1, frame_len);
    
    /* Frame auf Port 2 empfangen */
    int ifc = receive_frame(recv_buf, sizeof(recv_buf), &recv_len, 500);
    
    stop_vswitch();
    
    /* PRÜFUNG: Frame muss auf Port 2 ankommen */
    if (ifc != 2) {
        fprintf(stderr, "FAILED (not forwarded)\n");
        return 1;
    }
    
    /*
     * PRÜFUNG: Frame muss jetzt einen VLAN-Tag haben!
     * 
     * Wir interpretieren den empfangenen Frame als QHeader und prüfen:
     * 1. TPID = 0x8100 (802.1Q Tag Identifier)
     * 2. VLAN-ID = 1
     */
    struct QHeader *qh = (struct QHeader *)recv_buf;
    
    if (ntohs(qh->tpid) != ETH_802_1Q_TAG) {
        fprintf(stderr, "FAILED (no VLAN tag added)\n");
        return 1;
    }
    
    /* VLAN-ID aus TCI extrahieren (untere 12 Bits) */
    if ((ntohs(qh->tci) & 0x0FFF) != 1) {
        fprintf(stderr, "FAILED (wrong VLAN ID in tag)\n");
        return 1;
    }
    
    fprintf(stderr, "OK\n");
    return 0;
}

/**
 * TEST 5: VLAN Untagging (Tagged -> Untagged)
 * 
 * ERWARTETES VERHALTEN:
 * Wenn ein getaggter Frame von einem Tagged-Port kommt und an
 * einen Untagged-Port weitergeleitet wird, muss der VLAN-Tag
 * ENTFERNT werden!
 * 
 * SETUP:
 * - eth0[T:1] = Port 1, tagged VLAN 1
 * - eth1[U:1] = Port 2, untagged VLAN 1
 * 
 * ERWARTUNG:
 * Tagged Frame (VLAN 1) auf Port 1 -> Untagged Frame auf Port 2
 */
static int
test_vlan_untagging(void)
{
    char *args[] = {"./vswitch", "eth0[T:1]", "eth1[U:1]", NULL};
    char frame[64], recv_buf[128];
    size_t frame_len, recv_len;
    
    fprintf(stderr, "Test: VLAN untagging... ");
    
    if (start_vswitch(args) < 0) return 1;
    
    struct MacAddress macs[2] = {ifc_mac1, ifc_mac2};
    send_macs(2, macs);
    usleep(50000);
    
    /* Tagged Frame auf Port 1 senden */
    frame_len = build_tagged_frame(frame, &broadcast, &mac1, 1, 0x0800, "data", 4);
    send_frame(1, frame_len);
    
    /* Frame auf Port 2 empfangen */
    int ifc = receive_frame(recv_buf, sizeof(recv_buf), &recv_len, 500);
    
    stop_vswitch();
    
    if (ifc != 2) {
        fprintf(stderr, "FAILED (not forwarded)\n");
        return 1;
    }
    
    /*
     * PRÜFUNG: Frame darf KEINEN VLAN-Tag mehr haben!
     * 
     * Bei einem ungetaggten Frame steht an Position 12-13 der EtherType.
     * Wenn dort 0x8100 steht, ist der Frame noch getaggt -> FEHLER!
     */
    struct EthernetHeader *eh = (struct EthernetHeader *)recv_buf;
    
    if (ntohs(eh->tag) == ETH_802_1Q_TAG) {
        fprintf(stderr, "FAILED (VLAN tag not removed)\n");
        return 1;
    }
    
    fprintf(stderr, "OK\n");
    return 0;
}

/**
 * TEST 6: Multicast Flooding
 * 
 * ERWARTETES VERHALTEN:
 * Multicast-Frames (Ziel-MAC hat Bit 0 im ersten Byte gesetzt)
 * müssen wie Broadcast geflutet werden.
 * 
 * SETUP:
 * - 3 Interfaces im Default-VLAN
 * - Multicast (01:00:5E:00:00:01) von Port 1
 * 
 * ERWARTUNG:
 * Frame kommt auf Port 2 und 3 an (wie Broadcast)
 */
static int
test_multicast(void)
{
    char *args[] = {"./vswitch", "eth0", "eth1", "eth2", NULL};
    char frame[64], recv_buf[128];
    size_t frame_len, recv_len;
    int count = 0;
    
    /* IPv4 Multicast-Adresse (01:00:5E ist der Multicast-Präfix) */
    struct MacAddress multicast = {{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01}};
    
    fprintf(stderr, "Test: Multicast flooding... ");
    
    if (start_vswitch(args) < 0) return 1;
    
    struct MacAddress macs[3] = {ifc_mac1, ifc_mac2, ifc_mac3};
    send_macs(3, macs);
    usleep(50000);
    
    /* Multicast-Frame von Port 1 senden */
    frame_len = build_frame(frame, &multicast, &mac1, 0x0800, "mcast", 5);
    send_frame(1, frame, frame_len);
    
    /* Zählen auf wie vielen Ports wir empfangen */
    for (int i = 0; i < 3; i++) {
        int ifc = receive_frame(recv_buf, sizeof(recv_buf), &recv_len, 300);
        if (ifc == 2 || ifc == 3)
            count++;
    }
    
    stop_vswitch();
    
    /* PRÜFUNG: Mindestens 2 Empfänge (Port 2 und 3) */
    if (count < 2) {
        fprintf(stderr, "FAILED (multicast not flooded to all interfaces)\n");
        return 1;
    }
    
    fprintf(stderr, "OK\n");
    return 0;
}

/* ============================================================================
 * MAIN - TESTSUITE AUSFÜHREN
 * ============================================================================ */

/**
 * Hauptfunktion - Führt alle Tests aus.
 * 
 * @return 0 wenn alle Tests bestanden, sonst Anzahl der Fehler
 */
int
main(int argc, char **argv)
{
    int failures = 0;
    
    /* Ungenutzte Parameter markieren (verhindert Compiler-Warnung) */
    (void)argc;
    (void)argv;
    
    fprintf(stderr, "Running vswitch tests...\n\n");
    
    /*
     * Jeden Test ausführen und Fehler zählen.
     * 
     * Jeder Test gibt 0 (Erfolg) oder 1 (Fehler) zurück.
     * += addiert die Rückgabewerte auf.
     */
    failures += test_broadcast_flooding();
    failures += test_mac_learning();
    failures += test_vlan_separation();
    failures += test_vlan_tagging();
    failures += test_vlan_untagging();
    failures += test_multicast();
    
    fprintf(stderr, "\n%d test(s) failed.\n", failures);
    
    /*
     * Exit-Code:
     * 0 = Alle Tests bestanden
     * 1 = Mindestens ein Test fehlgeschlagen
     * 
     * Das ist wichtig für "make check-vswitch"!
     */
    return (failures > 0) ? 1 : 0;
}