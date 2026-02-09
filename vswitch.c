/*
     This file (was) part of GNUnet.
     Copyright (C) 2018 Christian Grothoff

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * =============================================================================
 * WAS IST EIN VSWITCH?
 * @disclaimer  Übersicht wurde dank Claude Opus 4.5 sauber erstellt
 * =============================================================================
 * 
 * Ein Virtual Switch (vswitch) ist eine Software-Implementierung eines 
 * Ethernet-Switches. Er verbindet mehrere Netzwerk-Interfaces und leitet
 * Ethernet-Frames zwischen ihnen weiter - genau wie ein physischer Switch.
 * 
 * HAUPTAUFGABEN EINES SWITCHES:
 * 
 * 1. MAC-LEARNING: Der Switch "merkt" sich, welche MAC-Adresse auf welchem
 *    Port erreichbar ist. Wenn ein Frame von MAC-Adresse AA:BB:CC:DD:EE:FF
 *    auf Port 1 ankommt, weiss der Switch: "Um AA:BB:CC:DD:EE:FF zu erreichen,
 *    muss ich Frames an Port 1 senden."
 * 
 * 2. FORWARDING: Wenn ein Frame für eine bekannte MAC-Adresse ankommt,
 *    wird er NUR an den Port gesendet, wo diese MAC erreichbar ist.
 *    Das spart Bandbreite im Vergleich zu einem Hub.
 * 
 * 3. FLOODING: Wenn die Ziel-MAC unbekannt ist, oder es sich um Broadcast/
 *    Multicast handelt, wird der Frame an ALLE Ports gesendet (ausser dem
 *    Eingangsport). So werden neue Geräte "entdeckt".
 * 
 * 4. VLAN-SUPPORT: VLANs (Virtual LANs) trennen ein physisches Netzwerk
 *    in mehrere logische Netzwerke. Frames eines VLANs werden nur an
 *    Ports weitergeleitet, die zu diesem VLAN gehören.
 * 
 * =============================================================================
 * VLAN-GRUNDLAGEN (IEEE 802.1Q)
 * =============================================================================
 * 
 * Ein VLAN-Tag ist ein 4-Byte-Feld, das in den Ethernet-Header eingefügt wird:
 * 
 * OHNE VLAN (untagged):
 * +--------+--------+----------+---------+
 * | DST    | SRC    | EtherType| Payload |
 * | 6 Byte | 6 Byte | 2 Byte   | ...     |
 * +--------+--------+----------+---------+
 * 
 * MIT VLAN (tagged):
 * +--------+--------+------+------+----------+---------+
 * | DST    | SRC    | TPID | TCI  | EtherType| Payload |
 * | 6 Byte | 6 Byte |0x8100| 2B   | 2 Byte   | ...     |
 * +--------+--------+------+------+----------+---------+
 *                   |<-- 4 Byte VLAN-Tag -->|
 * 
 * TPID = Tag Protocol Identifier = immer 0x8100 für 802.1Q
 * TCI  = Tag Control Information = enthält VLAN-ID (12 Bits = 0-4095)
 * 
 * PORT-TYPEN:
 * - UNTAGGED PORT: Erwartet Frames OHNE VLAN-Tag. Der Switch ordnet
 *   eingehende Frames automatisch einem konfigurierten VLAN zu.
 * - TAGGED PORT: Erwartet Frames MIT VLAN-Tag. Kann mehrere VLANs
 *   gleichzeitig transportieren (Trunk-Port).
 */
#include "glab.h"

/* ============================================================================
 * KONSTANTEN UND MAKROS
 * 
 * Diese Werte definieren die Grenzen und Standardwerte unseres Switches.
 * ============================================================================ */

/**
 * Maximale Anzahl VLANs die ein Interface unterstützen kann.
 * 
 * Der 802.1Q-Standard erlaubt VLAN-IDs von 0 bis 4095 (12 Bit).
 * VLAN 0 und 4095 sind reserviert, also 4094 nutzbare VLANs.
 */
#define MAX_VLANS 4094

/**
 * Spezieller Wert um "kein VLAN" anzuzeigen.
 * 
 * Wird verwendet wenn:
 * - Ein Interface kein untagged VLAN hat (nur tagged)
 * - Das Ende der tagged_vlans[] Liste erreicht ist
 * 
 * -1 ist ein guter Sentinel-Wert, da gültige VLAN-IDs >= 0 sind.
 */
#define NO_VLAN (-1)

/**
 * Standard-VLAN für Interfaces ohne explizite VLAN-Konfiguration.
 * 
 * Wenn ein Interface nur als "eth0" angegeben wird (ohne [U:x] oder [T:x]),
 * wird es automatisch als untagged Port für VLAN 0 konfiguriert
 */
#define DEFAULT_VLAN 0

/**
 * EtherType-Wert für 802.1Q VLAN-getaggte Frames
 */
#define ETH_802_1Q_TAG 0x8100

/**
 * Grösse der MAC-Learning-Tabelle. 
 */
#define MAC_TABLE_SIZE 1024

/**
 * Aging-Zeit für MAC-Einträge in Sekunden.
 * 
 * Wenn ein Gerät den Port wechselt oder ausgeschaltet wird, soll der
 * Switch dies irgendwann "vergessen" und nicht ewig an einen falschen
 * Port senden. Nach 300 Sekunden (5 Minuten) ohne Aktivität wird ein
 * Eintrag als "veraltet" betrachtet.
 * 
 */
#define MAC_AGING_TIME 300

/* ============================================================================
 * PAKETSTRUKTUREN
 * 
 * Diese Strukturen bilden den Aufbau von Ethernet-Frames ab.
 * 
 * WICHTIG: #pragma pack sorgt dafür, dass der Compiler KEINE Padding-Bytes
 * einfügt. Normalerweise würde der Compiler Strukturen auf 4- oder 8-Byte-
 * Grenzen ausrichten (für Performance). Bei Netzwerk-Paketen würde das aber
 * die Struktur zerstören!
 * 
 * Beispiel ohne pack:
 *   struct { char a; int b; }  ->  Grösse: 8 Bytes (3 Padding nach a)
 * Mit pack:
 *   struct { char a; int b; }  ->  Grösse: 5 Bytes (kein Padding)
 * ============================================================================ */

_Pragma("pack(push)") _Pragma("pack(1)")

/**
 * Standard Ethernet Frame Header (ohne VLAN-Tag).
 * 
 * Dies sind die ersten 14 Bytes jedes Ethernet-Frames.
 * 
 * MEMORY LAYOUT (14 Bytes total):
 * Offset 0-5:   Destination MAC (6 Bytes)
 * Offset 6-11:  Source MAC (6 Bytes)  
 * Offset 12-13: EtherType (2 Bytes, Big-Endian!)
 * 
 * Beispiel für einen IPv4-Frame an Broadcast:
 * FF FF FF FF FF FF  <- Destination: Broadcast
 * 00 11 22 33 44 55  <- Source: 00:11:22:33:44:55
 * 08 00              <- EtherType: 0x0800 = IPv4
 */
struct EthernetHeader
{
  struct MacAddress dst;   /**< Ziel-MAC: Wohin soll der Frame? */
  struct MacAddress src;   /**< Quell-MAC: Wer sendet? */
  uint16_t tag;            /**< EtherType ODER 0x8100 wenn VLAN-getaggt */
};

/**
 * IEEE 802.1Q VLAN Tag (nur der Tag selbst, 4 Bytes).
 * 
 * Dieser Tag wird zwischen Source-MAC und EtherType eingefügt.
 * 
 * MEMORY LAYOUT (4 Bytes total):
 * Offset 0-1: TPID = 0x8100 (identifiziert 802.1Q)
 * Offset 2-3: TCI  = Tag Control Information
 * 
 * TCI-Aufbau (16 Bits):
 * +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
 * |P2  |P1  |P0  |DEI |V11 |V10 |V9  |V8  |V7  |V6  |V5  |V4  |V3  |V2  |V1  |V0  |
 * +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
 * |<-- PCP -->|     |<---------------- VLAN ID (12 bits) ----------------------->|
 * 
 * PCP (3 Bits): Priority Code Point - für QoS (Quality of Service)
 * DEI (1 Bit):  Drop Eligible Indicator - darf bei Überlast gedroppt werden
 * VID (12 Bits): VLAN Identifier - die eigentliche VLAN-Nummer (0-4095)
 * 
 * Um die VLAN-ID zu extrahieren: vlan_id = ntohs(tci) & 0x0FFF;
 */
struct Q
{
  uint16_t tpid;  /**< Tag Protocol ID, MUSS 0x8100 sein */
  uint16_t tci;   /**< Tag Control Info, enthält VLAN-ID in Bits 0-11 */
};

/**
 * Vollständiger Ethernet-Header MIT 802.1Q VLAN-Tag.
 * 
 * MEMORY LAYOUT (18 Bytes total):
 * Offset 0-5:   Destination MAC
 * Offset 6-11:  Source MAC
 * Offset 12-13: TPID (0x8100)
 * Offset 14-15: TCI (enthält VLAN-ID)
 * Offset 16-17: Original EtherType
 * 
 * Vergleich tagged vs. untagged:
 * 
 * UNTAGGED: [DST 6B][SRC 6B][TYPE 2B][PAYLOAD...]  = 14 + Payload
 * TAGGED:   [DST 6B][SRC 6B][8100][TCI][TYPE 2B][PAYLOAD...] = 18 + Payload
 *                           ^^^^^^^^^^ 
 *                           4 Bytes eingefügt!
 */
struct TaggedEthernetHeader
{
  struct MacAddress dst;   /**< Ziel-MAC-Adresse */
  struct MacAddress src;   /**< Quell-MAC-Adresse */
  uint16_t tpid;           /**< 0x8100 für 802.1Q */
  uint16_t tci;            /**< VLAN-Tag mit VLAN-ID */
  uint16_t ethertype;      /**< Eigentlicher EtherType (z.B. 0x0800 für IPv4) */
};

_Pragma("pack(pop)")  /* Packing wieder auf Normal zurücksetzen */

/* ============================================================================
 * INTERFACE-STRUKTUR
 * 
 * Jedes Netzwerk-Interface (Port) des Switches hat eigene Eigenschaften.
 * ============================================================================ */

/**
 * Per-Interface context - speichert alle Infos zu einem Switch-Port.
 * 
 * KONFIGURATIONSBEISPIELE:
 * 
 * "eth0"        -> untagged_vlan = 0, tagged_vlans = {NO_VLAN}
 *                  Einfacher Access-Port für VLAN 0
 * 
 * "eth1[U:10]"  -> untagged_vlan = 10, tagged_vlans = {NO_VLAN}
 *                  Access-Port für VLAN 10 (untagged)
 * 
 * "eth2[T:10]"  -> untagged_vlan = NO_VLAN, tagged_vlans = {10, NO_VLAN}
 *                  Trunk-Port der VLAN 10 getaggt transportiert
 * 
 * "eth3[T:10,20,30]" -> untagged_vlan = NO_VLAN, tagged_vlans = {10,20,30,NO_VLAN}
 *                       Trunk-Port für mehrere VLANs
 * 
 * WICHTIG: Ein Interface ist entweder untagged ODER tagged, nie beides!
 */
struct Interface
{
  /**
   * MAC-Adresse dieses Interfaces.
   */
  struct MacAddress mac;

  /**
   * Nummer dieses Interfaces.
   * 
   * ACHTUNG: Der network-driver nummeriert Interfaces ab 1, nicht ab 0!
   * Also: eth0 = Interface 1, eth1 = Interface 2, etc.
   * 
   * Im Array gifc[] ist Interface N aber an Position N-1!
   */
  uint16_t ifc_num;

  /**
   * Name des Interfaces, z.B. "eth0", "lan1".
   * 
   * Wird aus den Kommandozeilen-Argumenten geparst.
   * Beispiel: "eth0[T:1,2]" -> ifc_name = "eth0"
   */
  char *ifc_name;

  /**
   * Liste der VLANs die auf diesem Interface TAGGED sind.
   * 
   * Das Array wird mit NO_VLAN terminiert (wie ein C-String mit '\0').
   * 
   * Beispiel für "eth0[T:1,2,5]":
   * tagged_vlans = {1, 2, 5, NO_VLAN, ?, ?, ...}
   *                          ^^^^^^^^ Ende-Marker
   * 
   * Wenn das Interface ein Untagged-Port ist: tagged_vlans[0] = NO_VLAN
   */
  int16_t tagged_vlans[MAX_VLANS + 1];  /* +1 für NO_VLAN Terminator */

  /**
   * VLAN-ID für ungetaggte Frames auf diesem Interface.
   * 
   * Wenn ein Interface als "untagged" konfiguriert ist (z.B. "eth0[U:10]"),
   * dann werden:
   * - Eingehende ungetaggte Frames dem VLAN 10 zugeordnet
   * - Ausgehende Frames für VLAN 10 ohne Tag gesendet
   * 
   * Wert NO_VLAN bedeutet: Dieses Interface akzeptiert keine untagged Frames.
   */
  int16_t untagged_vlan;
};

/* ============================================================================
 * MAC-LEARNING-TABELLE
 * 
 * Hier speichert der Switch, welche MAC-Adresse auf welchem Port ist.
 * ============================================================================ */

/**
 * Ein Eintrag in der MAC-Learning-Tabelle.
 * 
 * WARUM PRO VLAN?
 * Die gleiche MAC-Adresse kann in verschiedenen VLANs auf verschiedenen
 * Ports sein! Beispiel:
 * - Server hat zwei NICs: eine in VLAN 10 (Port 1), eine in VLAN 20 (Port 2)
 * - Beide NICs könnten theoretisch die gleiche MAC haben (ungewöhnlich, aber möglich)
 * 
 * Deshalb speichern wir: (MAC + VLAN) -> Port
 */
struct MacTableEntry
{
  struct MacAddress mac;    /**< Die gelernte MAC-Adresse */
  uint16_t ifc_num;         /**< Auf welchem Interface/Port wurde sie gesehen? */
  int16_t vlan_id;          /**< In welchem VLAN? */
  time_t last_seen;         /**< Wann wurde sie zuletzt gesehen? (für Aging) */
  int valid;                /**< Ist dieser Eintrag gültig? (1=ja, 0=nein/frei) */
};

/* ============================================================================
 * GLOBALE VARIABLEN
 * ============================================================================ */

/**
 * Anzahl der konfigurierten Interfaces.
 * 
 * Wird aus argc-1 berechnet (erstes Argument ist Programmname).
 * Beispiel: "./vswitch eth0 eth1 eth2" -> num_ifc = 3
 */
static unsigned int num_ifc;

/**
 * Zeiger auf das Array aller Interface-Strukturen.
 * 
 * Wird in main() auf ein lokales Array gesetzt.
 * Zugriff: gifc[0] = erstes Interface (Nummer 1)
 *          gifc[i-1] = Interface mit Nummer i
 */
static struct Interface *gifc;

/**
 * Die MAC-Learning-Tabelle.
 * 
 * Statisch alloziert = feste Grösse zur Compile-Zeit.
 * Vorteil: Kein malloc/free nötig, kein Speicherleck möglich.
 * Nachteil: Feste Grösse, kann nicht wachsen.
 */
static struct MacTableEntry mac_table[MAC_TABLE_SIZE];

/* ============================================================================
 * HILFSFUNKTIONEN FÜR MAC-LEARNING
 * ============================================================================ */

/**
 * Berechnet einen Hash-Wert für eine MAC-Adresse.
 * 
 * Mit einem Hash berechnen wir direkt den Index, wo die MAC sein SOLLTE.
 * 
 * KOLLISIONEN:
 * Zwei verschiedene MACs können den gleichen Hash haben!
 * 
 * @param mac Zeiger auf die MAC-Adresse (6 Bytes)
 * @return Index in die mac_table (0 bis MAC_TABLE_SIZE-1)
 */
static unsigned int
mac_hash(const struct MacAddress *mac)
{
  unsigned int hash = 0;
  
  /* Durch alle 6 Bytes der MAC-Adresse iterieren */
  for (int i = 0; i < 6; i++)
  {
    /* hash = hash * 31 + nächstes Byte */
    hash = hash * 31 + mac->mac[i];
  }
  
  /* Modulo, um im gültigen Bereich zu bleiben */
  return hash % MAC_TABLE_SIZE;
}

/**
 * Prüft, ob eine MAC-Adresse Broadcast oder Multicast ist.
 * 
 * BROADCAST: FF:FF:FF:FF:FF:FF
 * Geht an ALLE Geräte im Netzwerk.
 * 
 * MULTICAST: Erstes Byte ist ungerade (Bit 0 = 1)
 * Beispiele: 01:00:5E:xx:xx:xx (IPv4 Multicast)
 * 
 * UNICAST: Erstes Byte ist gerade (Bit 0 = 0)
 * 
 * WARUM WICHTIG?
 * - Broadcast/Multicast-Adressen dürfen NICHT in die MAC-Tabelle!
 *   Sie sind keine "echten" Quelladressen.
 * - Frames an Broadcast/Multicast werden immer geflutet, nie per Lookup.
 * 
 * @param mac Die zu prüfende MAC-Adresse
 * @return 1 wenn Broadcast/Multicast, 0 wenn Unicast
 */
static int
is_multicast_or_broadcast(const struct MacAddress *mac)
{
  /*
   * Das LSB (Least Significant Bit) des ersten Bytes zeigt an:
   * - Bit 0 = 0: Unicast
   * - Bit 0 = 1: Multicast
   * 
   * Broadcast (FF:FF:FF:FF:FF:FF) hat auch Bit 0 = 1, ist also
   * technisch gesehen ein spezieller Multicast.
   * 
   * Bitweise UND mit 0x01 extrahiert nur Bit 0:
   * mac[0] = 0b01011010 (z.B.)
   * 0x01   = 0b00000001
   * -------------------- AND
   * result = 0b00000000 = 0 -> Unicast
   * 
   * mac[0] = 0b01011011 
   * 0x01   = 0b00000001
   * -------------------- AND
   * result = 0b00000001 = 1 -> Multicast
   */
  return (mac->mac[0] & 0x01) != 0;
}

/**
 * Lernt eine MAC-Adresse und speichert sie in der Tabelle.
 * 
 * Jedes Mal wenn ein Frame empfangen wird, wird die QUELL-MAC
 * gelernt. 
 
 * Wenn ein Gerät den Port wechselt (z.B. Laptop wird umgesteckt),
 * überschreibt der neue Eintrag automatisch den alten.
 * 
 * KOLLISIONSBEHANDLUNG:
 * Bei Hash-Kollision wird der alte Eintrag einfach überschrieben.
 * 
 * @param mac Die Quell-MAC-Adresse des empfangenen Frames
 * @param ifc_num Das Interface, auf dem der Frame ankam
 * @param vlan_id Das VLAN des Frames
 */
static void
learn_mac(const struct MacAddress *mac, uint16_t ifc_num, int16_t vlan_id)
{
  /*
   * SCHRITT 1: Broadcast/Multicast ignorieren
   */
  if (is_multicast_or_broadcast(mac))
    return;

  /*
   * SCHRITT 2: Hash berechnen = Index in der Tabelle
   */
  unsigned int idx = mac_hash(mac);
  
  /*
   * SCHRITT 3: Eintrag speichern/aktualisieren
   * 
   * Wir überschreiben:
   * - Neuer Eintrag: Tabelle lernt neue MAC
   * - Update: Zeitstempel wird aktualisiert
   * - Re-Learning: MAC auf neuem Port -> alter Eintrag überschrieben
   * - Kollision: Andere MAC mit gleichem Hash -> überschrieben
   */
  mac_table[idx].mac = *mac;              /* MAC-Adresse kopieren */
  mac_table[idx].ifc_num = ifc_num;       /* Port merken */
  mac_table[idx].vlan_id = vlan_id;       /* VLAN merken */
  mac_table[idx].last_seen = time(NULL);  /* Aktuellen Zeitstempel setzen */
  mac_table[idx].valid = 1;               /* Eintrag als gültig markieren */
}

/**
 * Sucht eine MAC-Adresse in der Tabelle.
 * 
 * Bei jedem Unicast-Frame suchen wir die ZIEL-MAC in der Tabelle.
 * Wenn gefunden: Frame nur an diesen Port senden
 * Wenn nicht gefunden: Frame flooden (an alle Ports)
 * 
 * @param mac Die gesuchte Ziel-MAC-Adresse
 * @param vlan_id Das VLAN (Suche ist VLAN-spezifisch!)
 * @param out_ifc [OUTPUT] Hier wird die Interface-Nummer geschrieben
 * @return 1 wenn gefunden (out_ifc ist gültig), 0 wenn nicht gefunden
 */
static int
lookup_mac(const struct MacAddress *mac, int16_t vlan_id, uint16_t *out_ifc)
{
  /*
   * SCHRITT 1: Hash berechnen = möglicher Index
   */
  unsigned int idx = mac_hash(mac);
  
  /*
   * SCHRITT 2: Prüfen ob Eintrag gültig ist
   */
  if (!mac_table[idx].valid)
    return 0;  /* Kein gültiger Eintrag an dieser Position */
  
  /*
   * SCHRITT 3: Prüfen ob MAC übereinstimmt
   * 
   * Wegen Kollisionen könnte an diesem Index eine ANDERE MAC stehen!
   * memcmp vergleicht die 6 Bytes der MAC-Adresse.
   */
  if (memcmp(&mac_table[idx].mac, mac, sizeof(*mac)) != 0)
    return 0;  /* Kollision: Andere MAC an diesem Index */
  
  /*
   * SCHRITT 4: Prüfen ob VLAN übereinstimmt
   */
  if (mac_table[idx].vlan_id != vlan_id)
    return 0;  /* Falsche VLAN */
  
  /*
   * SCHRITT 5: Aging prüfen
   * 
   * Wenn der Eintrag zu alt ist, betrachten wir ihn als ungültig.
   * time(NULL) gibt die aktuelle Zeit in Sekunden seit 1970.
   */
  if (time(NULL) - mac_table[idx].last_seen > MAC_AGING_TIME)
  {
    mac_table[idx].valid = 0;  /* Als ungültig markieren */
    return 0;  /* Zu alt, nicht mehr verwenden */
  }
  
  /*
   * SCHRITT 6: Erfolg! Interface-Nummer zurückgeben.
   */
  *out_ifc = mac_table[idx].ifc_num;
  return 1;
}

/* ============================================================================
 * HILFSFUNKTIONEN FÜR VLAN-HANDLING
 * ============================================================================ */

/**
 * Prüft, ob ein Interface an einem bestimmten VLAN teilnimmt.
 * 
 * Ein Interface kann auf zwei Arten an einem VLAN teilnehmen:
 * 1. UNTAGGED: Das Interface ist der "Access Port" für dieses VLAN
 *    -> Frames kommen/gehen ohne VLAN-Tag
 * 2. TAGGED: Das Interface ist ein "Trunk Port" für dieses VLAN
 *    -> Frames kommen/gehen mit VLAN-Tag
 * 
 * @param ifc Das zu prüfende Interface
 * @param vlan_id Die VLAN-ID
 * @param tagged [OUTPUT] Wird auf 1 gesetzt wenn tagged, 0 wenn untagged
 * @return 1 wenn Interface im VLAN, 0 wenn nicht
 */
static int
interface_in_vlan(struct Interface *ifc, int16_t vlan_id, int *tagged)
{
  /*
   * ZUERST: Prüfen ob es das untagged VLAN dieses Interfaces ist
   */
  if (ifc->untagged_vlan == vlan_id)
  {
    *tagged = 0;  /* Untagged Port für dieses VLAN */
    return 1;     /* Ja, Interface ist im VLAN */
  }
  
  /*
   * DANN: Prüfen ob VLAN in der tagged-Liste ist
   * 
   * Das Array ist mit NO_VLAN terminiert, also durchsuchen bis Ende.
   */
  for (int i = 0; ifc->tagged_vlans[i] != NO_VLAN; i++)
  {
    if (ifc->tagged_vlans[i] == vlan_id)
    {
      *tagged = 1;  /* Tagged Port für dieses VLAN */
      return 1;     /* Ja, Interface ist im VLAN */
    }
  }
  
  /*
   * Weder untagged noch tagged -> Interface nicht in diesem VLAN
   */
  return 0;
}

/* ============================================================================
 * FRAME-VERSAND
 * ============================================================================ */

/**
 * Sendet einen Frame an den Network-Driver.
 * 
 * Der Network-Driver erwartet ein spezielles Protokoll auf stdout:
 * 
 * FORMAT:
 * [GLAB_MessageHeader (4 Bytes)][Frame-Daten (variable Länge)]
 * 
 * Der Header enthält:
 * - size: Gesamtlänge (Header + Frame) in Network Byte Order
 * - type: Interface-Nummer (1-basiert) wohin der Frame soll
 * 
 * @param ifc_num Ziel-Interface-Nummer (1, 2, 3, ...)
 * @param frame Die Frame-Daten (Ethernet-Header + Payload)
 * @param frame_size Grösse des Frames in Bytes
 */
static void
send_frame(uint16_t ifc_num, const void *frame, size_t frame_size)
{
  /*
   * GLAB_MessageHeader aufbauen
   * 
   * htons() konvertiert von Host Byte Order zu Network Byte Order.
   * Network Byte Order = Big Endian (höchstwertiges Byte zuerst)
   * 
   * Beispiel: size = 100 (0x0064)
   * Little Endian (Intel): 64 00
   * Big Endian (Network):  00 64  <- Das wollen wir!
   */
  struct GLAB_MessageHeader hdr;
  hdr.size = htons(sizeof(hdr) + frame_size);  /* Gesamtgrösse */
  hdr.type = htons(ifc_num);                   /* Ziel-Interface */
  
  /*
   * Erst Header senden, dann Frame-Daten.
   * write_all() ist eine Hilfsfunktion aus print.c, die sicherstellt
   * dass ALLE Bytes geschrieben werden (auch bei partial writes).
   */
  write_all(STDOUT_FILENO, &hdr, sizeof(hdr));
  write_all(STDOUT_FILENO, frame, frame_size);
}

/**
 * Leitet einen Frame an ein Ziel-Interface weiter.
 * 
 * DIESE FUNKTION HANDHABT VLAN-TAG MANIPULATION!
 * 
 * Es gibt 4 Fälle:
 * 
 * 1. Untagged -> Untagged (gleiches VLAN): Frame unverändert
 *    [DST|SRC|TYPE|PAYLOAD] -> [DST|SRC|TYPE|PAYLOAD]
 * 
 * 2. Tagged -> Tagged (gleiches VLAN): Frame unverändert
 *    [DST|SRC|8100|TCI|TYPE|PAYLOAD] -> [DST|SRC|8100|TCI|TYPE|PAYLOAD]
 * 
 * 3. Untagged -> Tagged: VLAN-Tag HINZUFÜGEN
 *    [DST|SRC|TYPE|PAYLOAD] -> [DST|SRC|8100|TCI|TYPE|PAYLOAD]
 *                                       ^^^^^^^^ 4 Bytes eingefügt!
 * 
 * 4. Tagged -> Untagged: VLAN-Tag ENTFERNEN
 *    [DST|SRC|8100|TCI|TYPE|PAYLOAD] -> [DST|SRC|TYPE|PAYLOAD]
 *            ^^^^^^^^ 4 Bytes entfernt!
 * 
 * @param src_ifc Quell-Interface (von wo kam der Frame)
 * @param dst_ifc Ziel-Interface (wohin soll er)
 * @param frame Original Frame-Daten
 * @param frame_size Grösse des Original-Frames
 * @param vlan_id VLAN-ID des Frames
 * @param frame_is_tagged Ist der Original-Frame getaggt? (1=ja, 0=nein)
 */
static void
forward_frame(struct Interface *src_ifc,
              struct Interface *dst_ifc,
              const void *frame,
              size_t frame_size,
              int16_t vlan_id,
              int frame_is_tagged)
{
  int dst_needs_tag;
  
  /*
   * SCHRITT 1: Ist das Ziel-Interface überhaupt im richtigen VLAN?
   * 
   * Wenn nicht, darf der Frame nicht dorthin!
   * interface_in_vlan sagt uns auch, ob tagged oder untagged.
   */
  if (!interface_in_vlan(dst_ifc, vlan_id, &dst_needs_tag))
    return;  /* Interface nicht im VLAN -> nicht senden */
  
  /*
   * SCHRITT 2: Nie an das Quell-Interface zurücksenden!
   * 
   * Das wäre sinnlos und könnte Schleifen verursachen.
   * Beispiel: Broadcast kommt auf Port 1 an -> geht an Port 2, 3, aber NICHT 1!
   */
  if (src_ifc->ifc_num == dst_ifc->ifc_num)
    return;
  
  /*
   * SCHRITT 3: Tag-Manipulation je nach Situation
   */
  
  if (frame_is_tagged && !dst_needs_tag)
  {
    /*
     * FALL: Tagged -> Untagged
     * Der Frame hat einen VLAN-Tag, aber das Ziel-Interface will keinen.
     * -> VLAN-Tag ENTFERNEN
     * 
     * VORHER (18 Bytes Header):
     * Byte 0-5:   Destination MAC
     * Byte 6-11:  Source MAC
     * Byte 12-13: TPID (0x8100)  \
     * Byte 14-15: TCI             > Diese 4 Bytes entfernen!
     * Byte 16-17: EtherType
     * Byte 18+:   Payload
     * 
     * NACHHER (14 Bytes Header):
     * Byte 0-5:   Destination MAC  }
     * Byte 6-11:  Source MAC       } Unverändert
     * Byte 12-13: EtherType        <- War vorher an Position 16-17
     * Byte 14+:   Payload          <- War vorher an Position 18+
     */
    
    /* Neuer Frame ist 4 Bytes kürzer (VLAN-Tag entfernt) */
    size_t new_size = frame_size - sizeof(struct Q);
    uint8_t new_frame[new_size];  /* VLA: Variable Length Array */
    
    /* Destination + Source MAC kopieren (erste 12 Bytes) */
    memcpy(new_frame, frame, 12);
    
    /* 
     * Rest NACH dem VLAN-Tag kopieren (EtherType + Payload)
     * 
     * Original:     [12 Bytes MAC][4 Bytes Tag][Rest...]
     * Position:     0             12           16
     * 
     * Im neuen Frame soll "Rest" direkt nach MAC kommen:
     * Quelle:  frame + 12 + 4 = frame + 16
     * Ziel:    new_frame + 12
     * Länge:   frame_size - 12 - 4
     */
    memcpy(new_frame + 12, 
           (const uint8_t*)frame + 12 + sizeof(struct Q),
           frame_size - 12 - sizeof(struct Q));
    
    send_frame(dst_ifc->ifc_num, new_frame, new_size);
  }
  else if (!frame_is_tagged && dst_needs_tag)
  {
    /*
     * FALL: Untagged -> Tagged
     * Der Frame hat keinen VLAN-Tag, aber das Ziel-Interface braucht einen.
     * -> VLAN-Tag HINZUFÜGEN
     * 
     * VORHER (14 Bytes Header):
     * Byte 0-5:   Destination MAC
     * Byte 6-11:  Source MAC
     * Byte 12-13: EtherType
     * Byte 14+:   Payload
     * 
     * NACHHER (18 Bytes Header):
     * Byte 0-5:   Destination MAC  }
     * Byte 6-11:  Source MAC       } Unverändert
     * Byte 12-13: TPID (0x8100)    \
     * Byte 14-15: TCI               > EINGEFÜGT!
     * Byte 16-17: EtherType        <- War vorher an Position 12-13
     * Byte 18+:   Payload          <- War vorher an Position 14+
     */
    
    /* Neuer Frame ist 4 Bytes länger (VLAN-Tag eingefügt) */
    size_t new_size = frame_size + sizeof(struct Q);
    uint8_t new_frame[new_size];
    
    /* Destination + Source MAC kopieren (erste 12 Bytes) */
    memcpy(new_frame, frame, 12);
    
    /* VLAN-Tag erstellen und einfügen */
    struct Q vlan_tag;
    vlan_tag.tpid = htons(ETH_802_1Q_TAG);  /* 0x8100 in Network Byte Order */
    vlan_tag.tci = htons(vlan_id & 0x0FFF); /* VLAN-ID, Bits 12-15 auf 0 (keine Prio) */
    memcpy(new_frame + 12, &vlan_tag, sizeof(vlan_tag));
    
    /* 
     * EtherType + Payload kopieren
     * 
     * Quelle:  frame + 12 (wo der EtherType war)
     * Ziel:    new_frame + 12 + 4 = new_frame + 16
     * Länge:   frame_size - 12 (alles nach den MACs)
     */
    memcpy(new_frame + 12 + sizeof(struct Q),
           (const uint8_t*)frame + 12,
           frame_size - 12);
    
    send_frame(dst_ifc->ifc_num, new_frame, new_size);
  }
  else
  {
    /*
     * FALL: Keine Änderung nötig
     * - Untagged -> Untagged
     * - Tagged -> Tagged
     * 
     * Frame unverändert weiterleiten.
     */
    send_frame(dst_ifc->ifc_num, frame, frame_size);
  }
}

/**
 * Flutet einen Frame an alle Ports im gleichen VLAN.
 * 
 * FLOODING wird verwendet für:
 * 1. BROADCAST (FF:FF:FF:FF:FF:FF) - alle Geräte sollen es sehen
 * 2. MULTICAST (01:xx:xx:xx:xx:xx) - Gruppe von Geräten
 * 3. UNKNOWN UNICAST - Ziel-MAC nicht in Tabelle, also "fragen wir alle"
 * 
 * Der Quell-Port wird AUSGESCHLOSSEN! Sonst würde der Sender
 * seinen eigenen Frame zurückbekommen.
 * 
 * @param src_ifc Interface von dem der Frame kam (wird ausgeschlossen)
 * @param frame Die Frame-Daten
 * @param frame_size Grösse des Frames
 * @param vlan_id VLAN für das Flooding
 * @param frame_is_tagged Ist der Original-Frame getaggt?
 */
static void
flood_frame(struct Interface *src_ifc,
            const void *frame,
            size_t frame_size,
            int16_t vlan_id,
            int frame_is_tagged)
{
  /*
   * An JEDES Interface im VLAN senden.
   * forward_frame() kümmert sich um:
   * - Prüfung ob Interface im VLAN ist
   * - Überspringen des Quell-Interfaces
   * - VLAN-Tag Manipulation
   */
  for (unsigned int i = 0; i < num_ifc; i++)
  {
    forward_frame(src_ifc, &gifc[i], frame, frame_size, vlan_id, frame_is_tagged);
  }
}

/* ============================================================================
 * HAUPTLOGIK: FRAME-VERARBEITUNG
 * ============================================================================ */

/**
 * Verarbeitet einen empfangenen Frame.
 * 
 * Ablauf:
 * 1. Frame validieren (genug Bytes?)
 * 2. VLAN bestimmen (aus Tag oder Interface-Konfiguration)
 * 3. Quell-MAC lernen
 * 4. Forwarding-Entscheidung:
 *    - Broadcast/Multicast -> Flooding
 *    - Unicast bekannt -> gezielter Versand
 *    - Unicast unbekannt -> Flooding
 *
 * @param ifc Interface auf dem der Frame ankam
 * @param frame Die rohen Frame-Daten
 * @param frame_size Grösse des Frames in Bytes
 */
static void
parse_frame(struct Interface *ifc,
            const void *frame,
            size_t frame_size)
{
  struct EthernetHeader eh;
  int16_t vlan_id;
  int frame_is_tagged = 0;
  
  /*
   * SCHRITT 1: Mindestgrösse prüfen
   * 
   * Ein Ethernet-Header ist mindestens 14 Bytes
   */
  if (frame_size < sizeof(eh))
  {
    fprintf(stderr, "Malformed frame: too short (%zu bytes)\n", frame_size);
    return;  /* Frame verwerfen */
  }
  
  /*
   * SCHRITT 2: Ethernet-Header in Struktur kopieren
   * 
   * Wir kopieren statt direkt zu casten, um Alignment-Probleme zu vermeiden.
   */
  memcpy(&eh, frame, sizeof(eh));
  
  /*
   * SCHRITT 3: Prüfen ob Frame VLAN-getaggt ist
   * 
   * Wenn das "EtherType"-Feld 0x8100 ist, dann ist es eigentlich
   * der TPID eines VLAN-Tags!
   */
  if (ntohs(eh.tag) == ETH_802_1Q_TAG)
  {
    /*
     * TAGGED FRAME
     * 
     * Der Frame hat einen 802.1Q VLAN-Tag.
     * Wir müssen:
     * 1. Prüfen ob Frame gross genug für tagged Header ist
     * 2. VLAN-ID aus dem Tag extrahieren
     * 3. Prüfen ob das Interface dieses VLAN tagged akzeptiert
     */
    
    /* Tagged Header ist 18 Bytes, prüfen! */
    if (frame_size < sizeof(struct TaggedEthernetHeader))
    {
      fprintf(stderr, "Malformed tagged frame: too short\n");
      return;
    }
    
    frame_is_tagged = 1;
    
    /*
     * VLAN-ID aus TCI extrahieren
     * 
     * TCI ist das 4. und 5. Byte nach den MACs (Position 14-15).
     * Bits 0-11 = VLAN-ID
     * 
     * & 0x0FFF maskiert die oberen 4 Bits (PCP + DEI) weg.
     */
    const struct TaggedEthernetHeader *teh = frame;
    vlan_id = ntohs(teh->tci) & 0x0FFF;
    
    /*
     * Prüfen: Akzeptiert dieses Interface tagged Frames für dieses VLAN?
     */
    int is_tagged_port;
    if (!interface_in_vlan(ifc, vlan_id, &is_tagged_port) || !is_tagged_port)
    {
      /*
       * ABLEHNUNG: Das Interface ist entweder:
       * - gar nicht für dieses VLAN konfiguriert
       * - als untagged für dieses VLAN konfiguriert
       */
      fprintf(stderr, 
              "Dropping tagged frame: interface %d not configured for VLAN %d tagged\n", 
              ifc->ifc_num, vlan_id);
      return;
    }
  }
  else
  {
    /*
     * UNTAGGED FRAME
     * 
     * Der Frame hat keinen VLAN-Tag.
     * Die VLAN-ID kommt aus der Interface-Konfiguration.
     */
    
    /* Prüfen: Akzeptiert dieses Interface überhaupt untagged Frames? */
    if (ifc->untagged_vlan == NO_VLAN)
    {
      /*
       * ABLEHNUNG: Das Interface ist als rein tagged konfiguriert
       * und akzeptiert keine ungetaggten Frames.
       */
      fprintf(stderr, 
              "Dropping untagged frame: interface %d has no untagged VLAN\n",
              ifc->ifc_num);
      return;
    }
    
    /* VLAN-ID aus Interface-Konfiguration übernehmen */
    vlan_id = ifc->untagged_vlan;
  }
  
  /*
   * SCHRITT 4: MAC-Adresse lernen
   * 
   * Aus der QUELL-MAC lernen wir, auf welchem Port dieses Gerät ist.
   * Die learn_mac Funktion ignoriert automatisch Broadcast/Multicast.
   */
  learn_mac(&eh.src, ifc->ifc_num, vlan_id);
  
  /*
   * SCHRITT 5: Forwarding-Entscheidung
   */
  if (is_multicast_or_broadcast(&eh.dst))
  {
    /*
     * BROADCAST oder MULTICAST
     * 
     * Diese Frames müssen an ALLE Ports im VLAN (ausser Quelle
     */
    flood_frame(ifc, frame, frame_size, vlan_id, frame_is_tagged);
  }
  else
  {
    /*
     * UNICAST
     * 
     * Suche die Ziel-MAC in der Tabelle.
     */
    uint16_t dst_ifc_num;
    
    if (lookup_mac(&eh.dst, vlan_id, &dst_ifc_num))
    {
      /*
       * MAC GEFUNDEN!
       * 
       * Wir wissen auf welchem Port die Ziel-MAC ist.
       * -> Frame nur dorthin senden (effizient!)
       */
      forward_frame(ifc, 
                    &gifc[dst_ifc_num - 1],  /* -1 weil Array 0-basiert! */
                    frame, frame_size, 
                    vlan_id, frame_is_tagged);
    }
    else
    {
      /*
       * MAC NICHT GEFUNDEN ("Unknown Unicast")
       * 
       * Wir wissen nicht wo das Ziel ist.
       * -> Flooding wie bei Broadcast
       */
      flood_frame(ifc, frame, frame_size, vlan_id, frame_is_tagged);
    }
  }
}

/* ============================================================================
 * CALLBACK-FUNKTIONEN FÜR DEN NETWORK-DRIVER
 * 
 * Diese Funktionen werden von loop() in loop.c aufgerufen.
 * ============================================================================ */

/**
 * Callback: Ein Frame wurde vom Driver empfangen.
 *
 * @param interface Interface-Nummer (1-basiert!)
 * @param frame Die Frame-Daten
 * @param frame_size Grösse in Bytes
 */
static void
handle_frame(uint16_t interface,
             const void *frame,
             size_t frame_size)
{
  /* Sicherheitscheck: Gültige Interface-Nummer? */
  if (interface > num_ifc)
    abort();  /* Sollte nie passieren - fataler Fehler */
  
  /* Frame verarbeiten. interface-1 weil Array 0-basiert! */
  parse_frame(&gifc[interface - 1],
              frame,
              frame_size);
}

/**
 * Callback: User hat einen Befehl eingegeben.
 * 
 * Wird in dieser Implementierung ignoriert.
 * Könnte für Debug-Befehle wie "show mac-table" genutzt werden.
 *
 * @param cmd Der eingegebene Text
 * @param cmd_len Länge des Textes
 */
static void
handle_control(char *cmd,
               size_t cmd_len)
{
  cmd[cmd_len - 1] = '\0';  /* Newline durch Null ersetzen */
  fprintf(stderr,
          "Received command `%s' (ignored)\n",
          cmd);
}

/**
 * Callback: Driver teilt uns die MAC-Adresse eines Interfaces mit.
 * 
 * Wird einmal pro Interface beim Start aufgerufen.
 *
 * @param ifc_num Interface-Nummer (1-basiert)
 * @param mac Die MAC-Adresse dieses Interfaces
 */
static void
handle_mac(uint16_t ifc_num,
           const struct MacAddress *mac)
{
  if (ifc_num > num_ifc)
    abort();  /* Ungültige Interface-Nummer */
  
  /* MAC in der Interface-Struktur speichern */
  gifc[ifc_num - 1].mac = *mac;
}

/* ============================================================================
 * KOMMANDOZEILEN-PARSER
 * 
 * Parst Interface-Spezifikationen wie "eth0[T:1,2]" oder "eth1[U:10]"
 * ============================================================================ */

/**
 * Parst eine TAGGED Interface-Spezifikation.
 * 
 * Format: ":1,2,3" (nach dem 'T' und vor dem ']')
 * 
 * Beispiel: "eth0[T:1,2,3]"
 *           start zeigt auf ':'
 *           end zeigt auf ']'
 *           Ergebnis: tagged_vlans = {1, 2, 3, NO_VLAN}
 *
 * @param start Zeiger auf ':', Beginn der VLAN-Liste
 * @param end Zeiger auf ']', Ende der Spezifikation
 * @param off Interface-Nummer für Fehlermeldungen
 * @param ifc [OUTPUT] Interface-Struktur zum Befüllen
 * @return 0 bei Erfolg, 1 bei Fehler
 */
static int
parse_tagged(const char *start,
             const char *end,
             int off,
             struct Interface *ifc)
{
  char *spec;
  unsigned int pos;

  /* Muss mit ':' beginnen */
  if (':' != *start)
  {
    fprintf(stderr,
            "Tagged definition for interface #%d lacks ':'\n",
            off);
    return 1;
  }
  start++;  /* ':' überspringen */
  
  /* String zwischen ':' und ']' extrahieren */
  spec = strndup(start, end - start);
  if (NULL == spec)
  {
    perror("strndup");
    return 1;
  }
  
  /*
   * VLAN-IDs parsen (kommasepariert)
   * 
   * strtok zerlegt "1,2,3" in "1", "2", "3"
   */
  pos = 0;
  for (const char *tok = strtok(spec, ",");
       NULL != tok;
       tok = strtok(NULL, ","))
  {
    unsigned int tag;

    /* Zu viele VLANs? */
    if (pos == MAX_VLANS)
    {
      fprintf(stderr,
              "Too many VLANs specified for interface #%d\n",
              off);
      free(spec);
      return 1;
    }
    
    /* String zu Zahl konvertieren */
    if (1 != sscanf(tok, "%u", &tag))
    {
      fprintf(stderr,
              "Expected number in tagged definition for interface #%d\n",
              off);
      free(spec);
      return 1;
    }
    
    /* VLAN-ID im gültigen Bereich? */
    if (tag > MAX_VLANS)
    {
      fprintf(stderr,
              "%u is too large for a 802.1Q VLAN ID (on interface #%d)\n",
              tag,
              off);
      free(spec);
      return 1;
    }
    
    /* VLAN zur Liste hinzufügen */
    ifc->tagged_vlans[pos++] = (int16_t)tag;
  }
  
  /* Liste mit NO_VLAN terminieren */
  ifc->tagged_vlans[pos] = NO_VLAN;
  
  free(spec);
  return 0;
}

/**
 * Parst eine UNTAGGED Interface-Spezifikation.
 * 
 * Format: ":10" (nach dem 'U' und vor dem ']')
 * 
 * Beispiel: "eth1[U:10]"
 *           start zeigt auf ':'
 *           end zeigt auf ']'
 *           Ergebnis: untagged_vlan = 10
 *
 * @param start Zeiger auf ':', Beginn der VLAN-Nummer
 * @param end Zeiger auf ']', Ende der Spezifikation
 * @param off Interface-Nummer für Fehlermeldungen
 * @param ifc [OUTPUT] Interface-Struktur zum Befüllen
 * @return 0 bei Erfolg, 1 bei Fehler
 */
static int
parse_untagged(const char *start,
               const char *end,
               int off,
               struct Interface *ifc)
{
  char *spec;
  unsigned int tag;

  /* Muss mit ':' beginnen */
  if (':' != *start)
  {
    fprintf(stderr,
            "Untagged definition for interface #%d lacks ':'\n",
            off);
    return 1;
  }
  start++;  /* ':' überspringen */
  
  /* String zwischen ':' und ']' extrahieren */
  spec = strndup(start, end - start);
  if (NULL == spec)
  {
    perror("strndup");
    return 1;
  }
  
  /* String zu Zahl konvertieren */
  if (1 != sscanf(spec, "%u", &tag))
  {
    fprintf(stderr,
            "Expected number in untagged definition for interface #%d\n",
            off);
    free(spec);
    return 1;
  }
  
  /* VLAN-ID im gültigen Bereich? */
  if (tag > MAX_VLANS)
  {
    fprintf(stderr,
            "%u is too large for a 802.1Q VLAN ID (on interface #%d)\n",
            tag,
            off);
    free(spec);
    return 1;
  }
  
  /* Untagged VLAN setzen */
  ifc->untagged_vlan = (int16_t)tag;
  
  free(spec);
  return 0;
}

/**
 * Parst ein Kommandozeilen-Argument für ein Interface.
 * 
 * FORMATE:
 * "eth0"           -> Interface eth0, untagged VLAN 0
 * "eth1[U:10]"     -> Interface eth1, untagged VLAN 10
 * "eth2[T:5]"      -> Interface eth2, tagged VLAN 5
 * "eth3[T:1,2,3]"  -> Interface eth3, tagged VLANs 1, 2, 3
 *
 * @param arg Das Kommandozeilen-Argument
 * @param off Position für Fehlermeldungen (1, 2, 3, ...)
 * @param ifc [OUTPUT] Interface-Struktur zum Befüllen
 * @return 0 bei Erfolg, 1 bei Fehler
 */
static int
parse_vlan_args(const char *arg,
                int off,
                struct Interface *ifc)
{
  const char *openbracket;
  const char *closebracket;

  /* Standardwerte setzen */
  ifc->tagged_vlans[0] = NO_VLAN;  /* Keine tagged VLANs */
  ifc->untagged_vlan = NO_VLAN;    /* Kein untagged VLAN */
  
  /* Suche '[' im Argument */
  openbracket = strchr(arg, (unsigned char)'[');
  
  if (NULL == openbracket)
  {
    /*
     * KEIN '[' gefunden -> Einfaches Interface ohne VLAN-Spezifikation
     * 
     * "eth0" -> untagged VLAN 0 (Default)
     */
    ifc->ifc_name = strdup(arg);
    if (NULL == ifc->ifc_name)
    {
      perror("strdup");
      return 1;
    }
    ifc->untagged_vlan = DEFAULT_VLAN;
    return 0;
  }
  
  /*
   * '[' gefunden -> Interface-Name ist alles VOR dem '['
   * 
   * "eth0[T:1]" -> ifc_name = "eth0"
   */
  ifc->ifc_name = strndup(arg, openbracket - arg);
  if (NULL == ifc->ifc_name)
  {
    perror("strndup");
    return 1;
  }
  
  openbracket++;  /* '[' überspringen, jetzt bei 'T' oder 'U' */
  
  /* Suche ']' */
  closebracket = strchr(openbracket, (unsigned char)']');
  if (NULL == closebracket)
  {
    fprintf(stderr,
            "Interface definition #%d includes '[' but lacks ']'\n",
            off);
    return 1;
  }
  
  /*
   * Erstes Zeichen nach '[' bestimmt den Typ:
   * 'T' = Tagged
   * 'U' = Untagged
   */
  switch (*openbracket)
  {
  case 'T':
    return parse_tagged(openbracket + 1,  /* Nach dem 'T' */
                        closebracket,
                        off,
                        ifc);
  case 'U':
    return parse_untagged(openbracket + 1,  /* Nach dem 'U' */
                          closebracket,
                          off,
                          ifc);
  default:
    fprintf(stderr,
            "Unsupported tagged/untagged specification `%c' in interface definition #%d\n",
            *openbracket,
            off);
    return 1;
  }
}

/* ============================================================================
 * MAIN - PROGRAMMSTART
 * ============================================================================ */

/**
 * Hauptfunktion - Startet den VSwitch.
 *
 * AUFRUF:
 * ./vswitch eth0 eth1[U:1] eth2[T:1,2]
 *
 * argc = 4
 * argv[0] = "./vswitch"
 * argv[1] = "eth0"
 * argv[2] = "eth1[U:1]"
 * argv[3] = "eth2[T:1,2]"
 *
 * @param argc Anzahl der Argumente (inkl. Programmname)
 * @param argv Array der Argument-Strings
 * @return 0 bei Erfolg, 1 bei Fehler
 */
int
main(int argc,
     char **argv)
{
  /*
   * VLA (Variable Length Array) für Interface-Strukturen
   * 
   * argc-1 weil argv[0] der Programmname ist.
   * Beispiel: "./vswitch eth0 eth1" -> argc=3, wir brauchen 2 Interfaces
   */
  struct Interface ifc[argc - 1];

  /*
   * (void)print; unterdrückt "unused variable" Warnung.
   * print ist eine Funktion aus print.c die wir nicht nutzen,
   * aber der Compiler würde sonst warnen.
   */
  (void)print;
  
  /*
   * Strukturen und MAC-Tabelle mit Nullen initialisieren.
   * memset(ptr, wert, grösse) setzt alle Bytes auf 'wert'.
   */
  memset(ifc, 0, sizeof(ifc));
  memset(mac_table, 0, sizeof(mac_table));
  
  /* Globale Variablen setzen */
  num_ifc = argc - 1;
  gifc = ifc;
  
  /*
   * Kommandozeilen-Argumente parsen
   * 
   * i startet bei 1 (argv[0] ist Programmname)
   */
  for (unsigned int i = 1; i < (unsigned int)argc; i++)
  {
    ifc[i - 1].ifc_num = i;  /* Interface-Nummer (1-basiert) */
    
    if (0 != parse_vlan_args(argv[i], i, &ifc[i - 1]))
    {
      /* Parsing fehlgeschlagen -> Programm beenden */
      return 1;
    }
  }
  
  /*
   * Hauptschleife starten!
   * 
   * loop() ist in loop.c definiert und liest von stdin,
   * ruft unsere Callback-Funktionen auf und läuft "ewig"
   * (bis stdin geschlossen wird oder Signal kommt).
   */
  loop(&handle_frame,
       &handle_control,
       &handle_mac);
  
  return 0;
}
