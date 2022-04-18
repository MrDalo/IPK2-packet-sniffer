# IPK2
## IPK2 project VUT FIT
### Author: Dalibor Králik, xkrali20

## Popis
Tento projekt slúži ako packet sniffer implementovaný v jazyku C.

## Spustenie
```$sudo ./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}```

  - -i eth0 ( práve jedno rozhranie, na ktorom sa bude načúvať. Nebude tento parameter uvedený, či bude uvedený lne -i bez hodnoty, vypíše sa zoznam dostupných rozhraní)
  - -p 23 (bude filtrovať pakety na danom porte; ak nebude tento parameter uvedený, uvažujeme všetky porty; pokial je parameter uvedený, može sa daný port vyskytnúť ako v source, tak aj v destination časti). Číslo portu musí byť väčšie ako -1.
  - -t nebo --tcp (bude zobrazovat iba TCP pakety)
  - -u nebo --udp (bude zobrazovat iba UDP pakety)
  - --icmp (bude zobrazovat iba ICMPv4 a ICMPv6 pakety)
  - --arp (bude zobrazovat iba ARP rámce)
  - Pokiaľ nebudú konkrétne protokoly špecifikované, uvažuje se tisk všetkých packetov
  - -n 10 (určuje počet paketov, které sa majú zobraziť, tj. i "dobu" behu programu; pokiaľ není uvedené, uvažujte zobrazenie iba jednoho paketu, teda akoby -n 1). Číslo musí byť väčšie ako 0.
  - argumenty môžu byť v libovolnom poradí
  - V prípade nezadania ani jedného argumentu program vypíše zoznam všetkých dostupných rozhraní a zachová sa ako pri zadaní argumentu -i bez parametru



## Zoznam odovzdaných súborov
  - ipk-sniffer.c
  - Makefile
  - README.md
  - manual.pdf

